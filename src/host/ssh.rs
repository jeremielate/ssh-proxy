use anyhow::Context;
use inquire::{Password, Text};
use russh::client::{self, AuthResult, Handler, KeyboardInteractiveAuthResponse, Msg};
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::{Channel, ChannelMsg, ChannelWriteHalf, MethodKind};
use std::future::ready;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, info};

pub struct SshConfig {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity: Option<PathBuf>,
    pub remote_binary: String,
}

struct SshHandler;

impl Handler for SshHandler {
    type Error = anyhow::Error;

    fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        ready(Ok(true))
    }
}

/// Connect to remote via SSH and start the remote proxy binary
/// Returns (reader, writer) for communicating with the remote process
pub async fn connect(
    config: SshConfig,
) -> anyhow::Result<(
    impl AsyncRead + Unpin + Send,
    impl AsyncWrite + Unpin + Send,
)> {
    let ssh_config = client::Config::default();
    let ssh_config = Arc::new(ssh_config);

    let handler = SshHandler;

    let addr = format!("{}:{}", config.host, config.port);
    info!("Connecting to SSH server at {}", addr);

    let mut session = client::connect(ssh_config, &addr, handler)
        .await
        .context("Failed to connect to SSH server")?;

    // Authenticate
    let authenticated = if let Some(identity_path) = &config.identity {
        // Key-based authentication
        info!("Using key-based authentication from {:?}", identity_path);
        let key = load_secret_key(identity_path, None).context("Failed to load private key")?;
        let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), None);
        let auth_result = session
            .authenticate_publickey(&config.user, key_with_hash)
            .await
            .context("Public key authentication failed")?;
        auth_result.success()
    } else {
        // Try SSH agent first
        info!("Attempting SSH agent authentication");
        match try_agent_auth(&mut session, &config.user).await {
            Ok(true) => true,
            Ok(false) | Err(_) => {
                // Fall back to password
                info!("SSH agent auth failed, falling back to password");
                let password =
                    Password::new(&(format!("Password for {}@{}: ", config.user, config.host)))
                        .without_confirmation()
                        .prompt()
                        .context("Failed to read password")?;

                let auth_result = session
                    .authenticate_password(&config.user, &password)
                    .await
                    .context("Password authentication failed")?;
                auth_result.success()
            }
        }
    };

    if !authenticated {
        anyhow::bail!("Authentication failed");
    }
    info!("SSH authentication successful");

    // Open a channel and execute the remote binary
    let channel = session
        .channel_open_session()
        .await
        .context("Failed to open SSH channel")?;

    let command = format!("{} remote", config.remote_binary);
    info!("Executing remote command: {}", command);

    channel
        .exec(true, command.as_bytes())
        .await
        .context("Failed to execute remote command")?;

    // Create a wrapper that provides AsyncRead/AsyncWrite over the SSH channel
    let (reader, writer) = create_channel_io(channel);

    Ok((reader, writer))
}

async fn try_agent_auth(
    session: &mut client::Handle<SshHandler>,
    user: &str,
) -> anyhow::Result<bool> {
    let mut agent = AgentClient::connect_env()
        .await
        .context("Failed to connect to SSH agent")?;

    let identities = agent.request_identities().await?;

    for pubkey in identities {
        debug!("Trying SSH agent key");
        // For agent auth, we need to use authenticate_publickey_with which uses the agent
        // to sign the authentication request
        match session
            .authenticate_publickey_with(user, pubkey, None, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(true),
            Ok(AuthResult::Failure {
                remaining_methods,
                partial_success,
            }) => {
                if !partial_success {
                    continue;
                }
                debug!("partial success true");
                for method in remaining_methods.into_iter() {
                    if matches!(method, MethodKind::KeyboardInteractive) {
                        debug!("begin keyboard interactive");
                        let keyb_response = session
                            .authenticate_keyboard_interactive_start(user, None)
                            .await
                            .context("cannot start keyboard interactive")?;
                        match keyb_response {
                            client::KeyboardInteractiveAuthResponse::Success => {
                                return Ok(true);
                            }
                            client::KeyboardInteractiveAuthResponse::InfoRequest {
                                name,
                                instructions,
                                prompts,
                            } => {
                                debug!(
                                    "keyboard interactive name={name} instructions={instructions}"
                                );
                                let responses = prompts
                                    .into_iter()
                                    .map(|prompt| {
                                        if prompt.echo {
                                            Text::new(&prompt.prompt)
                                                .prompt()
                                                .context("Failed to read response to prompt")
                                        } else {
                                            Password::new(&prompt.prompt)
                                                .without_confirmation()
                                                .prompt()
                                                .context("Failed to read response to prompt")
                                        }
                                    })
                                    .collect::<Result<Vec<String>, _>>()?;

                                let keyb_response = session
                                    .authenticate_keyboard_interactive_respond(responses)
                                    .await
                                    .context("cannot respond keyboard interactive")?;
                                if matches!(keyb_response, KeyboardInteractiveAuthResponse::Success)
                                {
                                    return Ok(true);
                                }
                            }
                            client::KeyboardInteractiveAuthResponse::Failure { .. } => {
                                continue;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Agent auth attempt failed: {}", e);
                continue;
            }
        }
    }

    Ok(false)
}

fn create_channel_io(channel: Channel<Msg>) -> (ChannelReader, ChannelWriter) {
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);
    let (mut r_channel, w_channel) = channel.split();

    // Spawn a task to read from the channel and send data through the mpsc
    tokio::spawn(async move {
        loop {
            info!("locking channel");
            info!("channel locked");
            match r_channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if data_tx.send(data.to_vec()).await.is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    // stderr (ext == 1)
                    if ext == 1 {
                        let stderr = String::from_utf8_lossy(&data);
                        for line in stderr.lines() {
                            debug!("Remote stderr: {}", line);
                        }
                    }
                }
                Some(ChannelMsg::Eof) => {
                    debug!("SSH channel EOF");
                    break;
                }
                Some(ChannelMsg::Close) => {
                    debug!("SSH channel closed");
                    break;
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    debug!("Remote process exited with status: {}", exit_status);
                }
                Some(_) => {
                    // Ignore other messages
                }
                None => {
                    break;
                }
            }
        }
    });

    let reader = ChannelReader {
        rx: data_rx,
        buffer: Vec::new(),
    };
    let writer = ChannelWriter {
        channel: Arc::new(tokio::sync::Mutex::new(w_channel)),
    };

    (reader, writer)
}

pub struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // If we have buffered data, return that first
        if !self.buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.buffer.len());
            buf.put_slice(&self.buffer[..to_copy]);
            self.buffer.drain(..to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        // Try to receive more data
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.buffer.extend_from_slice(&data[to_copy..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // Channel closed
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

pub struct ChannelWriter {
    channel: Arc<tokio::sync::Mutex<ChannelWriteHalf<Msg>>>,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;

        let channel = self.channel.clone();
        let data = buf.to_vec();
        let len = data.len();

        let fut = async move {
            debug!("poll_write AsyncWrite locking channel");
            let channel = channel.lock().await;
            debug!("poll_write AsyncWrite channel locked");
            channel.data(&data[..]).await.map(|_| len)
        };

        let mut fut = Box::pin(fut);
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // SSH channel doesn't need flushing
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;

        let channel = self.channel.clone();
        let fut = async move {
            debug!("poll_shutdown AsyncWrite locking channel");
            let channel = channel.lock().await;
            debug!("poll_shutdown AsyncWrite channel locked");
            channel.eof().await
        };

        let mut fut = Box::pin(fut);
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
