use anyhow::Context;
use inquire::{Confirm, Password, Text};
use russh::MethodKind;
use russh::client::{self, AuthResult, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts, load_secret_key};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

pub struct SshConfig {
    pub user: String,
    pub host: String,
    pub port: u16,
    pub identity: Option<PathBuf>,
    pub remote_binary: String,
}

struct SshHandler {
    host: String,
    port: u16,
}

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match check_known_hosts(&self.host, self.port, server_public_key)
            .context("{self.host}:{self.port} known hosts error")
        {
            Ok(false) => {
                if Confirm::new(&format!(
                    "{}:{} add key {}",
                    self.host,
                    self.port,
                    server_public_key.fingerprint(Default::default())
                ))
                .prompt()
                .unwrap_or(false)
                {
                    learn_known_hosts(&self.host, self.port, server_public_key)
                        .map(|_| true)
                        .context("cannot learn new host key")
                } else {
                    Ok(false)
                }
            }
            e => e,
        }
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
    let ssh_config = Arc::new(client::Config::default());

    let addr = format!("{}:{}", config.host, config.port);
    info!("Connecting to SSH server at {}", addr);

    let handler = SshHandler {
        host: config.host.clone(),
        port: config.port,
    };

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
    Ok(tokio::io::split(channel.into_stream()))
}

async fn keyboard_interactive_info_request(
    session: &mut client::Handle<SshHandler>,
    prompts: Vec<russh::client::Prompt>,
) -> anyhow::Result<KeyboardInteractiveAuthResponse> {
    debug!("keyboard interactive info request");
    let responses = prompts
        .into_iter()
        .map(|prompt| {
            if prompt.prompt.is_empty() {
                Ok(String::new())
            } else if prompt.echo {
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

    session
        .authenticate_keyboard_interactive_respond(responses)
        .await
        .context("cannot respond keyboard interactive")
}

async fn try_agent_auth(
    session: &mut client::Handle<SshHandler>,
    user: &str,
) -> anyhow::Result<bool> {
    let mut agent = AgentClient::connect_env()
        .await
        .context("Failed to connect to SSH agent")?;

    let identities = agent.request_identities().await?;

    'identities_loop: for identity in identities {
        let pubkey = identity.public_key();
        debug!(
            "Trying SSH agent key {}",
            pubkey.fingerprint(Default::default())
        );
        // For agent auth, we need to use authenticate_publickey_with which uses the agent
        // to sign the authentication request
        match session
            .authenticate_publickey_with(user, pubkey.into_owned(), None, &mut agent)
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
                for method in remaining_methods.iter() {
                    if matches!(method, MethodKind::KeyboardInteractive) {
                        debug!("Begin keyboard interactive");
                        let mut keyb_response = session
                            .authenticate_keyboard_interactive_start(user, None)
                            .await
                            .context("Cannot start keyboard interactive")?;
                        loop {
                            match keyb_response {
                                client::KeyboardInteractiveAuthResponse::Success => {
                                    return Ok(true);
                                }
                                client::KeyboardInteractiveAuthResponse::InfoRequest {
                                    prompts,
                                    ..
                                } => {
                                    keyb_response =
                                        keyboard_interactive_info_request(session, prompts).await?;
                                }
                                client::KeyboardInteractiveAuthResponse::Failure { .. } => {
                                    continue 'identities_loop;
                                }
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
