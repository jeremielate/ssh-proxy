mod proxy;

use crate::protocol::{HostMessage, RemoteMessage, read_message, write_message};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{BufReader, BufWriter, stdin, stdout};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// Run the remote proxy
pub async fn run() -> anyhow::Result<()> {
    info!("Remote proxy starting");

    let stdin = BufReader::new(stdin());
    let stdout = BufWriter::new(stdout());

    let mut proxy = RemoteProxy::new(stdin, stdout);
    proxy.run().await
}

struct RemoteProxy<R, W> {
    reader: R,
    writer: W,
    tcp_connections: Arc<DashMap<u32, TcpConnectionHandle>>,
    response_tx: mpsc::Sender<RemoteMessage>,
    response_rx: mpsc::Receiver<RemoteMessage>,
    running: Arc<AtomicBool>,
}

struct TcpConnectionHandle {
    tx: mpsc::Sender<Vec<u8>>,
}

impl<R, W> RemoteProxy<Arc<Mutex<R>>, Mutex<W>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn new(reader: R, writer: W) -> Self {
        let (response_tx, response_rx) = mpsc::channel(1024);
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Mutex::new(writer),
            tcp_connections: Arc::new(DashMap::new()),
            response_tx,
            response_rx,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        // Send ready message
        write_message(&mut self.writer, &RemoteMessage::Ready).await?;
        info!("Remote proxy ready");

        let (read_message_tx, mut read_message_rx) = mpsc::channel(1024);

        let self_reader = Arc::clone(&self.reader);
        tokio::spawn(async move {
            loop {
                let msg = read_message::<_, HostMessage>(self_reader.clone()).await;
                let break_loop = match msg {
                    Ok(None) | Err(_) => true,
                    _ => false,
                };
                if let Err(e) = read_message_tx.send(msg).await {
                    debug!("read message hang up: {}", e);
                    break;
                };
                if break_loop {
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                // Handle incoming messages from host
                msg = read_message_rx.recv() => {
                    if let Some(msg) = msg {
                        match msg {
                            Ok(Some(msg)) => {
                                if let Err(e) = self.handle_host_message(msg).await {
                                    error!("Error handling host message: {}", e);
                                }
                            }
                            Ok(None) => {
                                info!("Host disconnected");
                                break;
                            }
                            Err(e) => {
                                error!("Error reading host message: {}", e);
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }

                // Send responses back to host
                response = self.response_rx.recv() => {
                    if let Some(msg) = response
                        && let Err(e) = write_message(&mut self.writer, &msg).await {
                            error!("Error writing response: {}", e);
                            break;
                        }
                }
            }

            if !self.running.load(Ordering::Relaxed) {
                break;
            }
        }

        self.running.store(false, Ordering::Relaxed);
        Ok(())
    }

    async fn handle_host_message(&mut self, msg: HostMessage) -> anyhow::Result<()> {
        match msg {
            HostMessage::TcpConnect {
                id,
                dst_ip,
                dst_port,
            } => {
                debug!(
                    "TCP connect request: id={}, dst={}:{}",
                    id, dst_ip, dst_port
                );
                self.handle_tcp_connect(id, dst_ip, dst_port).await;
            }
            HostMessage::TcpData { id, data } => {
                debug!("TCP data: id={}, len={}", id, data.len());
                self.handle_tcp_data(id, data).await;
            }
            HostMessage::TcpClose { id } => {
                debug!("TCP close: id={}", id);
                self.handle_tcp_close(id).await;
            }
            HostMessage::UdpDatagram {
                src_port,
                dst_ip,
                dst_port,
                data,
            } => {
                debug!(
                    "UDP datagram: src_port={}, dst={}:{}, len={}",
                    src_port,
                    dst_ip,
                    dst_port,
                    data.len()
                );
                self.handle_udp_datagram(src_port, dst_ip, dst_port, data)
                    .await;
            }
            HostMessage::Shutdown => {
                info!("Shutdown requested");
                self.running.store(false, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    async fn handle_tcp_connect(&self, id: u32, dst_ip: std::net::Ipv4Addr, dst_port: u16) {
        let response_tx = self.response_tx.clone();
        let connections = self.tcp_connections.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let addr = format!("{}:{}", dst_ip, dst_port);
            match TcpStream::connect(&addr).await {
                Ok(stream) => {
                    debug!("TCP connected: id={}, addr={}", id, addr);

                    // Send connected response
                    let _ = response_tx.send(RemoteMessage::TcpConnected { id }).await;

                    // Create channel for sending data to this connection
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                    connections.insert(id, TcpConnectionHandle { tx });

                    // Handle the connection
                    proxy::handle_tcp_connection(id, stream, rx, response_tx.clone(), running)
                        .await;

                    // Remove connection when done
                    connections.remove(&id);
                    debug!("TCP connection closed: id={}", id);
                }
                Err(e) => {
                    warn!("TCP connect failed: id={}, addr={}, error={}", id, addr, e);
                    let _ = response_tx
                        .send(RemoteMessage::TcpError {
                            id,
                            error: e.to_string(),
                        })
                        .await;
                }
            }
        });
    }

    async fn handle_tcp_data(&self, id: u32, data: Vec<u8>) {
        if let Some(conn) = self.tcp_connections.get(&id) {
            if conn.tx.send(data).await.is_err() {
                warn!("Failed to send data to TCP connection: id={}", id);
                self.tcp_connections.remove(&id);
            }
        } else {
            warn!("TCP data for unknown connection: id={}", id);
        }
    }

    async fn handle_tcp_close(&self, id: u32) {
        if self.tcp_connections.remove(&id).is_some() {
            debug!("TCP connection removed: id={}", id);
        }
    }

    async fn handle_udp_datagram(
        &self,
        src_port: u16,
        dst_ip: std::net::Ipv4Addr,
        dst_port: u16,
        data: Vec<u8>,
    ) {
        let response_tx = self.response_tx.clone();

        tokio::spawn(async move {
            match proxy::send_udp_datagram(dst_ip, dst_port, &data).await {
                Ok(responses) => {
                    for (recv_ip, recv_port, recv_data) in responses {
                        let _ = response_tx
                            .send(RemoteMessage::UdpResponse {
                                dst_port: src_port,
                                src_ip: recv_ip,
                                src_port: recv_port,
                                data: recv_data,
                            })
                            .await;
                    }
                }
                Err(e) => {
                    warn!("UDP send failed: dst={}:{}, error={}", dst_ip, dst_port, e);
                }
            }
        });
    }
}
