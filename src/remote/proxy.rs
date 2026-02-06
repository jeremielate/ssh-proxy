use crate::protocol::RemoteMessage;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Handle a TCP connection: relay data between host and remote destination
pub async fn handle_tcp_connection(
    id: u32,
    mut stream: TcpStream,
    mut rx: mpsc::Receiver<Vec<u8>>,
    response_tx: mpsc::Sender<RemoteMessage>,
    running: Arc<AtomicBool>,
) {
    let (mut reader, mut writer) = stream.split();
    let mut read_buf = vec![0u8; 65536];

    loop {
        if !running.load(Ordering::Relaxed) {
            debug!("proxy not running");
            break;
        }

        tokio::select! {
            // Data from host to send to destination
            data = rx.recv() => {
                match data {
                    Some(data) => {
                        if let Err(e) = writer.write_all(&data).await {
                            warn!("TCP write error: id={}, error={}", id, e);
                            let _ = response_tx.send(RemoteMessage::TcpError {
                                id,
                                error: e.to_string(),
                            }).await;
                            break;
                        }
                    }
                    None => {
                        // Channel closed, connection should close
                        debug!("TCP channel closed: id={}", id);
                        break;
                    }
                }
            }

            // Data from destination to send to host
            result = reader.read(&mut read_buf) => {
                match result {
                    Ok(0) => {
                        // Connection closed by remote
                        debug!("TCP connection closed by remote: id={}", id);
                        // Already sent at line "Ensure we notify host of close"
                        // let _ = response_tx.send(RemoteMessage::TcpClosed { id }).await;
                        break;
                    }
                    Ok(n) => {
                        let data = read_buf[..n].to_vec();
                        debug!("TCP read: id={}, len={}", id, n);
                        if response_tx.send(RemoteMessage::TcpData { id, data }).await.is_err() {
                            warn!("Failed to send TCP data response: id={}", id);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("TCP read error: id={}, error={}", id, e);
                        let _ = response_tx.send(RemoteMessage::TcpError {
                            id,
                            error: e.to_string(),
                        }).await;
                        break;
                    }
                }
            }
        }
    }

    // Ensure we notify host of close
    let _ = response_tx.send(RemoteMessage::TcpClosed { id }).await;
}

/// Send a UDP datagram and wait for responses
pub async fn send_udp_datagram(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    data: &[u8],
) -> anyhow::Result<Vec<(Ipv4Addr, u16, Vec<u8>)>> {
    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Send datagram
    let dst_addr = format!("{}:{}", dst_ip, dst_port);
    socket.send_to(data, &dst_addr).await?;

    // Wait for response(s) with timeout
    let mut responses = Vec::new();
    let mut buf = vec![0u8; 65536];

    // For UDP, we typically expect one response, but DNS might send multiple
    // Use a short timeout to collect any responses
    let timeout = Duration::from_secs(5);

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        if let std::net::SocketAddr::V4(v4_addr) = addr {
                            responses.push((
                                *v4_addr.ip(),
                                v4_addr.port(),
                                buf[..len].to_vec(),
                            ));
                        }
                        // For most UDP protocols, one response is enough
                        // For DNS, the response is complete in one packet
                        break;
                    }
                    Err(e) => {
                        if responses.is_empty() {
                            return Err(e.into());
                        }
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(timeout) => {
                // Timeout - return what we have
                break;
            }
        }
    }

    Ok(responses)
}
