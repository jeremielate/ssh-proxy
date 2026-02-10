use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

use crate::protocol::HostMessage;

/// Register our DNS forwarder with systemd-resolved on the given TUN interface.
pub async fn register_dns(tun_name: &str, listen_port: u16) -> anyhow::Result<()> {
    // Set our local forwarder as the DNS server for this link
    let status = tokio::process::Command::new("resolvectl")
        .args(["dns", tun_name, &format!("127.0.0.1:{listen_port}")])
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("resolvectl dns failed with {}", status);
    }

    // Set catch-all domain so all queries go through us
    let status = tokio::process::Command::new("resolvectl")
        .args(["domain", tun_name, "~."])
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("resolvectl domain failed with {}", status);
    }

    info!(
        "Registered DNS forwarder on {} at 127.0.0.1:{}",
        tun_name, listen_port
    );
    Ok(())
}

/// Unregister DNS configuration from the TUN interface.
pub async fn unregister_dns(tun_name: &str) {
    let result = tokio::process::Command::new("resolvectl")
        .args(["revert", tun_name])
        .status()
        .await;
    match result {
        Ok(status) if status.success() => {
            info!("Reverted DNS config on {}", tun_name);
        }
        Ok(status) => {
            warn!("resolvectl revert failed with {}", status);
        }
        Err(e) => {
            warn!("Failed to run resolvectl revert: {}", e);
        }
    }
}

/// State for tracking pending DNS queries.
pub struct DnsState {
    pub socket: Arc<UdpSocket>,
    pub dns_server: IpAddr,
    pending: Mutex<HashMap<u32, SocketAddr>>,
    next_id: AtomicU32,
}

impl DnsState {
    pub fn new(socket: Arc<UdpSocket>, dns_server: IpAddr) -> Self {
        Self {
            socket,
            dns_server,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(0),
        }
    }

    /// Handle an incoming DNS query from a local client.
    /// Assigns an ID, tracks the sender, and forwards to remote via the channel.
    pub async fn handle_query(
        &self,
        data: &[u8],
        sender: SocketAddr,
        to_remote_tx: &mpsc::Sender<HostMessage>,
    ) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        debug!("DNS query id={} from {}, len={}", id, sender, data.len());

        self.pending.lock().await.insert(id, sender);

        if let Err(e) = to_remote_tx
            .send(HostMessage::DnsQuery {
                id,
                server: self.dns_server,
                data: data.to_vec(),
            })
            .await
        {
            error!("Failed to send DNS query to remote: {}", e);
            self.pending.lock().await.remove(&id);
        }
    }

    /// Handle a DNS response from the remote. Sends the response back to the original querier.
    pub async fn handle_response(&self, id: u32, data: &[u8]) {
        let sender = self.pending.lock().await.remove(&id);
        match sender {
            Some(addr) => {
                debug!("DNS response id={} -> {}, len={}", id, addr, data.len());
                if let Err(e) = self.socket.send_to(data, addr).await {
                    warn!("Failed to send DNS response to {}: {}", addr, e);
                }
            }
            None => {
                warn!("DNS response for unknown query id={}", id);
            }
        }
    }
}
