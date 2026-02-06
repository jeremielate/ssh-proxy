use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Key for TCP connection: (src_ip, src_port, dst_ip, dst_port)
pub type TcpKey = (Ipv4Addr, u16, Ipv4Addr, u16);

/// Key for UDP "connection": (src_ip, src_port, dst_ip, dst_port)
#[allow(dead_code)]
pub type UdpKey = (Ipv4Addr, u16, Ipv4Addr, u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConnectionState {
    SynSent,
    Established,
    FinWait,
    Closed,
}

struct TcpConnection {
    id: u32,
    state: ConnectionState,
    seq: u32,
    ack: u32,
}

struct UdpMapping {
    src_ip: Ipv4Addr,
    last_activity: Instant,
}

pub struct NatTable {
    /// TCP connections indexed by (src_ip, src_port, dst_ip, dst_port)
    tcp_by_key: DashMap<TcpKey, TcpConnection>,
    /// TCP connections indexed by connection ID (for reverse lookup)
    tcp_by_id: DashMap<u32, TcpKey>,
    /// UDP mappings indexed by (src_port, dst_ip, dst_port) for return path
    udp_mappings: DashMap<(u16, Ipv4Addr, u16), UdpMapping>,
    /// Next connection ID
    next_id: AtomicU32,
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            tcp_by_key: DashMap::new(),
            tcp_by_id: DashMap::new(),
            udp_mappings: DashMap::new(),
            next_id: AtomicU32::new(1),
        }
    }

    /// Create a new TCP connection entry and return its ID
    pub fn create_tcp_connection(&self, key: TcpKey, client_isn: u32) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let conn = TcpConnection {
            id,
            state: ConnectionState::SynSent,
            seq: 1000,              // Our ISN for the SYN-ACK
            ack: client_isn.wrapping_add(1), // Acknowledge the client's SYN
        };

        self.tcp_by_key.insert(key, conn);
        self.tcp_by_id.insert(id, key);

        id
    }

    /// Get the connection ID for a TCP key
    pub fn get_tcp_connection_id(&self, key: &TcpKey) -> Option<u32> {
        self.tcp_by_key.get(key).map(|conn| conn.id)
    }

    /// Get the TCP key for a connection ID
    pub fn get_tcp_connection_key(&self, id: u32) -> Option<TcpKey> {
        self.tcp_by_id.get(&id).map(|r| *r.value())
    }

    /// Set the state of a TCP connection
    pub fn set_tcp_state(&self, key: &TcpKey, state: ConnectionState) {
        if let Some(mut conn) = self.tcp_by_key.get_mut(key) {
            conn.state = state;
        }
    }

    /// Close a TCP connection
    pub fn close_tcp_connection(&self, key: &TcpKey) {
        if let Some((_, conn)) = self.tcp_by_key.remove(key) {
            self.tcp_by_id.remove(&conn.id);
        }
    }

    /// Get TCP sequence number for a connection
    pub fn get_tcp_seq(&self, id: u32) -> u32 {
        self.tcp_by_id
            .get(&id)
            .and_then(|key| self.tcp_by_key.get(key.value()).map(|c| c.seq))
            .unwrap_or(0)
    }

    /// Get TCP acknowledgment number for a connection
    pub fn get_tcp_ack(&self, id: u32) -> u32 {
        self.tcp_by_id
            .get(&id)
            .and_then(|key| self.tcp_by_key.get(key.value()).map(|c| c.ack))
            .unwrap_or(0)
    }

    /// Advance the TCP sequence number
    pub fn advance_tcp_seq(&self, id: u32, bytes: u32) {
        if let Some(key) = self.tcp_by_id.get(&id)
            && let Some(mut conn) = self.tcp_by_key.get_mut(key.value()) {
                conn.seq = conn.seq.wrapping_add(bytes);
            }
    }

    /// Advance the TCP seq by 1 (for SYN which consumes one sequence number)
    pub fn advance_tcp_seq_syn(&self, id: u32) {
        self.advance_tcp_seq(id, 1);
    }

    /// Update TCP ack number based on received data
    pub fn update_tcp_ack(&self, id: u32, ack: u32) {
        if let Some(key) = self.tcp_by_id.get(&id)
            && let Some(mut conn) = self.tcp_by_key.get_mut(key.value()) {
                conn.ack = ack;
            }
    }

    /// Track a UDP packet for return path routing
    pub fn track_udp(&self, src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) {
        let key = (src_port, dst_ip, dst_port);
        self.udp_mappings.insert(
            key,
            UdpMapping {
                src_ip,
                last_activity: Instant::now(),
            },
        );

        // Cleanup old mappings periodically
        self.cleanup_udp_mappings();
    }

    /// Get the original source IP for a UDP response
    pub fn get_udp_src_ip(
        &self,
        dst_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
    ) -> Option<Ipv4Addr> {
        let key = (dst_port, src_ip, src_port);
        self.udp_mappings.get(&key).map(|m| m.src_ip)
    }

    /// Remove stale UDP mappings (older than 60 seconds)
    fn cleanup_udp_mappings(&self) {
        let timeout = Duration::from_secs(60);
        let now = Instant::now();

        self.udp_mappings.retain(|_, mapping| {
            now.duration_since(mapping.last_activity) < timeout
        });
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connection_lifecycle() {
        let nat = NatTable::new();
        let key = (
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(192, 168, 1, 1),
            80,
        );

        // Create connection (client ISN = 5000)
        let id = nat.create_tcp_connection(key, 5000);
        assert_eq!(nat.get_tcp_connection_id(&key), Some(id));
        assert_eq!(nat.get_tcp_connection_key(id), Some(key));
        assert_eq!(nat.get_tcp_ack(id), 5001); // client ISN + 1

        // Update state
        nat.set_tcp_state(&key, ConnectionState::Established);

        // Close connection
        nat.close_tcp_connection(&key);
        assert_eq!(nat.get_tcp_connection_id(&key), None);
        assert_eq!(nat.get_tcp_connection_key(id), None);
    }

    #[test]
    fn test_udp_tracking() {
        let nat = NatTable::new();

        // Track outgoing UDP
        nat.track_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            54321,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        );

        // Look up return path
        let src_ip = nat.get_udp_src_ip(54321, Ipv4Addr::new(8, 8, 8, 8), 53);
        assert_eq!(src_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
