use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::debug;

/// Messages sent from host to remote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostMessage {
    /// Request to open a TCP connection
    TcpConnect {
        /// Connection ID for tracking
        id: u32,
        /// Destination IP address
        dst_ip: IpAddr,
        /// Destination port
        dst_port: u16,
    },
    /// Send data on an established TCP connection
    TcpData {
        /// Connection ID
        id: u32,
        /// Data payload
        data: Vec<u8>,
    },
    /// Close a TCP connection
    TcpClose {
        /// Connection ID
        id: u32,
    },
    /// Send a UDP datagram
    UdpDatagram {
        /// Source port (for return routing)
        src_port: u16,
        /// Destination IP address
        dst_ip: IpAddr,
        /// Destination port
        dst_port: u16,
        /// Datagram payload
        data: Vec<u8>,
    },
    /// Forward a DNS query to a specific server
    DnsQuery {
        /// Query ID for tracking
        id: u32,
        /// DNS server to forward to
        server: IpAddr,
        /// Raw DNS query data
        data: Vec<u8>,
    },
    /// Shutdown the remote proxy
    Shutdown,
}

/// Messages sent from remote to host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemoteMessage {
    /// TCP connection established
    TcpConnected {
        /// Connection ID
        id: u32,
    },
    /// Data received on TCP connection
    TcpData {
        /// Connection ID
        id: u32,
        /// Data payload
        data: Vec<u8>,
    },
    /// TCP connection closed by remote end
    TcpClosed {
        /// Connection ID
        id: u32,
    },
    /// TCP connection error
    TcpError {
        /// Connection ID
        id: u32,
        /// Error message
        error: String,
    },
    /// UDP response datagram
    UdpResponse {
        /// Destination port on host (original src_port)
        dst_port: u16,
        /// Source IP of the response
        src_ip: IpAddr,
        /// Source port of the response
        src_port: u16,
        /// Response payload
        data: Vec<u8>,
    },
    /// DNS query response
    DnsResponse {
        /// Query ID for tracking
        id: u32,
        /// Raw DNS response data
        data: Vec<u8>,
    },
    /// Remote ready
    Ready,
    /// Remote error
    Error { error: String },
}

/// Read a length-prefixed message from an async reader
pub async fn read_message<R, T>(reader: &mut R) -> anyhow::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let buf = {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        // let mut reader = reader.lock().await;
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 16 * 1024 * 1024 {
            anyhow::bail!("Message too large: {} bytes", len);
        }

        // Read message body
        debug!("reading message len={len}");
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        buf
    };

    // Deserialize
    let msg: T = postcard::from_bytes(&buf)?;
    Ok(Some(msg))
}

/// Write a length-prefixed message to an async writer
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let data: Vec<u8> = postcard::to_allocvec(msg)?;
    let len = data.len() as u32;
    debug!("writing message len={len}");

    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_message_roundtrip() {
        let msg = HostMessage::TcpConnect {
            id: 42,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_port: 80,
        };

        let mut buf = Mutex::new(Vec::new());
        write_message(&mut buf, &msg).await.unwrap();

        let inner_buf = buf.into_inner();
        let cursor = Arc::new(Mutex::new(Cursor::new(inner_buf)));
        let decoded: HostMessage = read_message(cursor).await.unwrap().unwrap();

        match decoded {
            HostMessage::TcpConnect {
                id,
                dst_ip,
                dst_port,
            } => {
                assert_eq!(id, 42);
                assert_eq!(dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
