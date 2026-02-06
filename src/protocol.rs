use serde::{Deserialize, Serialize};
use tracing::debug;
use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Messages sent from host to remote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostMessage {
    /// Request to open a TCP connection
    TcpConnect {
        /// Connection ID for tracking
        id: u32,
        /// Destination IP address
        dst_ip: Ipv4Addr,
        /// Destination port
        dst_port: u16,
    },
    /// Send data on an established TCP connection
    TcpData {
        /// Connection ID
        id: u32,
        /// Data payload
        #[serde(with = "serde_bytes")]
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
        dst_ip: Ipv4Addr,
        /// Destination port
        dst_port: u16,
        /// Datagram payload
        #[serde(with = "serde_bytes")]
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
        #[serde(with = "serde_bytes")]
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
        src_ip: Ipv4Addr,
        /// Source port of the response
        src_port: u16,
        /// Response payload
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    /// Remote ready
    Ready,
    /// Remote error
    Error {
        error: String,
    },
}

/// Read a length-prefixed message from an async reader
pub async fn read_message<R, T>(reader: &mut R) -> anyhow::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
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

    // Deserialize
    let msg: T = postcard::from_bytes(&buf)?;
    Ok(Some(msg))
}

/// Write a length-prefixed message to an async writer
pub async fn write_message<W, T>(mut writer: W, msg: &T) -> anyhow::Result<()>
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

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_message_roundtrip() {
        let msg = HostMessage::TcpConnect {
            id: 42,
            dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_port: 80,
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: HostMessage = read_message(&mut cursor).await.unwrap().unwrap();

        match decoded {
            HostMessage::TcpConnect { id, dst_ip, dst_port } => {
                assert_eq!(id, 42);
                assert_eq!(dst_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(dst_port, 80);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
