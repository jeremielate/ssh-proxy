use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;
use tun::{AsyncDevice, Configuration};

/// Wrapper around the TUN device for async I/O
pub struct AsyncTunDevice {
    device: AsyncDevice,
}

impl AsyncTunDevice {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.read(buf).await
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.device.write(buf).await
    }
}

/// Create a TUN device with the given name and IP address
// Kept async: the interface is awaited by callers and the commented-out
// rtnetlink setup below is expected to reintroduce `.await`.
#[allow(clippy::unused_async)]
pub async fn create_tun(name: &str) -> anyhow::Result<AsyncTunDevice> {
    // use netlink_packet_route::link::InfoKind;
    // use rtnetlink::{LinkMessageBuilder, new_connection};
    // use std::process::Command;

    let mut config = Configuration::default();

    config.tun_name(name).mtu(1500).up();

    let device = tun::create_as_async(&config)?;

    info!("Created TUN device {}", name);

    // The tun crate should bring the interface up, but let's make sure
    // Also set the IP address explicitly using ip command as backup
    // let _ = Command::new("ip")
    //     .args(["link", "set", "dev", name, "up"])
    //     .output();

    // let (connection, handle, _) = new_connection()?;
    // tokio::spawn(connection);

    // let index = device.tun_index()?;

    // let link_message = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(InfoKind::Tun)
    //     .index(index as u32)
    //     .up()
    //     .build();
    // handle.link().add(link_message).execute().await?;

    Ok(AsyncTunDevice { device })
}

/// Convert a CIDR prefix to a netmask
#[allow(dead_code)]
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else if prefix >= 32 {
        Ipv4Addr::BROADCAST
    } else {
        let mask = !((1u32 << (32 - prefix)) - 1);
        Ipv4Addr::from(mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::BROADCAST);
    }
}
