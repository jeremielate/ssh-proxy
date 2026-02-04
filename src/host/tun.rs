use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use tun::{AsyncDevice, Configuration};

/// Wrapper around the TUN device for async I/O
pub struct AsyncTunDevice {
    #[cfg(target_os = "linux")]
    device: AsyncDevice,
    #[cfg(not(target_os = "linux"))]
    _phantom: std::marker::PhantomData<()>,
}

impl AsyncTunDevice {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.device.read(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux, just wait forever (this code path shouldn't be used)
            let _ = buf;
            std::future::pending::<std::io::Result<usize>>().await
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            self.device.write(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf;
            Ok(0)
        }
    }
}

/// Create a TUN device with the given name and IP address
#[cfg(target_os = "linux")]
pub async fn create_tun(name: &str, ip: Ipv4Addr, prefix: u8) -> anyhow::Result<AsyncTunDevice> {
    use std::process::Command;

    let mut config = Configuration::default();

    config
        .name(name)
        .address(ip)
        .netmask(prefix_to_netmask(prefix))
        .mtu(1500)
        .up();

    let device = tun::create_as_async(&config)?;

    info!(
        "Created TUN device {} with IP {}/{}",
        name, ip, prefix
    );

    // The tun crate should bring the interface up, but let's make sure
    // Also set the IP address explicitly using ip command as backup
    let _ = Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .output();

    let _ = Command::new("ip")
        .args([
            "addr",
            "add",
            &format!("{}/{}", ip, prefix),
            "dev",
            name,
        ])
        .output();

    Ok(AsyncTunDevice { device })
}

#[cfg(not(target_os = "linux"))]
pub async fn create_tun(_name: &str, _ip: Ipv4Addr, _prefix: u8) -> anyhow::Result<AsyncTunDevice> {
    anyhow::bail!(
        "TUN device creation is only supported on Linux. \
        Current platform: {}",
        std::env::consts::OS
    );
}

/// Convert a CIDR prefix to a netmask
#[allow(dead_code)]
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else if prefix >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
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
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
