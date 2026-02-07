use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ssh-proxy")]
#[command(about = "SSH tunnel proxy for routing traffic through a remote server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run in host mode: create TUN interface and tunnel traffic through SSH
    Host(HostArgs),
    /// Run in remote mode: proxy connections (executed automatically via SSH)
    Remote,
}

#[derive(Parser, Debug)]
pub struct HostArgs {
    /// Remote SSH destination (host or host:port)
    #[arg(short, long)]
    pub remote: String,

    /// Remote SSH user
    #[arg(short, long, default_value_t = default_user())]
    pub user: String,

    /// Subnets to route through the tunnel (e.g., 192.168.1.0/24)
    #[arg(short, long, value_delimiter = ',')]
    pub subnets: Vec<String>,

    /// IP address for the TUN interface (e.g., 10.0.0.1/24)
    #[arg(short, long, default_value = "10.255.0.1/24")]
    pub tun_ip: String,

    /// Name for the TUN interface
    #[arg(long, default_value = "tun0")]
    pub tun_name: String,

    /// Path to SSH private key
    #[arg(short, long)]
    pub identity: Option<PathBuf>,

    /// Path to the remote binary (default: ssh-proxy)
    #[arg(long, default_value = "ssh-proxy")]
    pub remote_binary: String,

    /// DNS server to use for the tunnel
    #[arg(long)]
    pub dns: Option<IpAddr>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

fn default_user() -> String {
    users::get_current_username()
        .and_then(|u| u.into_string().ok())
        .unwrap_or_else(|| String::from("root"))
}

/// Parse a remote string like "user@host" or "user@host:port"
pub fn parse_remote(remote: &str) -> anyhow::Result<(String, u16)> {
    if remote.contains(':') {
        let parts: Vec<&str> = remote.splitn(2, ':').collect();
        let port: u16 = parts[1].parse()?;
        Ok((parts[0].to_string(), port))
    } else {
        Ok((remote.to_string(), 22))
    }
}

/// Parse a CIDR notation string like "192.168.1.0/24" or "fd00::/64"
pub fn parse_cidr(cidr: &str) -> anyhow::Result<(IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR format. Expected address/prefix");
    }

    let ip: IpAddr = parts[0].parse()?;
    let prefix: u8 = parts[1].parse()?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        anyhow::bail!("Invalid prefix length: {} (max {} for {:?})", prefix, max_prefix, ip);
    }

    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_remote() {
        let (host, port) = parse_remote("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 22);

        let (host, port) = parse_remote("192.168.1.1:2222").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn test_parse_cidr_ipv4() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(prefix, 24);

        let (ip, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(prefix, 8);
    }

    #[test]
    fn test_parse_cidr_ipv6() {
        let (ip, prefix) = parse_cidr("fd00::/64").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)));
        assert_eq!(prefix, 64);

        let (ip, prefix) = parse_cidr("2001:db8::/32").unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_parse_cidr_invalid_prefix() {
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("fd00::/129").is_err());
    }
}
