use clap::{Parser, Subcommand};
use std::net::Ipv4Addr;
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
    /// Remote SSH destination (user@host or user@host:port)
    #[arg(short, long)]
    pub remote: String,

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
    pub dns: Option<Ipv4Addr>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

/// Parse a remote string like "user@host" or "user@host:port"
pub fn parse_remote(remote: &str) -> anyhow::Result<(String, String, u16)> {
    let (user_host, port) = if remote.contains(':') {
        let parts: Vec<&str> = remote.rsplitn(2, ':').collect();
        let port: u16 = parts[0].parse()?;
        (parts[1], port)
    } else {
        (remote, 22)
    };

    let parts: Vec<&str> = user_host.splitn(2, '@').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid remote format. Expected user@host or user@host:port");
    }

    Ok((parts[0].to_string(), parts[1].to_string(), port))
}

/// Parse a CIDR notation string like "192.168.1.0/24"
pub fn parse_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR format. Expected x.x.x.x/prefix");
    }

    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix: u8 = parts[1].parse()?;

    if prefix > 32 {
        anyhow::bail!("Invalid prefix length: {}", prefix);
    }

    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_remote() {
        let (user, host, port) = parse_remote("user@example.com").unwrap();
        assert_eq!(user, "user");
        assert_eq!(host, "example.com");
        assert_eq!(port, 22);

        let (user, host, port) = parse_remote("admin@192.168.1.1:2222").unwrap();
        assert_eq!(user, "admin");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn test_parse_cidr() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);

        let (ip, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(prefix, 8);
    }
}
