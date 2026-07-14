# ssh-proxy

An SSH tunnel proxy that routes network traffic through a remote server — a lightweight, VPN-like tunnel that needs nothing on the server side but SSH access and a copy of the binary.

## What it does

`ssh-proxy` creates a TUN interface on your local machine and transparently forwards traffic for selected subnets through an SSH connection. Applications don't need to be configured for a proxy: any TCP connection or UDP datagram destined for a routed subnet is captured, sent over SSH, and re-emitted from the remote server.

- **IPv4 and IPv6** support across all layers
- **TCP and UDP** forwarding with NAT-style connection tracking
- **DNS forwarding**: optionally forward DNS queries for specific domains to a server reachable through the tunnel, with automatic systemd-resolved integration
- **No server-side setup**: the remote end runs as an ordinary unprivileged process over SSH stdin/stdout — no root, no port openings, no configuration files
- **SSH authentication** via agent (with keyboard-interactive fallback), identity file, and `known_hosts` verification with interactive prompts for unknown host keys

## How it works

A single binary runs in one of two modes:

1. **Host mode** (`ssh-proxy host`) — runs on your local Linux machine. It creates a TUN interface, adds routes for the subnets you specify, parses the IP packets it captures, and tracks connections in a NAT table.
2. **Remote mode** (`ssh-proxy remote`) — executed automatically on the server through SSH. It speaks a length-prefixed message protocol over stdin/stdout and makes the actual TCP/UDP connections on the host's behalf.

```
App → TUN → host (packet parsing, NAT) → SSH stdin/stdout → remote (proxy) → destination
```

## Requirements

- **Host mode**: Linux (TUN device and rtnetlink), root privileges to create the TUN interface
- **Remote mode**: any platform that runs the binary; only plain TCP/UDP sockets are used

## Installation

```bash
cargo build --release
```

Copy the binary to the remote server (it must be in `PATH`, or point `--remote-binary` at it):

```bash
scp target/release/ssh-proxy user@server:/usr/local/bin/
```

## Usage

Route one IPv4 and one IPv6 subnet through the server:

```bash
sudo ./ssh-proxy host --remote server.example.com --user alice \
    --subnets 192.168.1.0/24,fd00::/64
```

Forward DNS queries for `internal.example.com` to a resolver reachable through the tunnel:

```bash
sudo ./ssh-proxy host --remote server.example.com \
    --subnets 10.10.0.0/16 \
    --dns 10.10.0.53 --dns-domains internal.example.com
```

### Options

| Option | Description |
|---|---|
| `-r, --remote <HOST[:PORT]>` | SSH destination (port defaults to 22) |
| `-u, --user <USER>` | SSH user (defaults to the current username) |
| `-s, --subnets <CIDR,...>` | Subnets to route through the tunnel |
| `-t, --tun-ip <CIDR>` | TUN interface IP (default `10.255.0.1/24`) |
| `--tun-name <NAME>` | TUN interface name (default `tun0`) |
| `-i, --identity <PATH>` | SSH private key file |
| `--remote-binary <PATH>` | Path to `ssh-proxy` on the server (default `ssh-proxy`) |
| `--dns <IP>` | DNS server to use for the tunnel |
| `--dns-domains <DOMAINS>` | Domains to forward to that DNS server |
| `-v, --verbose` | Verbose logging |

Press `ctrl-c` to shut the tunnel down; the remote process exits with the SSH session.
