# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
cargo build              # Build debug
cargo build --release    # Build release
cargo test               # Run all tests
cargo test test_name     # Run single test
cargo check              # Fast type checking
```

## Architecture

This is an SSH tunnel proxy that routes traffic through a remote server. It supports both **IPv4 and IPv6**. It's a **single binary** with two modes:

### Two-Mode Design

1. **Host mode** (`ssh-proxy host`): Runs on your local machine
   - Creates a TUN interface to capture network traffic
   - Parses IPv4/IPv6 packets and extracts TCP/UDP data
   - Maintains NAT table for connection tracking
   - Connects via SSH and executes the remote binary

2. **Remote mode** (`ssh-proxy remote`): Automatically executed on the server via SSH
   - Communicates via stdin/stdout (not direct network)
   - Makes actual TCP/UDP connections on behalf of the host
   - Runs without special privileges

### Data Flow

```
App → TUN → Host (parse packets, NAT) → SSH stdin/stdout → Remote (proxy) → Destination
```

### Wire Protocol

Host and remote communicate using length-prefixed postcard messages over SSH stdin/stdout. All IP addresses use `IpAddr` (dual-stack):
- `HostMessage`: TcpConnect, TcpData, TcpClose, UdpDatagram, Shutdown
- `RemoteMessage`: TcpConnected, TcpData, TcpClosed, TcpError, UdpResponse, Ready

### Key Modules

- `src/host/` - Host mode: SSH client, TUN device, routing, NAT table
- `src/remote/` - Remote mode: proxy engine for TCP/UDP
- `src/protocol.rs` - Message types and serialization
- `src/packet.rs` - IPv4/IPv6 packet parsing and building with etherparse

### Platform Constraints

- **Host mode**: Linux only (requires TUN device and rtnetlink)
- **Remote mode**: Cross-platform (just TCP/UDP sockets)

Linux-specific dependencies (`tun`, `rtnetlink`) are conditionally compiled with `#[cfg(target_os = "linux")]`.

## Usage

```bash
# On remote server (copy binary first)
scp target/release/ssh-proxy user@server:/usr/local/bin/

# On host (Linux, requires sudo for TUN)
sudo ./ssh-proxy host --remote user@server --subnets 192.168.1.0/24,fd00::/64
```
