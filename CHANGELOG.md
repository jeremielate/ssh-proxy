# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-20

### Added

- Continuous integration workflow that lints (rustfmt + clippy pedantic),
  tests, and builds static musl release binaries for `x86_64` and `aarch64`,
  publishing them to GitHub Releases on `v*` tags.
- Pinned Rust toolchain via `rust-toolchain.toml` for reproducible builds.

### Changed

- Updated `netlink-packet-route` to 0.30 and adapted SSH agent authentication
  to the new russh identities API.
- Refactored packet builders into `TcpPacket` / `UdpPacket` structs and
  enforced clippy pedantic across the codebase.
- Host mode is now gated to Linux while remote mode builds cross-platform.

## [0.1.0]

### Added

- SSH tunnel proxy routing selected subnets through a remote server via a
  local TUN interface, with no server-side setup beyond SSH access.
- IPv4 and IPv6 support across all layers.
- TCP and UDP forwarding with NAT-style connection tracking.
- DNS forwarding for specific domains with automatic systemd-resolved
  integration (`--dns`, `--domains`).
- SSH authentication via agent with keyboard-interactive fallback, identity
  files, and `known_hosts` verification with interactive prompts for unknown
  host keys.

[Unreleased]: https://github.com/jeremielate/ssh-proxy/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jeremielate/ssh-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jeremielate/ssh-proxy/releases/tag/v0.1.0
