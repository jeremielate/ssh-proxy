use etherparse::{IpNumber, Ipv4HeaderSlice, Ipv6ExtensionsSlice, Ipv6Header, Ipv6HeaderSlice, PacketBuilder, TcpHeaderSlice, UdpHeaderSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parsed packet information
#[derive(Debug, Clone)]
pub enum ParsedPacket {
    Tcp(TcpPacketInfo),
    Udp(UdpPacketInfo),
    Other { protocol: u8 },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TcpPacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Debug, Clone)]
pub struct UdpPacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Parse an IP packet from raw bytes
pub fn parse_ip_packet(data: &[u8]) -> anyhow::Result<ParsedPacket> {
    if data.is_empty() {
        anyhow::bail!("Empty packet");
    }

    let version = (data[0] >> 4) & 0xF;
    match version {
        4 => parse_ipv4_packet(data),
        6 => parse_ipv6_packet(data),
        _ => anyhow::bail!("Unknown IP version: {}", version),
    }
}

fn parse_ipv4_packet(data: &[u8]) -> anyhow::Result<ParsedPacket> {
    if data.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    let ip_header = Ipv4HeaderSlice::from_slice(data)?;
    let src_ip = IpAddr::V4(Ipv4Addr::from(ip_header.source()));
    let dst_ip = IpAddr::V4(Ipv4Addr::from(ip_header.destination()));
    let protocol = ip_header.protocol();
    let header_len = ip_header.slice().len();
    let total_len = ip_header.total_len() as usize;

    let payload_start = header_len;
    let payload_end = total_len.min(data.len());
    let ip_payload = &data[payload_start..payload_end];

    parse_transport(protocol, src_ip, dst_ip, ip_payload)
}

fn parse_ipv6_packet(data: &[u8]) -> anyhow::Result<ParsedPacket> {
    if data.len() < Ipv6Header::LEN {
        anyhow::bail!("Packet too short for IPv6 header");
    }

    let ip_header = Ipv6HeaderSlice::from_slice(data)?;
    let src_ip = IpAddr::V6(Ipv6Addr::from(ip_header.source()));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(ip_header.destination()));
    let next_header = ip_header.next_header();
    let payload_length = ip_header.payload_length() as usize;

    let remaining = &data[Ipv6Header::LEN..data.len().min(Ipv6Header::LEN + payload_length)];

    // Walk extension headers to find the actual transport protocol and payload
    let (_exts, protocol, transport_payload) =
        Ipv6ExtensionsSlice::from_slice(next_header, remaining)?;

    parse_transport(protocol, src_ip, dst_ip, transport_payload)
}

fn parse_transport(
    protocol: IpNumber,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_payload: &[u8],
) -> anyhow::Result<ParsedPacket> {
    match protocol {
        IpNumber::TCP => {
            if ip_payload.len() < 20 {
                anyhow::bail!("Packet too short for TCP header");
            }

            let tcp_header = TcpHeaderSlice::from_slice(ip_payload)?;
            let tcp_header_len = tcp_header.slice().len();
            let tcp_payload = &ip_payload[tcp_header_len..];

            Ok(ParsedPacket::Tcp(TcpPacketInfo {
                src_ip,
                dst_ip,
                src_port: tcp_header.source_port(),
                dst_port: tcp_header.destination_port(),
                seq: tcp_header.sequence_number(),
                ack: tcp_header.acknowledgment_number(),
                flags: TcpFlags {
                    syn: tcp_header.syn(),
                    ack: tcp_header.ack(),
                    fin: tcp_header.fin(),
                    rst: tcp_header.rst(),
                    psh: tcp_header.psh(),
                },
                window: tcp_header.window_size(),
                payload: tcp_payload.to_vec(),
            }))
        }
        IpNumber::UDP => {
            if ip_payload.len() < 8 {
                anyhow::bail!("Packet too short for UDP header");
            }

            let udp_header = UdpHeaderSlice::from_slice(ip_payload)?;
            let udp_payload = &ip_payload[8..];

            Ok(ParsedPacket::Udp(UdpPacketInfo {
                src_ip,
                dst_ip,
                src_port: udp_header.source_port(),
                dst_port: udp_header.destination_port(),
                payload: udp_payload.to_vec(),
            }))
        }
        other => Ok(ParsedPacket::Other {
            protocol: other.0,
        }),
    }
}

/// Build a TCP packet
pub fn build_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
        }
        _ => panic!("Mismatched IP address families in build_tcp_packet"),
    };

    let mut tcp = builder.tcp(src_port, dst_port, seq, window);

    if flags.syn {
        tcp = tcp.syn();
    }
    if flags.ack {
        tcp = tcp.ack(ack);
    }
    if flags.fin {
        tcp = tcp.fin();
    }
    if flags.rst {
        tcp = tcp.rst();
    }
    if flags.psh {
        tcp = tcp.psh();
    }

    let mut result = Vec::with_capacity(60 + payload.len());
    tcp.write(&mut result, payload).expect("Failed to write TCP packet");
    result
}

/// Build a UDP packet
pub fn build_udp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            PacketBuilder::ipv4(src.octets(), dst.octets(), 64)
                .udp(src_port, dst_port)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                .udp(src_port, dst_port)
        }
        _ => panic!("Mismatched IP address families in build_udp_packet"),
    };

    let mut result = Vec::with_capacity(28 + payload.len());
    builder.write(&mut result, payload).expect("Failed to write UDP packet");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_packet_roundtrip() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let packet = build_tcp_packet(
            src,
            dst,
            12345,
            80,
            1000,
            0,
            TcpFlags { syn: true, ..Default::default() },
            65535,
            &[],
        );

        match parse_ip_packet(&packet).unwrap() {
            ParsedPacket::Tcp(info) => {
                assert_eq!(info.src_ip, src);
                assert_eq!(info.dst_ip, dst);
                assert_eq!(info.src_port, 12345);
                assert_eq!(info.dst_port, 80);
                assert!(info.flags.syn);
            }
            _ => panic!("Expected TCP packet"),
        }
    }

    #[test]
    fn test_udp_packet_roundtrip() {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let payload = b"Hello, UDP!";
        let packet = build_udp_packet(src, dst, 54321, 53, payload);

        match parse_ip_packet(&packet).unwrap() {
            ParsedPacket::Udp(info) => {
                assert_eq!(info.src_ip, src);
                assert_eq!(info.dst_ip, dst);
                assert_eq!(info.src_port, 54321);
                assert_eq!(info.dst_port, 53);
                assert_eq!(info.payload, payload);
            }
            _ => panic!("Expected UDP packet"),
        }
    }

    #[test]
    fn test_tcp_packet_roundtrip_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let packet = build_tcp_packet(
            src,
            dst,
            12345,
            443,
            2000,
            0,
            TcpFlags { syn: true, ..Default::default() },
            65535,
            &[],
        );

        match parse_ip_packet(&packet).unwrap() {
            ParsedPacket::Tcp(info) => {
                assert_eq!(info.src_ip, src);
                assert_eq!(info.dst_ip, dst);
                assert_eq!(info.src_port, 12345);
                assert_eq!(info.dst_port, 443);
                assert!(info.flags.syn);
            }
            _ => panic!("Expected TCP packet"),
        }
    }

    #[test]
    fn test_udp_packet_roundtrip_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        let payload = b"Hello, IPv6 UDP!";
        let packet = build_udp_packet(src, dst, 54321, 53, payload);

        match parse_ip_packet(&packet).unwrap() {
            ParsedPacket::Udp(info) => {
                assert_eq!(info.src_ip, src);
                assert_eq!(info.dst_ip, dst);
                assert_eq!(info.src_port, 54321);
                assert_eq!(info.dst_port, 53);
                assert_eq!(info.payload, payload);
            }
            _ => panic!("Expected UDP packet"),
        }
    }
}
