use etherparse::{IpNumber, Ipv4HeaderSlice, PacketBuilder, TcpHeaderSlice, UdpHeaderSlice};
use std::net::Ipv4Addr;

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
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
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
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Parse an IP packet from raw bytes
pub fn parse_ip_packet(data: &[u8]) -> anyhow::Result<ParsedPacket> {
    // Check minimum length for IPv4 header
    if data.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    // Check IP version
    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        anyhow::bail!("Not an IPv4 packet (version: {})", version);
    }

    let ip_header = Ipv4HeaderSlice::from_slice(data)?;
    let src_ip = Ipv4Addr::from(ip_header.source());
    let dst_ip = Ipv4Addr::from(ip_header.destination());
    let protocol = ip_header.protocol();
    let header_len = ip_header.slice().len();
    let total_len = ip_header.total_len() as usize;

    // Get payload (everything after IP header, respecting total_len)
    let payload_start = header_len;
    let payload_end = total_len.min(data.len());
    let ip_payload = &data[payload_start..payload_end];

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
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64);

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
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
        .udp(src_port, dst_port);

    let mut result = Vec::with_capacity(28 + payload.len());
    builder.write(&mut result, payload).expect("Failed to write UDP packet");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_packet_roundtrip() {
        let packet = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
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
                assert_eq!(info.src_ip, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(info.dst_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(info.src_port, 12345);
                assert_eq!(info.dst_port, 80);
                assert!(info.flags.syn);
            }
            _ => panic!("Expected TCP packet"),
        }
    }

    #[test]
    fn test_udp_packet_roundtrip() {
        let payload = b"Hello, UDP!";
        let packet = build_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            54321,
            53,
            payload,
        );

        match parse_ip_packet(&packet).unwrap() {
            ParsedPacket::Udp(info) => {
                assert_eq!(info.src_ip, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(info.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(info.src_port, 54321);
                assert_eq!(info.dst_port, 53);
                assert_eq!(info.payload, payload);
            }
            _ => panic!("Expected UDP packet"),
        }
    }
}
