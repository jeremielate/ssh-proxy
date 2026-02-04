mod nat;
mod routing;
mod ssh;
mod tun;

use crate::cli::{parse_cidr, parse_remote, HostArgs};
use crate::packet::{parse_ip_packet, ParsedPacket, TcpFlags, TcpPacketInfo, UdpPacketInfo};
use crate::protocol::{read_message, write_message, HostMessage, RemoteMessage};
use nat::{ConnectionState, NatTable};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Run the host mode
pub async fn run(args: HostArgs) -> anyhow::Result<()> {
    info!("Starting host mode");

    // Parse remote connection info
    let (user, host, port) = parse_remote(&args.remote)?;
    info!("Connecting to {}@{}:{}", user, host, port);

    // Parse TUN IP
    let (tun_ip, tun_prefix) = parse_cidr(&args.tun_ip)?;
    info!("TUN interface: {} with IP {}/{}", args.tun_name, tun_ip, tun_prefix);

    // Parse subnets to route
    let subnets: Vec<(Ipv4Addr, u8)> = args
        .subnets
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    info!("Routing subnets: {:?}", subnets);

    // Connect via SSH and start remote proxy
    let ssh_config = ssh::SshConfig {
        user,
        host: host.clone(),
        port,
        identity: args.identity,
        remote_binary: args.remote_binary,
    };

    let (ssh_reader, ssh_writer) = ssh::connect(ssh_config).await?;
    info!("SSH connection established, remote proxy started");

    // Create TUN interface
    let tun_device = tun::create_tun(&args.tun_name, tun_ip, tun_prefix).await?;
    info!("TUN interface created");

    // Add routes for subnets
    for (subnet_ip, prefix) in &subnets {
        routing::add_route(&args.tun_name, *subnet_ip, *prefix).await?;
        info!("Added route for {}/{} via {}", subnet_ip, prefix, args.tun_name);
    }

    // Run the main proxy loop
    let result = run_proxy_loop(tun_device, ssh_reader, ssh_writer, tun_ip).await;

    // Cleanup routes
    for (subnet_ip, prefix) in &subnets {
        if let Err(e) = routing::remove_route(&args.tun_name, *subnet_ip, *prefix).await {
            warn!("Failed to remove route {}/{}: {}", subnet_ip, prefix, e);
        }
    }

    result
}

async fn run_proxy_loop<R, W>(
    mut tun_device: tun::AsyncTunDevice,
    mut ssh_reader: R,
    mut ssh_writer: W,
    tun_ip: Ipv4Addr,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // Wait for remote to be ready
    match read_message::<_, RemoteMessage>(&mut ssh_reader).await? {
        Some(RemoteMessage::Ready) => {
            info!("Remote proxy ready");
        }
        Some(other) => {
            anyhow::bail!("Unexpected message from remote: {:?}", other);
        }
        None => {
            anyhow::bail!("Remote disconnected before ready");
        }
    }

    let nat_table = Arc::new(NatTable::new());
    let running = Arc::new(AtomicBool::new(true));

    // Channel for messages to send to remote
    let (to_remote_tx, mut to_remote_rx) = mpsc::channel::<HostMessage>(1024);

    // Channel for packets to write to TUN
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    let mut tun_buf = vec![0u8; 65536];

    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        tokio::select! {
            // Read packets from TUN
            result = tun_device.read(&mut tun_buf) => {
                match result {
                    Ok(n) => {
                        let packet_data = tun_buf[..n].to_vec();
                        if let Err(e) = handle_tun_packet(
                            &packet_data,
                            &nat_table,
                            &to_remote_tx,
                        ).await {
                            debug!("Error handling TUN packet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }

            // Read messages from remote
            result = read_message::<_, RemoteMessage>(&mut ssh_reader) => {
                match result {
                    Ok(Some(msg)) => {
                        if let Err(e) = handle_remote_message(
                            msg,
                            &nat_table,
                            &to_tun_tx,
                            tun_ip,
                        ).await {
                            debug!("Error handling remote message: {}", e);
                        }
                    }
                    Ok(None) => {
                        info!("Remote disconnected");
                        break;
                    }
                    Err(e) => {
                        error!("SSH read error: {}", e);
                        break;
                    }
                }
            }

            // Send messages to remote
            msg = to_remote_rx.recv() => {
                if let Some(msg) = msg {
                    if let Err(e) = write_message(&mut ssh_writer, &msg).await {
                        error!("SSH write error: {}", e);
                        break;
                    }
                }
            }

            // Write packets to TUN
            packet = to_tun_rx.recv() => {
                if let Some(packet) = packet {
                    if let Err(e) = tun_device.write(&packet).await {
                        error!("TUN write error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Send shutdown to remote
    let _ = write_message(&mut ssh_writer, &HostMessage::Shutdown).await;

    Ok(())
}

async fn handle_tun_packet(
    packet_data: &[u8],
    nat_table: &Arc<NatTable>,
    to_remote_tx: &mpsc::Sender<HostMessage>,
) -> anyhow::Result<()> {
    let parsed = parse_ip_packet(packet_data)?;

    match parsed {
        ParsedPacket::Tcp(tcp) => {
            handle_outbound_tcp(tcp, nat_table, to_remote_tx).await?;
        }
        ParsedPacket::Udp(udp) => {
            handle_outbound_udp(udp, nat_table, to_remote_tx).await?;
        }
        ParsedPacket::Other { protocol } => {
            debug!("Ignoring packet with protocol {}", protocol);
        }
    }

    Ok(())
}

async fn handle_outbound_tcp(
    tcp: TcpPacketInfo,
    nat_table: &Arc<NatTable>,
    to_remote_tx: &mpsc::Sender<HostMessage>,
) -> anyhow::Result<()> {
    let key = (tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port);

    if tcp.flags.syn && !tcp.flags.ack {
        // New connection - SYN packet
        let conn_id = nat_table.create_tcp_connection(key);
        debug!(
            "New TCP connection: id={}, {}:{} -> {}:{}",
            conn_id, tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port
        );

        to_remote_tx
            .send(HostMessage::TcpConnect {
                id: conn_id,
                dst_ip: tcp.dst_ip,
                dst_port: tcp.dst_port,
            })
            .await?;
    } else if let Some(conn_id) = nat_table.get_tcp_connection_id(&key) {
        // Existing connection
        if tcp.flags.fin || tcp.flags.rst {
            debug!("TCP close: id={}", conn_id);
            nat_table.close_tcp_connection(&key);
            to_remote_tx.send(HostMessage::TcpClose { id: conn_id }).await?;
        } else if !tcp.payload.is_empty() {
            debug!("TCP data: id={}, len={}", conn_id, tcp.payload.len());
            to_remote_tx
                .send(HostMessage::TcpData {
                    id: conn_id,
                    data: tcp.payload,
                })
                .await?;
        }
    } else {
        debug!(
            "TCP packet for unknown connection: {}:{} -> {}:{}",
            tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port
        );
    }

    Ok(())
}

async fn handle_outbound_udp(
    udp: UdpPacketInfo,
    nat_table: &Arc<NatTable>,
    to_remote_tx: &mpsc::Sender<HostMessage>,
) -> anyhow::Result<()> {
    // Track UDP "connection" for return path
    nat_table.track_udp(udp.src_ip, udp.src_port, udp.dst_ip, udp.dst_port);

    debug!(
        "UDP datagram: {}:{} -> {}:{}, len={}",
        udp.src_ip, udp.src_port, udp.dst_ip, udp.dst_port, udp.payload.len()
    );

    to_remote_tx
        .send(HostMessage::UdpDatagram {
            src_port: udp.src_port,
            dst_ip: udp.dst_ip,
            dst_port: udp.dst_port,
            data: udp.payload,
        })
        .await?;

    Ok(())
}

async fn handle_remote_message(
    msg: RemoteMessage,
    nat_table: &Arc<NatTable>,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
    _tun_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    use crate::packet::{build_tcp_packet, build_udp_packet};

    match msg {
        RemoteMessage::TcpConnected { id } => {
            debug!("TCP connected: id={}", id);
            if let Some(key) = nat_table.get_tcp_connection_key(id) {
                nat_table.set_tcp_state(&key, ConnectionState::Established);

                // Send SYN-ACK back to application
                let packet = build_tcp_packet(
                    key.2, // dst_ip becomes src
                    key.0, // src_ip becomes dst
                    key.3, // dst_port becomes src
                    key.1, // src_port becomes dst
                    0,     // seq
                    1,     // ack (acknowledging the SYN)
                    TcpFlags { syn: true, ack: true, ..Default::default() },
                    65535,
                    &[],
                );
                to_tun_tx.send(packet).await?;
            }
        }
        RemoteMessage::TcpData { id, data } => {
            debug!("TCP data from remote: id={}, len={}", id, data.len());
            if let Some(key) = nat_table.get_tcp_connection_key(id) {
                // Build TCP packet with data
                let packet = build_tcp_packet(
                    key.2,
                    key.0,
                    key.3,
                    key.1,
                    nat_table.get_tcp_seq(id),
                    nat_table.get_tcp_ack(id),
                    TcpFlags { ack: true, psh: true, ..Default::default() },
                    65535,
                    &data,
                );
                nat_table.advance_tcp_seq(id, data.len() as u32);
                to_tun_tx.send(packet).await?;
            }
        }
        RemoteMessage::TcpClosed { id } => {
            debug!("TCP closed: id={}", id);
            if let Some(key) = nat_table.get_tcp_connection_key(id) {
                // Send FIN packet
                let packet = build_tcp_packet(
                    key.2,
                    key.0,
                    key.3,
                    key.1,
                    nat_table.get_tcp_seq(id),
                    nat_table.get_tcp_ack(id),
                    TcpFlags { fin: true, ack: true, ..Default::default() },
                    65535,
                    &[],
                );
                to_tun_tx.send(packet).await?;
                nat_table.close_tcp_connection(&key);
            }
        }
        RemoteMessage::TcpError { id, error } => {
            warn!("TCP error: id={}, error={}", id, error);
            if let Some(key) = nat_table.get_tcp_connection_key(id) {
                // Send RST packet
                let packet = build_tcp_packet(
                    key.2,
                    key.0,
                    key.3,
                    key.1,
                    0,
                    0,
                    TcpFlags { rst: true, ..Default::default() },
                    0,
                    &[],
                );
                to_tun_tx.send(packet).await?;
                nat_table.close_tcp_connection(&key);
            }
        }
        RemoteMessage::UdpResponse { dst_port, src_ip, src_port, data } => {
            debug!(
                "UDP response: src={}:{}, dst_port={}, len={}",
                src_ip, src_port, dst_port, data.len()
            );

            // Find the original source IP for this UDP "connection"
            if let Some(original_src_ip) = nat_table.get_udp_src_ip(dst_port, src_ip, src_port) {
                let packet = build_udp_packet(
                    src_ip,
                    original_src_ip,
                    src_port,
                    dst_port,
                    &data,
                );
                to_tun_tx.send(packet).await?;
            } else {
                warn!("UDP response for unknown mapping: dst_port={}", dst_port);
            }
        }
        RemoteMessage::Ready => {
            // Already handled earlier
        }
        RemoteMessage::Error { error } => {
            error!("Remote error: {}", error);
        }
    }

    Ok(())
}
