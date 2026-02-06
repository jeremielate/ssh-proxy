mod nat;
mod routing;
mod ssh;
mod tun;

use crate::cli::{HostArgs, parse_cidr, parse_remote};
use crate::packet::{ParsedPacket, TcpFlags, TcpPacketInfo, UdpPacketInfo, build_tcp_packet, parse_ip_packet};
use crate::protocol::{HostMessage, RemoteMessage, read_message, write_message};

use std::net::Ipv4Addr;
use std::sync::Arc;

use nat::{ConnectionState, NatTable};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal::ctrl_c;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, error, info, warn};

/// Run the host mode
pub async fn run(args: HostArgs) -> anyhow::Result<()> {
    info!("Starting host mode");

    // Parse remote connection info
    let (host, port) = parse_remote(&args.remote)?;
    info!("Connecting to {}@{}:{}", args.user, host, port);

    info!("TUN interface: {}", args.tun_name);

    // Parse subnets to route
    let subnets: Vec<(Ipv4Addr, u8)> = args
        .subnets
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    info!("Routing subnets: {:?}", subnets);

    // Connect via SSH and start remote proxy
    let ssh_config = ssh::SshConfig {
        user: args.user,
        host: host.clone(),
        port,
        identity: args.identity,
        remote_binary: args.remote_binary,
    };

    let (ssh_reader, ssh_writer) = ssh::connect(ssh_config).await?;
    info!("SSH connection established, remote proxy started");

    // Create TUN interface
    let tun_device = tun::create_tun(&args.tun_name).await?;
    info!("TUN interface created");

    // Add routes for subnets
    for (subnet_ip, prefix) in &subnets {
        routing::add_route(&args.tun_name, *subnet_ip, *prefix).await?;
        info!(
            "Added route for {}/{} via {}",
            subnet_ip, prefix, args.tun_name
        );
    }

    // Run the main proxy loop
    let result = run_proxy_loop(tun_device, ssh_reader, ssh_writer).await;

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

    // Channel for messages to send to remote
    let (to_remote_tx, mut to_remote_rx) = mpsc::channel::<HostMessage>(1024);

    // Channel for packets to write to TUN
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    let mut tun_buf = vec![0u8; 65536];

    loop {
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
                            &to_tun_tx,
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
                if let Some(msg) = msg
                    && let Err(e) = write_message(&mut ssh_writer, &msg).await {
                        error!("SSH write error: {}", e);
                        break;
                    }
            }

            // Write packets to TUN
            packet = to_tun_rx.recv() => {
                if let Some(packet) = packet
                    && let Err(e) = tun_device.write(&packet).await {
                        error!("TUN write error: {}", e);
                        break;
                    }
            }

            _ = ctrl_c() => {
                debug!("ctrl+c received, quitting");
                break;
            }
        }
    }

    // Send shutdown to remote
    let _ = write_message(&mut ssh_writer, &HostMessage::Shutdown).await;
    debug!("shutdown sent");

    Ok(())
}

async fn handle_tun_packet(
    packet_data: &[u8],
    nat_table: &Arc<NatTable>,
    to_remote_tx: &mpsc::Sender<HostMessage>,
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()> {
    let parsed = parse_ip_packet(packet_data)?;

    match parsed {
        ParsedPacket::Tcp(tcp) => {
            handle_outbound_tcp(tcp, nat_table, to_remote_tx, to_tun_tx).await?;
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
    to_tun_tx: &mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()> {
    let key = (tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port);

    if tcp.flags.syn && !tcp.flags.ack {
        // New connection - SYN packet
        let conn_id = nat_table.create_tcp_connection(key, tcp.seq);
        debug!(
            "New TCP connection: id={}, {}:{} -> {}:{} (client ISN={})",
            conn_id, tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port, tcp.seq
        );

        to_remote_tx
            .send(HostMessage::TcpConnect {
                id: conn_id,
                dst_ip: tcp.dst_ip,
                dst_port: tcp.dst_port,
            })
            .await?;
        return Ok(());
    }

    let Some(conn_id) = nat_table.get_tcp_connection_id(&key) else {
        // Ignore packets for unknown connections (e.g. stale ACKs after close)
        debug!(
            "TCP packet for unknown connection: {}:{} -> {}:{}",
            tcp.src_ip, tcp.src_port, tcp.dst_ip, tcp.dst_port
        );
        return Ok(());
    };

    // RST always immediately closes regardless of state
    if tcp.flags.rst {
        debug!("TCP RST: id={}", conn_id);
        nat_table.close_tcp_connection(&key);
        to_remote_tx
            .send(HostMessage::TcpClose { id: conn_id })
            .await?;
        return Ok(());
    }

    let state = nat_table.get_tcp_state(&key);

    match state {
        Some(ConnectionState::Established) => {
            if tcp.flags.fin {
                // App initiates close
                debug!("TCP FIN from app: id={}", conn_id);

                // ACK the FIN (FIN consumes 1 seq number, plus any payload)
                let fin_ack = tcp
                    .seq
                    .wrapping_add(tcp.payload.len() as u32)
                    .wrapping_add(1);
                nat_table.update_tcp_ack(conn_id, fin_ack);

                // Forward any piggybacked data
                if !tcp.payload.is_empty() {
                    to_remote_tx
                        .send(HostMessage::TcpData {
                            id: conn_id,
                            data: tcp.payload,
                        })
                        .await?;
                }

                // Send ACK for the FIN back to app
                let ack_packet = build_tcp_packet(
                    key.2,
                    key.0,
                    key.3,
                    key.1,
                    nat_table.get_tcp_seq(conn_id),
                    nat_table.get_tcp_ack(conn_id),
                    TcpFlags {
                        ack: true,
                        ..Default::default()
                    },
                    65535,
                    &[],
                );
                to_tun_tx.send(ack_packet).await?;

                // Tell remote to close
                to_remote_tx
                    .send(HostMessage::TcpClose { id: conn_id })
                    .await?;

                nat_table.set_tcp_state(&key, ConnectionState::FinWait);
            } else if !tcp.payload.is_empty() {
                // Normal data
                debug!("TCP data: id={}, len={}", conn_id, tcp.payload.len());
                nat_table.update_tcp_ack(
                    conn_id,
                    tcp.seq.wrapping_add(tcp.payload.len() as u32),
                );
                to_remote_tx
                    .send(HostMessage::TcpData {
                        id: conn_id,
                        data: tcp.payload,
                    })
                    .await?;
            }
            // Bare ACKs in Established state are normal (acking our data), ignore
        }

        Some(ConnectionState::CloseWait) => {
            // Remote already closed, we sent FIN to app, waiting for app's FIN
            if tcp.flags.fin {
                debug!("TCP FIN from app (CloseWait): id={}", conn_id);

                // ACK the app's FIN
                let fin_ack = tcp.seq.wrapping_add(1);
                nat_table.update_tcp_ack(conn_id, fin_ack);

                let ack_packet = build_tcp_packet(
                    key.2,
                    key.0,
                    key.3,
                    key.1,
                    nat_table.get_tcp_seq(conn_id),
                    nat_table.get_tcp_ack(conn_id),
                    TcpFlags {
                        ack: true,
                        ..Default::default()
                    },
                    65535,
                    &[],
                );
                to_tun_tx.send(ack_packet).await?;

                // Both sides have FIN'd, fully closed
                nat_table.close_tcp_connection(&key);
            }
            // Bare ACKs (acking our FIN) are expected, no action needed
        }

        Some(ConnectionState::LastAck) => {
            // App already FIN'd, we sent FIN after remote closed, waiting for app's ACK
            if tcp.flags.ack {
                debug!("TCP ACK of our FIN (LastAck): id={}", conn_id);
                nat_table.close_tcp_connection(&key);
            }
        }

        Some(ConnectionState::FinWait) => {
            // We're waiting for remote to close, ignore app packets
            debug!("Ignoring packet in FinWait state: id={}", conn_id);
        }

        _ => {
            debug!(
                "TCP packet in unexpected state {:?}: id={}",
                state, conn_id
            );
        }
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
        udp.src_ip,
        udp.src_port,
        udp.dst_ip,
        udp.dst_port,
        udp.payload.len()
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
) -> anyhow::Result<()> {
    use crate::packet::build_udp_packet;

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
                    nat_table.get_tcp_seq(id),
                    nat_table.get_tcp_ack(id),
                    TcpFlags {
                        syn: true,
                        ack: true,
                        ..Default::default()
                    },
                    65535,
                    &[],
                );
                // SYN consumes one sequence number
                nat_table.advance_tcp_seq_syn(id);
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
                    TcpFlags {
                        ack: true,
                        psh: true,
                        ..Default::default()
                    },
                    65535,
                    &data,
                );
                nat_table.advance_tcp_seq(id, data.len() as u32);
                to_tun_tx.send(packet).await?;
            }
        }
        RemoteMessage::TcpClosed { id } => {
            debug!("TCP closed from remote: id={}", id);
            if let Some(key) = nat_table.get_tcp_connection_key(id) {
                let state = nat_table.get_tcp_state(&key);
                match state {
                    Some(ConnectionState::Established) => {
                        // Remote closed first — send FIN+ACK to app
                        let packet = build_tcp_packet(
                            key.2,
                            key.0,
                            key.3,
                            key.1,
                            nat_table.get_tcp_seq(id),
                            nat_table.get_tcp_ack(id),
                            TcpFlags {
                                fin: true,
                                ack: true,
                                ..Default::default()
                            },
                            65535,
                            &[],
                        );
                        // FIN consumes 1 sequence number
                        nat_table.advance_tcp_seq(id, 1);
                        to_tun_tx.send(packet).await?;
                        nat_table.set_tcp_state(&key, ConnectionState::CloseWait);
                    }
                    Some(ConnectionState::FinWait) => {
                        // App closed first, remote now confirms close — send FIN+ACK to app
                        let packet = build_tcp_packet(
                            key.2,
                            key.0,
                            key.3,
                            key.1,
                            nat_table.get_tcp_seq(id),
                            nat_table.get_tcp_ack(id),
                            TcpFlags {
                                fin: true,
                                ack: true,
                                ..Default::default()
                            },
                            65535,
                            &[],
                        );
                        nat_table.advance_tcp_seq(id, 1);
                        to_tun_tx.send(packet).await?;
                        nat_table.set_tcp_state(&key, ConnectionState::LastAck);
                    }
                    _ => {
                        // Already closing or unexpected state, just clean up
                        debug!(
                            "TcpClosed in unexpected state {:?}: id={}",
                            state, id
                        );
                        nat_table.close_tcp_connection(&key);
                    }
                }
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
                    TcpFlags {
                        rst: true,
                        ..Default::default()
                    },
                    0,
                    &[],
                );
                to_tun_tx.send(packet).await?;
                nat_table.close_tcp_connection(&key);
            }
        }
        RemoteMessage::UdpResponse {
            dst_port,
            src_ip,
            src_port,
            data,
        } => {
            debug!(
                "UDP response: src={}:{}, dst_port={}, len={}",
                src_ip,
                src_port,
                dst_port,
                data.len()
            );

            // Find the original source IP for this UDP "connection"
            if let Some(original_src_ip) = nat_table.get_udp_src_ip(dst_port, src_ip, src_port) {
                let packet = build_udp_packet(src_ip, original_src_ip, src_port, dst_port, &data);
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
