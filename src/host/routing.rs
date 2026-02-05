use std::net::Ipv4Addr;

use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::RouteMessageBuilder;
use tracing::{debug, info};

use {
    futures::TryStreamExt,
    rtnetlink::{Handle, new_connection},
};

/// Add a route for a subnet through the TUN interface
pub async fn add_route(tun_name: &str, subnet: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let if_index = get_interface_index(&handle, tun_name).await?;
    debug!("Interface {} has index {}", tun_name, if_index);

    let route_message = RouteMessageBuilder::<Ipv4Addr>::new()
        .source_prefix(subnet, prefix)
        .destination_prefix(subnet, prefix)
        .output_interface(if_index)
        .build();

    // Add the route
    handle.route().add(route_message).execute().await?;

    info!(
        "Added route {}/{} via {} (ifindex {})",
        subnet, prefix, tun_name, if_index
    );

    Ok(())
}

fn get_destination_and_interface_attributes(msg: &RouteMessage) -> Option<(&RouteAddress, u32)> {
    let mut r_addr: Option<&RouteAddress> = None;
    let mut i_if: Option<u32> = None;
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Iif(i) => {
                i_if = Some(*i);
            }
            RouteAttribute::Destination(r) => {
                r_addr = Some(r);
            }
            _ => {}
        }
    }
    match (r_addr, i_if) {
        (Some(r), Some(i)) => Some((r, i)),
        _ => None,
    }
}

pub async fn remove_route(tun_name: &str, subnet: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let if_index = get_interface_index(&handle, tun_name).await?;

    let route_message = RouteMessageBuilder::<Ipv4Addr>::new().build();

    // Find and delete the route
    let mut routes = handle.route().get(route_message).execute();

    while let Some(route) = routes.try_next().await? {
        // Check if this is our route
        if let Some((dest, test_if_index)) = get_destination_and_interface_attributes(&route)
            && let RouteAddress::Inet(dest_ip) = dest
                && *dest_ip == subnet
                    && route.header.destination_prefix_length == prefix
                    && test_if_index == if_index
                {
                    handle.route().del(route).execute().await?;
                    info!("Removed route {}/{} via {}", subnet, prefix, tun_name);
                    return Ok(());
                }
    }

    anyhow::bail!("Route {}/{} via {} not found", subnet, prefix, tun_name)
}

async fn get_interface_index(handle: &Handle, name: &str) -> anyhow::Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        anyhow::bail!("Interface {} not found", name)
    }
}
