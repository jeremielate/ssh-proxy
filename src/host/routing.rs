use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use tracing::{debug, info};

#[cfg(target_os = "linux")]
use {
    futures::TryStreamExt,
    rtnetlink::{new_connection, Handle, IpVersion},
};

/// Add a route for a subnet through the TUN interface
#[cfg(target_os = "linux")]
pub async fn add_route(tun_name: &str, subnet: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let if_index = get_interface_index(&handle, tun_name).await?;
    debug!("Interface {} has index {}", tun_name, if_index);

    // Add the route
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(subnet, prefix)
        .output_interface(if_index)
        .execute()
        .await?;

    info!("Added route {}/{} via {} (ifindex {})", subnet, prefix, tun_name, if_index);

    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn remove_route(tun_name: &str, subnet: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let if_index = get_interface_index(&handle, tun_name).await?;

    // Find and delete the route
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = routes.try_next().await? {
        // Check if this is our route
        if let Some(dest) = route.destination_prefix() {
            if let (std::net::IpAddr::V4(dest_ip), dest_prefix) = dest {
                if dest_ip == subnet && dest_prefix == prefix {
                    // Check if it's using our interface
                    if route.output_interface() == Some(if_index) {
                        handle.route().del(route).execute().await?;
                        info!("Removed route {}/{} via {}", subnet, prefix, tun_name);
                        return Ok(());
                    }
                }
            }
        }
    }

    anyhow::bail!("Route {}/{} via {} not found", subnet, prefix, tun_name)
}

#[cfg(target_os = "linux")]
async fn get_interface_index(handle: &Handle, name: &str) -> anyhow::Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        anyhow::bail!("Interface {} not found", name)
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn add_route(_tun_name: &str, _subnet: Ipv4Addr, _prefix: u8) -> anyhow::Result<()> {
    anyhow::bail!(
        "Route management is only supported on Linux. Current platform: {}",
        std::env::consts::OS
    );
}

#[cfg(not(target_os = "linux"))]
pub async fn remove_route(_tun_name: &str, _subnet: Ipv4Addr, _prefix: u8) -> anyhow::Result<()> {
    anyhow::bail!(
        "Route management is only supported on Linux. Current platform: {}",
        std::env::consts::OS
    );
}
