mod cli;
#[cfg(target_os = "linux")]
mod host;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod packet;
mod protocol;
mod remote;

use std::fs::OpenOptions;

use clap::Parser;
use cli::{Cli, Command};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if matches!(&cli.command, Command::Host(args) if args.verbose) {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env()
    };

    match cli.command {
        #[cfg(target_os = "linux")]
        Command::Host(args) => {
            tracing_subscriber::registry()
                .with(fmt::layer().with_line_number(true))
                .with(filter)
                .init();

            host::run(args).await
        }
        #[cfg(not(target_os = "linux"))]
        Command::Host(_) => {
            anyhow::bail!("host mode is only supported on Linux (requires TUN device)")
        }
        Command::Remote => {
            // Log to stderr only in remote mode
            if let Some(mut cache_home) = xdg::BaseDirectories::new().get_cache_home() {
                cache_home.push("ssh-proxy.log");
                let log_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(cache_home)?;
                tracing_subscriber::registry()
                    .with(fmt::layer().with_writer(log_file).with_line_number(true))
                    .with(filter)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(
                        fmt::layer()
                            .with_writer(std::io::stderr)
                            .with_line_number(true),
                    )
                    .with(filter)
                    .init();
            };
            remote::run().await
        }
    }
}
