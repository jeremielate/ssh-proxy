mod cli;
mod host;
mod packet;
mod protocol;
mod remote;

use std::fs::{File, OpenOptions};

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
        EnvFilter::from_default_env().add_directive("ssh_proxy=debug".parse()?)
    };

    // For remote mode, we must not log to stdout as it's used for protocol
    match &cli.command {
        Command::Host(_) => {
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(filter)
                .init();
        }
        Command::Remote => {
            // Log to stderr only in remote mode
            if let Some(mut cache_home) = xdg::BaseDirectories::new().get_cache_home() {
                cache_home.push("ssh-proxy.log");
                let log_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .write(true)
                    .open(cache_home)?;
                tracing_subscriber::registry()
                    .with(fmt::layer().with_writer(log_file))
                    .with(filter)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(fmt::layer().with_writer(std::io::stderr))
                    .with(filter)
                    .init();
            };
        }
    }

    match cli.command {
        Command::Host(args) => host::run(args).await,
        Command::Remote => remote::run().await,
    }
}
