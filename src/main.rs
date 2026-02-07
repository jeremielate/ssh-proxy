mod cli;
mod host;
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
        Command::Host(args) => {
            tracing_subscriber::registry()
                .with(fmt::layer().with_line_number(true))
                .with(filter)
                .init();

            host::run(args).await
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
