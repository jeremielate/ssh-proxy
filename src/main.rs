mod cli;
mod host;
mod packet;
mod protocol;
mod remote;

use clap::Parser;
use cli::{Cli, Command};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if matches!(&cli.command, Command::Host(args) if args.verbose) {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env().add_directive("ssh_proxy=info".parse()?)
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
            tracing_subscriber::registry()
                .with(fmt::layer().with_writer(std::io::stderr))
                .with(filter)
                .init();
        }
    }

    match cli.command {
        Command::Host(args) => host::run(args).await,
        Command::Remote => remote::run().await,
    }
}
