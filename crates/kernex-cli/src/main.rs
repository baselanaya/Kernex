//! kernex — zero-trust kernel-level execution sandbox for AI agents.
//!
//! Entry point: parse CLI arguments and dispatch to the appropriate command.

use clap::Parser as _;
use tracing_subscriber::EnvFilter;

mod cli;
mod commands;
mod output;
mod policy_io;

use cli::{Cli, Commands, OutputFormat};
use output::Output;

#[tokio::main]
async fn main() {
    // Initialise structured logging from RUST_LOG (e.g. RUST_LOG=kernex=debug).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let json = cli.global.output_format == Some(OutputFormat::Json);
    let out = Output::new(json, cli.global.quiet);

    let result = match cli.command {
        Commands::Init(args) => commands::init::run(&out, &cli.global, args).await,
        Commands::Run(args) => commands::run::run(&out, &cli.global, args).await,
        Commands::Audit(args) => commands::audit::run(&out, &cli.global, args).await,
        Commands::Diff(args) => commands::diff::run(&out, &cli.global, args).await,
        Commands::Status(args) => commands::status::run(&out, &cli.global, args).await,
    };

    if let Err(e) = result {
        out.error(&e.to_string());
        std::process::exit(1);
    }
}
