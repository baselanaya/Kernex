use clap::{Args, Parser, Subcommand};

/// kernex — zero-trust sandbox for AI agents.
#[derive(Debug, Parser)]
#[command(
    name = "kernex",
    version,
    about = "Zero-trust kernel-level execution sandbox for AI agents",
    long_about = None,
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

/// Flags shared across all subcommands.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Output results as JSON (suitable for CI and tooling).
    #[arg(long = "output", value_name = "FORMAT")]
    pub output_format: Option<OutputFormat>,

    /// Abort if any enforcement layer cannot be fully applied.
    #[arg(long)]
    pub strict: bool,

    /// Path to the kernex.yaml policy file.
    #[arg(long, value_name = "PATH", default_value = "kernex.yaml")]
    pub config: String,

    /// Suppress informational output; show warnings and errors only.
    #[arg(long)]
    pub quiet: bool,

    /// Co-sandbox MCP servers declared in kernex.yaml.
    #[arg(long)]
    pub mcp: bool,
}

/// Output format selector for `--output`.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate a starter kernex.yaml via an interactive wizard.
    Init(InitArgs),

    /// Run an agent under full sandbox enforcement.
    Run(RunArgs),

    /// Run an agent in observation mode and generate/update kernex.yaml.
    Audit(AuditArgs),

    /// Compare two kernex.yaml files or two audit sessions.
    Diff(DiffArgs),

    /// Show a human-readable summary of the active policy and its score.
    Status(StatusArgs),
}

/// Arguments for `kernex init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Accept all defaults without prompting.
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for `kernex run -- <cmd>`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The command and arguments to run inside the sandbox.
    #[arg(trailing_var_arg = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,

    /// Require explicit confirmation when scope-expansion JIT prompts appear.
    #[arg(long)]
    pub accept_expansions: bool,
}

/// Arguments for `kernex audit -- <cmd>`.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// The command and arguments to run in observation mode.
    #[arg(trailing_var_arg = true, required = true, value_name = "CMD")]
    pub command: Vec<String>,

    /// Apply the generated policy even when scope expansions are present.
    #[arg(long)]
    pub accept_expansions: bool,

    /// Include sensitive paths in the generated policy without prompting.
    #[arg(long)]
    pub allow_sensitive: bool,
}

/// Arguments for `kernex diff`.
#[derive(Debug, Args)]
pub struct DiffArgs {
    /// First policy file (old). Defaults to the active kernex.yaml.
    #[arg(value_name = "OLD")]
    pub old: Option<String>,

    /// Second policy file (new).
    #[arg(value_name = "NEW")]
    pub new: Option<String>,
}

/// Arguments for `kernex status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    // config path comes from GlobalArgs
}
