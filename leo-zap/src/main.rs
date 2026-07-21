mod parser;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// LeoZap - Property-based fuzzer + privacy invariant checker for Aleo Leo contracts
#[derive(Parser, Debug)]
#[command(name = "leo-zap")]
#[command(version = "0.1.0")]
#[command(about = "Fuzz Leo contracts and verify privacy invariants", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse a compiled .aleo file and print its structure
    Parse {
        /// Path to the .aleo file (e.g. build/token/token.aleo)
        #[arg(short, long)]
        file: PathBuf,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Run the fuzzer on a contract
    Fuzz {
        /// Path to the .aleo file
        #[arg(short, long)]
        file: PathBuf,

        /// Number of fuzz iterations
        #[arg(short, long, default_value_t = 1000)]
        runs: u32,
    },
    /// Check invariants defined in a spec file
    Check {
        /// Path to the .aleo file
        #[arg(short, long)]
        file: PathBuf,

        /// Path to the invariant spec file
        #[arg(short, long)]
        spec: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { file, json } => {
            let content = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {}", file.display(), e))?;

            let contract = parser::parse(&content)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&contract)?);
            } else {
                print!("{}", contract.pretty_print());
            }
        }
        Commands::Fuzz { file, runs } => {
            println!("⚡ Fuzzing {} ({} runs)", file.display(), runs);
            println!("(fuzzer not implemented yet — W2 task)");
        }
        Commands::Check { file, spec } => {
            println!(
                "✅ Checking invariants for {} with spec {}",
                file.display(),
                spec.display()
            );
            println!("(invariant checker not implemented yet — W3 task)");
        }
    }
    Ok(())
}