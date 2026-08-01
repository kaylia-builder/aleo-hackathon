mod parser;
mod generator;
mod fuzzer;
mod invariants;
mod spec;
mod leo_runner;
mod leo_compiler;
mod web;
mod web_templates;

use clap::{Parser, Subcommand};
use colored::Colorize;
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

        /// Random seed for reproducible runs (0 = random)
        #[arg(short, long, default_value_t = 0)]
        seed: u64,

        /// Only fuzz this function (by name)
        #[arg(long)]
        function: Option<String>,

        /// Path to Leo source project (with program.json). Auto-compiles with leo build.
        /// Alternative to --file for .leo source projects.
        #[arg(long, verbatim_doc_comment)]
        source: Option<PathBuf>,

        /// Path to Leo project directory (with program.json) for real ZK proof verification
        /// When set, leo run is called for suspicious inputs to generate actual ZK proofs
        #[arg(long, verbatim_doc_comment)]
        project_dir: Option<PathBuf>,

        /// Verify ALL fuzz runs with leo run (very slow but exhaustive ZK verification)
        /// Default: only verify suspicious runs (symbolic failures + record-involving functions)
        #[arg(long, verbatim_doc_comment)]
        verify_all: bool,
    },
    /// Check invariants defined in a spec file
    Check {
        /// Path to the .aleo file
        #[arg(short, long)]
        file: PathBuf,

        /// Path to the invariant spec file
        #[arg(short = 'S', long)]
        spec: PathBuf,

        /// Number of fuzz iterations per function
        #[arg(short, long, default_value_t = 100)]
        runs: u32,

        /// Random seed for reproducible runs (0 = random)
        #[arg(short, long, default_value_t = 0)]
        seed: u64,

        /// Path to Leo source project (with program.json). Auto-compiles with leo build.
        /// Alternative to --file for .leo source projects.
        #[arg(long, verbatim_doc_comment)]
        source: Option<PathBuf>,

        /// Path to Leo project directory (with program.json) for real ZK proof verification
        /// When set, leo run is called for suspicious inputs to generate actual ZK proofs
        #[arg(long, verbatim_doc_comment)]
        project_dir: Option<PathBuf>,

        /// Verify ALL fuzz runs with leo run (very slow but exhaustive ZK verification)
        /// Default: only verify suspicious runs (symbolic failures + record-involving functions)
        #[arg(long, verbatim_doc_comment)]
        verify_all: bool,
    },
    /// Start the web dashboard (browser UI for fuzzing)
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value_t = 3000)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        Commands::Fuzz {
            file,
            runs,
            seed,
            function,
            source,
            project_dir,
            verify_all,
        } => {
            // If --source is set, auto-compile the Leo project
            let aleo_file = if let Some(ref src_dir) = source {
                leo_compiler::build_project(src_dir)
                    .map_err(|e| anyhow::anyhow!("{}", e))?
            } else {
                file.clone()
            };

            let content = std::fs::read_to_string(&aleo_file)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {}", aleo_file.display(), e))?;

            let contract = parser::parse(&content)?;

            // Determine seed
            let seed = if seed == 0 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(42)
            } else {
                seed
            };

            // Validate project_dir exists if specified
            if let Some(ref dir) = project_dir {
                if !dir.exists() {
                    anyhow::bail!("project directory '{}' does not exist", dir.display());
                }
                if !dir.join("program.json").exists() {
                    eprintln!(
                        "{} project directory '{}' does not contain program.json — ZK verification may fail",
                        "warning:".yellow(),
                        dir.display()
                    );
                }
            }

            let config = fuzzer::FuzzConfig {
                runs,
                seed,
                function_filter: function,
                include_edge_cases: true,
                spec: None,
                project_dir,
                verify_all_with_leo: verify_all,
                source_dir: source.clone(),
            };

            let runner = fuzzer::FuzzRunner::new(config, contract, content);
            let report = runner.run();
            print!("{}", report.pretty_print());
        }
        Commands::Check {
            file,
            spec,
            runs,
            seed,
            source,
            project_dir,
            verify_all,
        } => {
            // If --source is set, auto-compile the Leo project
            let aleo_file = if let Some(ref src_dir) = source {
                leo_compiler::build_project(src_dir)
                    .map_err(|e| anyhow::anyhow!("{}", e))?
            } else {
                file.clone()
            };

            let content = std::fs::read_to_string(&aleo_file)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {}", aleo_file.display(), e))?;

            let contract = parser::parse(&content)?;

            let spec_content = std::fs::read_to_string(&spec)
                .map_err(|e| anyhow::anyhow!("failed to read spec {}: {}", spec.display(), e))?;
            let invariant_spec = spec::parse_spec(&spec_content)
                .map_err(|e| anyhow::anyhow!("failed to parse spec: {}", e))?;

            // Print validation warnings to stderr
            let warnings = spec::validate_spec(&invariant_spec, &contract);
            for w in &warnings {
                eprintln!("{} {}", "warning:".yellow(), w);
            }

            if invariant_spec.contract.name != contract.program {
                eprintln!(
                    "{} spec is for '{}' but contract is '{}' — results may be misleading",
                    "warning:".yellow(),
                    invariant_spec.contract.name,
                    contract.program
                );
            }

            // Determine seed
            let seed = if seed == 0 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(42)
            } else {
                seed
            };

            // Validate project_dir exists if specified
            if let Some(ref dir) = project_dir {
                if !dir.exists() {
                    anyhow::bail!("project directory '{}' does not exist", dir.display());
                }
                if !dir.join("program.json").exists() {
                    eprintln!(
                        "{} project directory '{}' does not contain program.json — ZK verification may fail",
                        "warning:".yellow(),
                        dir.display()
                    );
                }
            }

            let config = fuzzer::FuzzConfig {
                runs,
                seed,
                function_filter: None,
                include_edge_cases: true,
                spec: Some(invariant_spec.clone()),
                project_dir,
                verify_all_with_leo: verify_all,
                source_dir: source.clone(),
            };

            let runner = fuzzer::FuzzRunner::new(config, contract, content);
            let report = runner.run();
            print!("{}", report.pretty_print_with_spec(&invariant_spec));
        }
        Commands::Serve { port } => {
            web::start_server(port).await?;
        }
    }
    Ok(())
}
