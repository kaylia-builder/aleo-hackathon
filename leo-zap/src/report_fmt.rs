//! Pretty-print formatting for core types using `colored`.
//! These methods are kept in the binary crate because `colored` is not
//! compatible with WASM and is only used for terminal output.

use colored::*;
use leo_zap_core::fuzzer::{FuzzReport, FuzzOutcome, FuzzResult};
use leo_zap_core::spec::InvariantSpec;

/// Extension trait to add pretty_print methods to FuzzReport
pub trait FuzzReportExt {
    fn pretty_print(&self) -> String;
    fn pretty_print_with_spec(&self, spec: &InvariantSpec) -> String;
}

impl FuzzReportExt for FuzzReport {
    fn pretty_print(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{} (seed: {}, runs: {})\n\n",
            "⚡ Fuzz Report".bold().bright_yellow(),
            self.config.seed.to_string().cyan(),
            self.total_runs.to_string().cyan()
        ));

        // Per-function breakdown
        for (func_name, runs, passed, violations) in &self.per_function {
            let status = if *violations == 0 {
                "✅".green()
            } else {
                "⚠️ ".yellow()
            };

            let pass_pct = if *runs > 0 {
                (*passed as f64 / *runs as f64) * 100.0
            } else {
                100.0
            };

            out.push_str(&format!(
                "  {} {}: {}/{} passed ({:.0}%)",
                status,
                func_name.magenta(),
                passed,
                runs,
                pass_pct
            ));

            if *violations > 0 {
                out.push_str(&format!(" — {} {}", violations, "violations".red()));
            }

            out.push('\n');
        }

        // Violation details
        if !self.violation_results.is_empty() {
            out.push_str(&format!("\n{}\n", "Violations:".red().bold()));

            let mut underflows = Vec::new();
            let mut overflows = Vec::new();
            let mut others = Vec::new();

            for result in &self.violation_results {
                if let FuzzOutcome::Violation { detail, .. } = &result.outcome {
                    if detail.contains("UNDERFLOW") {
                        underflows.push((result, detail));
                    } else if detail.contains("OVERFLOW") {
                        overflows.push((result, detail));
                    } else {
                        others.push((result, detail));
                    }
                }
            }

            let all_violations: Vec<&(&FuzzResult, &String)> = underflows
                .iter()
                .chain(overflows.iter())
                .chain(others.iter())
                .take(5)
                .collect();

            for (result, detail) in &all_violations {
                out.push_str(&format!(
                    "  {} {}: {}\n",
                    "▸".red(),
                    result.function.magenta(),
                    detail
                ));
                out.push_str(&format!(
                    "    inputs: {}\n",
                    result.input_strings.join(", ").dimmed()
                ));
            }

            if all_violations.len() < self.violation_results.len() {
                out.push_str(&format!(
                    "  ... and {} more violations\n",
                    self.violation_results.len() - all_violations.len()
                ));
            }
        }

        // Summary
        out.push_str(&format!("\n{}\n", "Summary:".bold()));
        out.push_str(&format!("  Total runs: {}\n", self.total_runs));
        out.push_str(&format!("  {} Passed\n", format!("{}", self.passed).green()));
        out.push_str(&format!(
            "  {} Violations\n",
            format!("{}", self.violations).red()
        ));
        let cov_str = format!("{:.0}%", self.coverage_pct);
        out.push_str(&format!(
            "  Instruction coverage: {}\n",
            cov_str.cyan()
        ));
        if self.errors > 0 {
            out.push_str(&format!(
                "  {} Errors\n",
                format!("{}", self.errors).red()
            ));
        }

        // ZK verification stats
        if self.zk_verifications > 0 {
            out.push_str(&format!("\n{}\n", "Privacy Capability Used:".bold().bright_cyan()));
            out.push_str(&format!(
                "  {} ZK proof verifications via leo run\n",
                self.zk_verifications.to_string().cyan()
            ));
            out.push_str(&format!(
                "  {} ZK proofs generated successfully\n",
                self.zk_proofs_generated.to_string().green()
            ));
            out.push_str(&format!(
                "  {} Mismatches (symbolic vs ZK) — true bugs\n",
                self.zk_mismatches.to_string().red()
            ));
        }

        out
    }

    fn pretty_print_with_spec(&self, spec: &InvariantSpec) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "{} {}\n\n",
            "Invariant Check Report".bold().bright_yellow(),
            format!("(spec: {})", spec.contract.name).cyan()
        ));

        out.push_str(&format!(
            "{} {} runs (seed: {})\n\n",
            "Ran".bold(),
            self.total_runs.to_string().cyan(),
            self.config.seed.to_string().cyan()
        ));

        for (func_name, runs, passed, violations) in &self.per_function {
            let status = if *violations == 0 {
                "PASS".green()
            } else {
                "FAIL".red()
            };
            let toggle = spec.invariants.resolve(func_name);

            let mut active: Vec<&str> = Vec::new();
            if toggle.is_enabled("balance_conservation") {
                active.push("balance");
            }
            if toggle.is_enabled("owner_integrity") {
                active.push("owner");
            }
            if toggle.is_enabled("zero_amount") {
                active.push("zero-amt");
            }
            if toggle.is_enabled("overflow_check") {
                active.push("overflow");
            }
            if toggle.is_enabled("self_transfer") {
                active.push("self-xfer");
            }

            let pass_pct = if *runs > 0 {
                (*passed as f64 / *runs as f64) * 100.0
            } else {
                100.0
            };

            out.push_str(&format!(
                "  {} {}: {}/{} ({:.0}%)  invariants: [{}]\n",
                status,
                func_name.magenta(),
                passed,
                runs,
                pass_pct,
                active.join(", ").dimmed()
            ));
        }

        if !spec.assertions.is_empty() {
            out.push_str(&format!(
                "\n{} ({} defined)\n",
                "Custom Assertions:".bold(),
                spec.assertions.len().to_string().cyan()
            ));
            for a in &spec.assertions {
                let type_str = format!("{:?}", a.assertion_type).to_lowercase();
                out.push_str(&format!(
                    "  {} [{}] {} — {}\n",
                    "▸".dimmed(),
                    type_str.dimmed(),
                    a.function.magenta(),
                    a.description
                ));
            }
        }

        if !self.violation_results.is_empty() {
            out.push_str(&format!("\n{}\n", "Violations:".red().bold()));
            for result in self.violation_results.iter().take(10) {
                if let FuzzOutcome::Violation { invariant, detail } = &result.outcome {
                    out.push_str(&format!(
                        "  {} [{}] {}: {}\n",
                        "▸".red(),
                        invariant.yellow(),
                        result.function.magenta(),
                        detail
                    ));
                }
            }
            if self.violation_results.len() > 10 {
                out.push_str(&format!(
                    "  ... and {} more violations\n",
                    self.violation_results.len() - 10
                ));
            }
        }

        out.push_str(&format!(
            "\n{} {} passed, {} violations\n",
            "Result:".bold(),
            format!("{}", self.passed).green(),
            format!("{}", self.violations).red()
        ));

        // ZK verification stats
        if self.zk_verifications > 0 {
            out.push_str(&format!("\n{}\n", "Privacy Capability Used:".bold().bright_cyan()));
            out.push_str(&format!(
                "  {} ZK proof verifications via leo run\n",
                self.zk_verifications.to_string().cyan()
            ));
            out.push_str(&format!(
                "  {} ZK proofs generated successfully\n",
                self.zk_proofs_generated.to_string().green()
            ));
            out.push_str(&format!(
                "  {} Mismatches (symbolic vs ZK) — true bugs\n",
                self.zk_mismatches.to_string().red()
            ));
        }

        out
    }
}

/// Extension trait to add pretty_print method to Contract
pub trait ContractExt {
    fn pretty_print(&self) -> String;
}

impl ContractExt for leo_zap_core::parser::Contract {
    fn pretty_print(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{} {}\n", "📊 Contract:".bold(), self.program.cyan()));

        if !self.records.is_empty() {
            out.push_str(&format!("\n{}\n", "Records:".yellow().bold()));
            for r in &self.records {
                let fields: Vec<String> = r
                    .fields
                    .iter()
                    .map(|f| format!("{}: {}", f.name, format_type_vis(&f.ty, f.visibility)))
                    .collect();
                out.push_str(&format!("  {} ({})\n", r.name.green(), fields.join(", ")));
            }
        }

        if !self.mappings.is_empty() {
            out.push_str(&format!("\n{}\n", "Mappings:".yellow().bold()));
            for m in &self.mappings {
                out.push_str(&format!(
                    "  {} (key: {}, value: {})\n",
                    m.name.green(),
                    m.key_type,
                    m.value_type
                ));
            }
        }

        if !self.functions.is_empty() {
            out.push_str(&format!("\n{}\n", "Functions:".yellow().bold()));
            for f in &self.functions {
                let ins: Vec<String> = f
                    .inputs
                    .iter()
                    .map(|p| format_type_vis(&p.ty, p.visibility))
                    .collect();
                let outs: Vec<String> = f
                    .outputs
                    .iter()
                    .map(|p| format_type_vis(&p.ty, p.visibility))
                    .collect();
                out.push_str(&format!(
                    "  {}({}) → {}\n",
                    f.name.magenta(),
                    ins.join(", "),
                    if outs.is_empty() {
                        "()".to_string()
                    } else {
                        outs.join(", ")
                    }
                ));
            }
        }

        if !self.finalizes.is_empty() {
            out.push_str(&format!("\n{}\n", "Finalizes:".yellow().bold()));
            for f in &self.finalizes {
                let ins: Vec<String> = f.inputs.iter().map(|p| p.ty.clone()).collect();
                out.push_str(&format!("  {}({})\n", f.name.magenta(), ins.join(", ")));
            }
        }

        out
    }
}

fn format_type_vis(ty: &str, vis: leo_zap_core::parser::Visibility) -> String {
    match vis {
        leo_zap_core::parser::Visibility::Public => format!("{}.public", ty),
        leo_zap_core::parser::Visibility::Private => format!("{}.private", ty),
        leo_zap_core::parser::Visibility::Constant => format!("{}.constant", ty),
        leo_zap_core::parser::Visibility::None => ty.to_string(),
    }
}
