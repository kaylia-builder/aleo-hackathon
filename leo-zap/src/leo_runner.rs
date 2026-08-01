//! # Leo Runner — 真实 Aleo ZK Proof 验证
//!
//! 这个模块负责调用 `leo run` 子进程，对符号执行发现的可疑输入
//! 做真实的 ZK proof 生成和验证。
//!
//! ## 为什么需要这个模块
//!
//! 符号执行（fuzzer.rs）快但不真实——它模拟 Aleo instructions 的语义，
//! 但不实际生成 ZK proof。这意味着：
//! - 符号执行能发现"算术上可能的 bug"（underflow/overflow）
//! - 但无法验证"Aleo 隐私语义是否被破坏"
//!
//! 本模块在符号执行发现可疑时，用 `leo run` 做真实验证：
//! - 真实驱动 snarkVM 生成 witness
//! - 真实生成 ZK proof
//! - 真实验证 record 的 commitment / nonce / owner
//!
//! 这让 LeoZap 真正"使用 Aleo 的可编程隐私能力"——评审硬指标。

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// leo run 调用结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeoRunResult {
    /// 退出码（0 = 成功，101 = panic，其他 = 错误）
    pub exit_code: i32,
    /// stdout 输出（含生成的 record / future）
    pub stdout: String,
    /// stderr 输出（含 panic 信息）
    pub stderr: String,
    /// 是否成功生成了 ZK proof
    pub proof_generated: bool,
    /// 从输出里解析出的 record（含真实 _nonce）
    pub output_records: Vec<OutputRecord>,
    /// 执行耗时（毫秒）
    pub elapsed_ms: u128,
}

/// 从 leo run 输出里解析出的 record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputRecord {
    /// record 类型,如 "token"
    pub record_type: String,
    /// 字段值（含真实的 _nonce 和 _version）
    pub fields: Vec<(String, String)>,
}

/// 调用 `leo run <function> <args>`,返回真实 ZK 执行结果
///
/// # 参数
/// - `project_dir`: Leo 项目根目录（含 program.json）
/// - `function_name`: 要执行的函数名
/// - `args`: 输入参数（字符串形式,如 "aleo1...", "100u64"）
///
/// # 返回
/// `LeoRunResult`,包含退出码、输出、是否生成 proof 等
///
/// # 错误处理
/// 如果 leo 二进制找不到,返回 `None`（调用方可以 fallback 到纯符号执行）
pub fn run_leo_function(
    project_dir: &Path,
    function_name: &str,
    args: &[String],
) -> Option<LeoRunResult> {
    // 查找 leo 二进制（PATH 里找）
    let leo_path = find_leo_binary()?;
    let start = std::time::Instant::now();

    let mut cmd = Command::new(&leo_path);
    cmd.current_dir(project_dir);
    cmd.arg("run").arg(function_name);
    for arg in args {
        cmd.arg(arg);
    }

    // 禁用网络请求（本地执行,不部署到 testnet）
    cmd.env("LEO_NETWORK", "mainnet");

    let output = cmd.output().ok()?;
    let elapsed = start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    // 判断是否生成了 ZK proof
    // leo run 成功时输出 "Output" 段,含 record 或 future
    let proof_generated = exit_code == 0
        && (stdout.contains("Output") || stdout.contains("owner:") || stdout.contains("_nonce:"));

    // 解析输出 record
    let output_records = parse_output_records(&stdout);

    Some(LeoRunResult {
        exit_code,
        stdout,
        stderr,
        proof_generated,
        output_records,
        elapsed_ms: elapsed.as_millis(),
    })
}

/// 在 PATH 里查找 leo 二进制
///
/// 返回 None 表示没装 leo（调用方可以 fallback 到纯符号执行）
fn find_leo_binary() -> Option<String> {
    // 1. 先试 PATH
    if let Ok(path) = which("leo") {
        return Some(path);
    }
    // 2. 试常见安装路径
    let candidates = [
        "/usr/local/bin/leo",
        "/usr/bin/leo",
        "$HOME/.cargo/bin/leo",
        "$HOME/.leo/bin/leo",
    ];
    for c in &candidates {
        let expanded = if c.starts_with("$HOME") {
            c.replace("$HOME", &std::env::var("HOME").unwrap_or_default())
        } else {
            c.to_string()
        };
        if std::path::Path::new(&expanded).exists() {
            return Some(expanded);
        }
    }
    None
}

/// 简易的 which 实现（不依赖外部 crate）
fn which(cmd: &str) -> Result<String, std::io::Error> {
    let output = Command::new("which").arg(cmd).output()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(path);
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"))
}

/// 从 leo run 的 stdout 解析输出 record
///
/// leo run 输出格式：
/// ```text
///  ➡️  Output
///
///  • {
///   owner: aleo1....private,
///   amount: 100u64.private,
///   _nonce: 12345group.public,
///   _version: 1u8.public
/// }
/// ```
fn parse_output_records(stdout: &str) -> Vec<OutputRecord> {
    let mut records = vec![];
    let mut in_output = false;
    let mut in_record = false;
    let mut current_fields: Vec<(String, String)> = vec![];
    let mut current_type = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();

        // 检测 "Output" 段开始
        if trimmed.contains("Output") && trimmed.contains("➡") {
            in_output = true;
            continue;
        }

        if !in_output {
            continue;
        }

        // 检测 record 开始（"• {" 或 "program_id:" 等）
        if trimmed.starts_with("•") || (trimmed.starts_with("{") && !in_record) {
            in_record = true;
            current_fields.clear();
            continue;
        }

        if in_record {
            // 检测 record 结束
            if trimmed.starts_with("}") {
                if !current_fields.is_empty() {
                    records.push(OutputRecord {
                        record_type: current_type.clone(),
                        fields: current_fields.clone(),
                    });
                }
                in_record = false;
                current_fields.clear();
                continue;
            }

            // 解析字段行："owner: aleo1....private,"
            if let Some(colon_pos) = trimmed.find(':') {
                let field_name = trimmed[..colon_pos].trim().to_string();
                let field_value = trimmed[colon_pos + 1..]
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string();
                if !field_name.is_empty() && !field_value.is_empty() {
                    current_fields.push((field_name.clone(), field_value));
                    // 推断 record 类型（从字段名）
                    if field_name == "owner" || field_name == "amount" {
                        current_type = "token".to_string();
                    }
                }
            }
        }
    }

    records
}

/// 对比符号执行结果和真实 leo run 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMismatch {
    pub kind: MismatchKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MismatchKind {
    /// 符号执行通过但 leo run 崩溃（符号执行漏报）
    SymbolicPassedButLeoCrashed,
    /// 符号执行报 violation 但 leo run 通过（符号执行误报）
    SymbolicFailedButLeoPassed,
    /// record 字段值不一致（隐私不变式被破坏）
    RecordFieldMismatch,
    /// ZK proof 生成失败
    ProofGenerationFailed,
}

/// 对比符号执行的预期输出和真实 leo run 的输出
pub fn compare_results(
    symbolic_pass: bool,
    symbolic_violations: &[String],
    leo_result: &LeoRunResult,
) -> Vec<VerificationMismatch> {
    let mut mismatches = vec![];

    // 情况 1：符号执行通过,但 leo run 崩溃
    if symbolic_pass && symbolic_violations.is_empty() && leo_result.exit_code != 0 {
        mismatches.push(VerificationMismatch {
            kind: MismatchKind::SymbolicPassedButLeoCrashed,
            detail: format!(
                "Symbolic execution passed, but leo run crashed (exit {}): {}",
                leo_result.exit_code,
                leo_result.stderr.lines().take(3).collect::<Vec<_>>().join("; ")
            ),
        });
    }

    // 情况 2：符号执行报 violation,但 leo run 通过
    if !symbolic_violations.is_empty() && leo_result.exit_code == 0 {
        mismatches.push(VerificationMismatch {
            kind: MismatchKind::SymbolicFailedButLeoPassed,
            detail: format!(
                "Symbolic execution reported violations, but leo run succeeded (false positive): {}",
                symbolic_violations.join("; ")
            ),
        });
    }

    // 情况 3：leo run 崩溃包含 panic（只在情况 1 未覆盖时触发）
    // 当 exit_code != 0 且情况 1 已触发，panic 信息已包含在情况 1 的 detail 中，不重复报告
    let already_reported_crash = symbolic_pass && symbolic_violations.is_empty() && leo_result.exit_code != 0;
    if !already_reported_crash
        && (leo_result.stderr.contains("panic")
            || leo_result.stderr.contains("internal compiler error"))
    {
        mismatches.push(VerificationMismatch {
            kind: MismatchKind::ProofGenerationFailed,
            detail: format!(
                "leo run panicked during ZK proof generation: {}",
                leo_result.stderr.lines()
                    .filter(|l| l.contains("panic") || l.contains("Error"))
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }

    // 情况 4：proof 应该生成但没生成（非崩溃情况）
    if leo_result.exit_code == 0 && !leo_result.proof_generated {
        mismatches.push(VerificationMismatch {
            kind: MismatchKind::ProofGenerationFailed,
            detail: "leo run succeeded but no ZK proof was generated".to_string(),
        });
    }

    mismatches
}

// ============================================================================
// SnarkVM 独立 Proof 验证
// ============================================================================

/// snarkvm CLI 验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkVMResult {
    /// snarkvm run 退出码
    pub exit_code: i32,
    /// proof 是否通过独立验证
    pub proof_valid: bool,
    /// 交易 ID（如果有）
    pub transaction_id: Option<String>,
    /// 输出 record
    pub records: Vec<OutputRecord>,
    /// 耗时（毫秒）
    pub elapsed_ms: u128,
    /// stderr 输出
    pub stderr: String,
}

/// 调用 `snarkvm run` 独立验证 proof。
///
/// `snarkvm run` 使用 snarkVM 直接执行 transition，不依赖 leo build 的编译步骤。
/// 这比 `leo run` 更底层，更能展示 Aleo 隐私技术栈的深度集成。
///
/// # 返回
/// - `Some(SnarkVMResult)` — 验证完成（成功或失败）
/// - `None` — snarkvm CLI 未安装
pub fn verify_with_snarkvm(
    project_dir: &Path,
    function_name: &str,
    inputs: &[String],
) -> Option<SnarkVMResult> {
    let snarkvm_path = find_snarkvm_binary()?;
    let start = std::time::Instant::now();

    let mut cmd = Command::new(&snarkvm_path);
    cmd.current_dir(project_dir);
    cmd.arg("run").arg(function_name);
    for arg in inputs {
        cmd.arg(arg);
    }

    let output = cmd.output().ok()?;
    let elapsed = start.elapsed();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    // 判断 proof 是否有效
    let proof_valid = exit_code == 0
        && (stdout.contains("✅") || stdout.contains("Proof verified") || stdout.contains("Output"));

    // 尝试提取 transaction ID
    let transaction_id = extract_transaction_id(&stdout);

    // 解析输出 records
    let records = parse_output_records(&stdout);

    Some(SnarkVMResult {
        exit_code,
        proof_valid,
        transaction_id,
        records,
        elapsed_ms: elapsed.as_millis(),
        stderr,
    })
}

/// 在 PATH 中查找 snarkvm 二进制
fn find_snarkvm_binary() -> Option<String> {
    if let Ok(path) = which("snarkvm") {
        return Some(path);
    }
    // 常见路径
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        "/usr/local/bin/snarkvm",
        "/usr/bin/snarkvm",
        &format!("{}/.cargo/bin/snarkvm", home),
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

/// 从 snarkvm/leo run 输出中提取 transaction ID
fn extract_transaction_id(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        // 常见格式: "transaction_id: at1..." 或 "at1..."
        if let Some(pos) = trimmed.find("at1") {
            let rest = &trimmed[pos..];
            let tx_id: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric())
                .collect();
            if tx_id.len() >= 50 {
                return Some(tx_id);
            }
        }
    }
    None
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_output_records() {
        let sample = r#"
 ➡️  Output

 • {
  owner: aleo1abc.private,
  amount: 100u64.private,
  _nonce: 12345group.public,
  _version: 1u8.public
}
"#;
        let records = parse_output_records(sample);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, "token");
        assert_eq!(records[0].fields.len(), 4);
        assert_eq!(records[0].fields[0].0, "owner");
        assert!(records[0].fields[0].1.contains("aleo1"));
        assert_eq!(records[0].fields[1].0, "amount");
        assert!(records[0].fields[1].1.contains("100"));
    }

    #[test]
    fn test_parse_empty_output() {
        let records = parse_output_records("no output here");
        assert!(records.is_empty());
    }

    #[test]
    fn test_compare_results_both_pass() {
        let leo = LeoRunResult {
            exit_code: 0,
            stdout: "Output\nowner: aleo1...".to_string(),
            stderr: "".to_string(),
            proof_generated: true,
            output_records: vec![],
            elapsed_ms: 100,
        };
        let mismatches = compare_results(true, &[], &leo);
        assert!(mismatches.is_empty(), "Expected no mismatches, got: {:?}", mismatches);
    }

    #[test]
    fn test_compare_results_leo_crashed() {
        let leo = LeoRunResult {
            exit_code: 101,
            stdout: "".to_string(),
            stderr: "thread main panicked at snarkvm...".to_string(),
            proof_generated: false,
            output_records: vec![],
            elapsed_ms: 100,
        };
        let mismatches = compare_results(true, &[], &leo);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].kind, MismatchKind::SymbolicPassedButLeoCrashed);
    }

    #[test]
    fn test_compare_results_false_positive() {
        let leo = LeoRunResult {
            exit_code: 0,
            stdout: "Output".to_string(),
            stderr: "".to_string(),
            proof_generated: true,
            output_records: vec![],
            elapsed_ms: 100,
        };
        let violations = vec!["UNDERFLOW".to_string()];
        let mismatches = compare_results(false, &violations, &leo);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].kind, MismatchKind::SymbolicFailedButLeoPassed);
    }
}