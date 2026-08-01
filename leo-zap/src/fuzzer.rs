//! # Fuzzer Engine
//!
//! Core fuzzing engine for Aleo `.aleo` contracts.
//!
//! ## Architecture
//!
//! 1. **Instruction Parser**: extracts instructions from function bodies in `.aleo` files
//! 2. **Symbolic Executor**: tracks register values through instruction sequences
//! 3. **Violation Detector**: checks for underflows, balance mismatches, and other bugs
//! 4. **FuzzRunner**: orchestrates input generation + symbolic execution across N iterations
//! 5. **ZK Verifier**: 对涉及 record 隐私操作的路径调用 leo run 真实生成 ZK proof
//!
//! ## Instruction Support
//!
//! Supported operations: `add`, `sub`, `cast`, `gt`, `get.or_use`, `set`,
//! `async`, `assert.eq`, `assert.neq`, `output`.
//! Field access (e.g. `r0.amount`) and `self.caller` are handled.

use crate::generator::{InputGenerator, SymValue};
use crate::invariants;
use crate::parser::{Contract, FunctionDef};
use crate::spec::InvariantSpec;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ZK 验证统计（fuzz_function 内部用）
#[derive(Default)]
struct ZkStats {
    verifications: u32,
    proofs_generated: u32,
    mismatches: u32,
    mismatch_details: Vec<crate::leo_runner::VerificationMismatch>,
}

// ============================================================================
// Instruction Types
// ============================================================================

/// Parsed .aleo instruction from a function body
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Instruction {
    /// `add rA rB into rC` — rC = rA + rB
    Add {
        lhs: Operand,
        rhs: Operand,
        dest: String,
    },
    /// `sub rA rB into rC` — rC = rA - rB
    Sub {
        lhs: Operand,
        rhs: Operand,
        dest: String,
    },
    /// `cast rA rB ... into rC as type` — create a record or struct
    Cast {
        fields: Vec<Operand>,
        dest: String,
        as_type: String,
    },
    /// `gt rA rB into rC` — rC = (rA > rB)
    Gt {
        lhs: Operand,
        rhs: Operand,
        dest: String,
    },
    /// `get.or_use mapping[key] default into rC`
    GetOrUse {
        mapping: String,
        key: String,
        default: String,
        dest: String,
    },
    /// `set rA into mapping[key]`
    Set {
        value: String,
        mapping: String,
        key: String,
    },
    /// `async func args... into rC`
    Async {
        func: String,
        args: Vec<String>,
        dest: String,
    },
    /// `assert.eq rA rB`
    AssertEq {
        lhs: Operand,
        rhs: Operand,
    },
    /// `assert.neq rA rB`
    AssertNeq {
        lhs: Operand,
        rhs: Operand,
    },
    /// `output rA as type` — marks a function output
    Output {
        src: String,
        ty: String,
    },
    /// Unknown or unsupported instruction (passed through silently)
    Unknown(String),
}

/// An operand in an instruction
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Operand {
    /// A register: `r0`, `r1`, etc.
    Register(String),
    /// A field access on a register: `r0.amount`, `r0.owner`
    FieldAccess {
        register: String,
        field: String,
    },
    /// A literal value: `0u64`, `100u64`
    Literal(String),
    /// `self.caller` — the transaction caller's address
    SelfCaller,
}

// ============================================================================
// Fuzzing Types
// ============================================================================

/// Configuration for a fuzzing run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    /// Number of random input sets per function
    pub runs: u32,
    /// Random seed for reproducibility
    pub seed: u64,
    /// If set, only fuzz this function (by name)
    pub function_filter: Option<String>,
    /// Include edge cases in input generation
    pub include_edge_cases: bool,
    /// Optional invariant spec for targeted checking
    pub spec: Option<InvariantSpec>,
    /// Leo 项目根目录（含 program.json），用于 leo run 真实验证
    /// None = 不做 ZK 验证（纯符号执行模式）
    pub project_dir: Option<std::path::PathBuf>,
    /// 是否对每个 run 都做 ZK 验证（默认 false，只对可疑做验证）
    pub verify_all_with_leo: bool,
    /// Leo 源码目录（含 program.json），如果设置则自动编译
    pub source_dir: Option<std::path::PathBuf>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            runs: 1000,
            seed: 0,
            function_filter: None,
            include_edge_cases: true,
            spec: None,
            project_dir: None,
            verify_all_with_leo: false,
            source_dir: None,
        }
    }
}

/// Outcome of a single fuzz iteration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzOutcome {
    /// Execution passed with no issues
    Pass,
    /// A violation was found (underflow, balance mismatch, etc.)
    Violation {
        invariant: String,
        detail: String,
    },
    /// An instruction-level error (unexpected state, etc.)
    Error {
        message: String,
    },
}

impl FuzzOutcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, FuzzOutcome::Pass)
    }

    pub fn is_violation(&self) -> bool {
        matches!(self, FuzzOutcome::Violation { .. })
    }
}

/// Result of a single fuzz case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Function name
    pub function: String,
    /// Inputs as (register, value) pairs
    pub inputs: Vec<(String, SymValue)>,
    /// Input values formatted as strings
    pub input_strings: Vec<String>,
    /// What happened
    pub outcome: FuzzOutcome,
}

/// Aggregated report from a fuzzing run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    pub config: FuzzConfig,
    pub total_runs: u32,
    pub passed: u32,
    pub violations: u32,
    pub errors: u32,
    /// Per-function breakdown: (function_name, total, passed, violations)
    pub per_function: Vec<(String, u32, u32, u32)>,
    /// All violation results
    pub violation_results: Vec<FuzzResult>,
    /// 调用 leo run 做真实验证的次数
    pub zk_verifications: u32,
    /// ZK proof 生成成功的次数
    pub zk_proofs_generated: u32,
    /// 符号执行和 ZK 验证结果不一致的次数（真实 bug）
    pub zk_mismatches: u32,
    /// ZK 验证失败的详情
    pub zk_mismatch_details: Vec<crate::leo_runner::VerificationMismatch>,
}

// ============================================================================
// Instruction Parser
// ============================================================================

/// Parse a single instruction line from a function body.
/// Lines that are `input`, `output`, or block headers are handled separately.
pub fn parse_instruction(line: &str) -> Option<Instruction> {
    let trimmed = line.trim_end_matches(';').trim();

    if trimmed.is_empty() {
        return None;
    }

    // Split into tokens
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    match tokens[0] {
        "add" => parse_binary_op("add", &tokens),
        "sub" => parse_binary_op("sub", &tokens),
        "gt" => parse_binary_op("gt", &tokens),
        "cast" => parse_cast(&tokens),
        "get.or_use" => parse_get_or_use(&tokens),
        "set" => parse_set(&tokens),
        "async" => parse_async(&tokens),
        "assert.eq" => parse_assert_eq(&tokens),
        "assert.neq" => parse_assert_neq(&tokens),
        "output" => parse_output(&tokens),
        _ => Some(Instruction::Unknown(trimmed.to_string())),
    }
}

/// Parse `add rA rB into rC` or `sub rA rB into rC` or `gt rA rB into rC`
fn parse_binary_op(op: &str, tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 5 || tokens[3] != "into" {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }
    let lhs = parse_operand(tokens[1]);
    let rhs = parse_operand(tokens[2]);
    let dest = tokens[4].to_string();

    match op {
        "add" => Some(Instruction::Add { lhs, rhs, dest }),
        "sub" => Some(Instruction::Sub { lhs, rhs, dest }),
        "gt" => Some(Instruction::Gt { lhs, rhs, dest }),
        _ => None,
    }
}

/// Parse `cast rA rB ... into rC as token.record`
fn parse_cast(tokens: &[&str]) -> Option<Instruction> {
    let into_pos = tokens.iter().position(|&t| t == "into")?;
    let as_pos = tokens.iter().position(|&t| t == "as")?;

    let fields: Vec<Operand> = tokens[1..into_pos]
        .iter()
        .map(|t| parse_operand(t))
        .collect();
    let dest = tokens[into_pos + 1].to_string();
    let as_type = tokens[as_pos + 1..].join(".");

    Some(Instruction::Cast {
        fields,
        dest,
        as_type,
    })
}

/// Parse `get.or_use mapping[key] default into rC`
fn parse_get_or_use(tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 5 || tokens[tokens.len() - 2] != "into" {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }

    let mapping_key = tokens[1];
    let (mapping, key) = if let Some(bracket_pos) = mapping_key.find('[') {
        let m = &mapping_key[..bracket_pos];
        let k = &mapping_key[bracket_pos + 1..mapping_key.len() - 1];
        (m.to_string(), k.to_string())
    } else {
        (mapping_key.to_string(), String::new())
    };

    let default = tokens[2].to_string();
    let dest = tokens.last().unwrap().to_string();

    Some(Instruction::GetOrUse {
        mapping,
        key,
        default,
        dest,
    })
}

/// Parse `set rA into mapping[key]`
fn parse_set(tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 4 || tokens[2] != "into" {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }

    let value = tokens[1].to_string();
    let mapping_key = tokens[3];
    let (mapping, key) = if let Some(bracket_pos) = mapping_key.find('[') {
        let m = &mapping_key[..bracket_pos];
        let k = &mapping_key[bracket_pos + 1..mapping_key.len() - 1];
        (m.to_string(), k.to_string())
    } else {
        (mapping_key.to_string(), String::new())
    };

    Some(Instruction::Set {
        value,
        mapping,
        key,
    })
}

/// Parse `async func args... into rC`
fn parse_async(tokens: &[&str]) -> Option<Instruction> {
    let into_pos = tokens.iter().position(|&t| t == "into")?;

    let func = tokens[1].to_string();
    let args: Vec<String> = tokens[2..into_pos].iter().map(|&s| s.to_string()).collect();
    let dest = tokens[into_pos + 1].to_string();

    Some(Instruction::Async { func, args, dest })
}

/// Parse `assert.eq rA rB`
fn parse_assert_eq(tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 3 {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }
    Some(Instruction::AssertEq {
        lhs: parse_operand(tokens[1]),
        rhs: parse_operand(tokens[2]),
    })
}

/// Parse `assert.neq rA rB`
fn parse_assert_neq(tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 3 {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }
    Some(Instruction::AssertNeq {
        lhs: parse_operand(tokens[1]),
        rhs: parse_operand(tokens[2]),
    })
}

/// Parse `output rA as type`
fn parse_output(tokens: &[&str]) -> Option<Instruction> {
    if tokens.len() < 4 || tokens[2] != "as" {
        return Some(Instruction::Unknown(tokens.join(" ")));
    }
    let src = tokens[1].to_string();
    let ty = tokens[3..].join(".");

    Some(Instruction::Output { src, ty })
}

/// Parse a single operand: register, field access, literal, or self.caller
fn parse_operand(s: &str) -> Operand {
    if s == "self.caller" {
        return Operand::SelfCaller;
    }
    // r0.amount → FieldAccess
    if let Some(dot_pos) = s.find('.') {
        let register = s[..dot_pos].to_string();
        let field = s[dot_pos + 1..].to_string();
        // Only if register starts with 'r' and the rest is digits
        if register.starts_with('r') && register[1..].chars().all(|c| c.is_ascii_digit()) {
            return Operand::FieldAccess { register, field };
        }
    }
    // r0, r1, ... → Register
    if s.starts_with('r') && s.len() >= 2 && s[1..].chars().all(|c| c.is_ascii_digit()) {
        return Operand::Register(s.to_string());
    }
    // Everything else → Literal
    Operand::Literal(s.to_string())
}

// ============================================================================
// Symbolic State
// ============================================================================

/// Tracks register values during symbolic execution
#[derive(Debug, Clone)]
pub struct SymbolicState {
    /// Register name → value
    registers: HashMap<String, SymValue>,
    /// Whether execution should stop (error encountered)
    pub halted: bool,
    /// Error message if halted
    pub error_message: Option<String>,
}

impl SymbolicState {
    /// Create a new empty state
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            halted: false,
            error_message: None,
        }
    }

    /// Initialize from generated inputs
    pub fn with_inputs(inputs: Vec<(String, SymValue)>) -> Self {
        let mut state = Self::new();
        for (reg, val) in inputs {
            state.set(&reg, val);
        }
        state
    }

    /// Set a register value
    pub fn set(&mut self, reg: &str, value: SymValue) {
        self.registers.insert(reg.to_string(), value);
    }

    /// Get a register value
    pub fn get(&self, reg: &str) -> Option<&SymValue> {
        self.registers.get(reg)
    }

    /// Iterate over all register entries
    pub fn registers(&self) -> impl Iterator<Item = (&String, &SymValue)> {
        self.registers.iter()
    }

    /// Resolve an operand to a concrete SymValue
    pub fn resolve(&self, operand: &Operand) -> Option<SymValue> {
        match operand {
            Operand::Register(reg) => self.get(reg).cloned(),
            Operand::FieldAccess { register, field } => {
                let record = self.get(register)?;
                record.get_field(field).cloned()
            }
            Operand::Literal(s) => parse_literal(s),
            Operand::SelfCaller => Some(SymValue::Address(
                "aleo1selfcaller0000000000000000000000000000000000000000".to_string(),
            )),
        }
    }
}

/// Parse a literal string like "0u64", "100u64", "0u16", "0group" into a SymValue
pub fn parse_literal(s: &str) -> Option<SymValue> {
    if s == "self.caller" {
        return Some(SymValue::Address(
            "aleo1selfcaller0000000000000000000000000000000000000000".to_string(),
        ));
    }

    if s.ends_with("u64") {
        let num: u64 = s.trim_end_matches("u64").parse().ok()?;
        return Some(SymValue::U64(num));
    }
    if s.ends_with("u32") {
        let num: u32 = s.trim_end_matches("u32").parse().ok()?;
        return Some(SymValue::U32(num));
    }
    if s.ends_with("u16") {
        let num: u16 = s.trim_end_matches("u16").parse().ok()?;
        return Some(SymValue::U16(num));
    }
    if s.ends_with("u8") {
        let num: u8 = s.trim_end_matches("u8").parse().ok()?;
        return Some(SymValue::U8(num));
    }
    if s.ends_with("u128") {
        let num: u128 = s.trim_end_matches("u128").parse().ok()?;
        return Some(SymValue::U128(num));
    }
    if s.ends_with("i64") {
        let num: i64 = s.trim_end_matches("i64").parse().ok()?;
        return Some(SymValue::I64(num));
    }
    if s.ends_with("i32") {
        let num: i32 = s.trim_end_matches("i32").parse().ok()?;
        return Some(SymValue::I32(num));
    }
    if s.ends_with("i16") {
        let num: i16 = s.trim_end_matches("i16").parse().ok()?;
        return Some(SymValue::I16(num));
    }
    if s.ends_with("i8") {
        let num: i8 = s.trim_end_matches("i8").parse().ok()?;
        return Some(SymValue::I8(num));
    }
    if s == "true" {
        return Some(SymValue::Bool(true));
    }
    if s == "false" {
        return Some(SymValue::Bool(false));
    }
    // Unknown literals — treat as U64(0) for default values
    if s.ends_with("group") || s.ends_with("field") {
        return Some(SymValue::U64(0));
    }

    None
}

// ============================================================================
// Symbolic Executor
// ============================================================================

/// Execute a single instruction on the state, returning any violations found
pub fn execute_instruction(
    inst: &Instruction,
    state: &mut SymbolicState,
    func_name: &str,
) -> Vec<String> {
    let mut violations = Vec::new();

    match inst {
        Instruction::Add { lhs, rhs, dest } => {
            let lhs_val = state.resolve(lhs);
            let rhs_val = state.resolve(rhs);

            match (lhs_val, rhs_val) {
                (Some(SymValue::U64(a)), Some(SymValue::U64(b))) => {
                    let (result, overflow) = a.overflowing_add(b);
                    if overflow {
                        violations.push(format!(
                            "OVERFLOW in {}: add r{} r{} — {} + {} overflows u64",
                            func_name,
                            operand_str(lhs),
                            operand_str(rhs),
                            a,
                            b
                        ));
                    }
                    state.set(dest, SymValue::U64(result));
                }
                (Some(_a), Some(_b)) => {
                    state.set(dest, SymValue::Unknown);
                }
                (None, _) | (_, None) => {
                    state.set(dest, SymValue::Unknown);
                }
            }
        }

        Instruction::Sub { lhs, rhs, dest } => {
            let lhs_val = state.resolve(lhs);
            let rhs_val = state.resolve(rhs);

            match (lhs_val, rhs_val) {
                (Some(SymValue::U64(a)), Some(SymValue::U64(b))) => {
                    if b > a {
                        violations.push(format!(
                            "UNDERFLOW in {}: sub {} {} — {} < {} would underflow u64 (wraps to {})",
                            func_name,
                            operand_str(lhs),
                            operand_str(rhs),
                            a,
                            b,
                            a.wrapping_sub(b)
                        ));
                    }
                    let (result, _underflow) = a.overflowing_sub(b);
                    state.set(dest, SymValue::U64(result));
                }
                (Some(_a), Some(_b)) => {
                    state.set(dest, SymValue::Unknown);
                }
                (None, _) | (_, None) => {
                    state.set(dest, SymValue::Unknown);
                }
            }
        }

        Instruction::Cast {
            fields,
            dest,
            as_type,
        } => {
            let mut record_fields = HashMap::new();

            let type_name = as_type
                .trim_end_matches(".record")
                .trim_end_matches(&format!(".aleo/{}", as_type));

            for (i, field_op) in fields.iter().enumerate() {
                if let Some(val) = state.resolve(field_op) {
                    let field_name = match i {
                        0 => "owner",
                        1 => "amount",
                        _ => "unknown",
                    };
                    record_fields.insert(field_name.to_string(), val);
                }
            }

            let record = SymValue::Record {
                record_type: type_name.to_string(),
                fields: record_fields,
            };
            state.set(dest, record);
        }

        Instruction::Gt { lhs, rhs, dest } => {
            let lhs_val = state.resolve(lhs);
            let rhs_val = state.resolve(rhs);

            match (lhs_val, rhs_val) {
                (Some(SymValue::U64(a)), Some(SymValue::U64(b))) => {
                    state.set(dest, SymValue::Bool(a > b));
                }
                _ => {
                    state.set(dest, SymValue::Bool(false));
                }
            }
        }

        Instruction::GetOrUse { default, dest, .. } => {
            if let Some(val) = parse_literal(default) {
                state.set(dest, val);
            } else {
                state.set(dest, SymValue::U64(0));
            }
        }

        Instruction::Set { .. } => {
            // No state change for symbolic execution (we don't track mappings)
        }

        Instruction::Async { dest, .. } => {
            state.set(dest, SymValue::Future("future".to_string()));
        }

        Instruction::AssertEq { lhs, rhs } => {
            let lhs_val = state.resolve(lhs);
            let rhs_val = state.resolve(rhs);
            if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                if a != b {
                    violations.push(format!(
                        "ASSERTION FAILED in {}: assert.eq {} {} — {:?} != {:?}",
                        func_name,
                        operand_str(lhs),
                        operand_str(rhs),
                        a,
                        b
                    ));
                }
            }
        }

        Instruction::AssertNeq { lhs, rhs } => {
            let lhs_val = state.resolve(lhs);
            let rhs_val = state.resolve(rhs);
            if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                if a == b {
                    violations.push(format!(
                        "ASSERTION FAILED in {}: assert.neq {} {} — {:?} == {:?}",
                        func_name,
                        operand_str(lhs),
                        operand_str(rhs),
                        a,
                        b
                    ));
                }
            }
        }

        Instruction::Output { .. } => {
            // Outputs are tracked separately; no state change
        }

        Instruction::Unknown(_) => {
            // Silently skip unknown instructions
        }
    }

    violations
}

/// Format an operand for display in error messages
fn operand_str(op: &Operand) -> String {
    match op {
        Operand::Register(r) => r.clone(),
        Operand::FieldAccess { register, field } => format!("{}.{}", register, field),
        Operand::Literal(s) => s.clone(),
        Operand::SelfCaller => "self.caller".to_string(),
    }
}

// ============================================================================
// FuzzRunner
// ============================================================================

/// The main fuzzing orchestrator.
pub struct FuzzRunner {
    config: FuzzConfig,
    contract: Contract,
    /// Raw .aleo file content for instruction extraction
    raw_content: String,
}

impl FuzzRunner {
    /// Create a new fuzz runner
    pub fn new(config: FuzzConfig, contract: Contract, raw_content: String) -> Self {
        Self {
            config,
            contract,
            raw_content,
        }
    }

    /// Run the fuzzer and produce a report
    pub fn run(&self) -> FuzzReport {
        let mut report = FuzzReport {
            config: self.config.clone(),
            total_runs: 0,
            passed: 0,
            violations: 0,
            errors: 0,
            per_function: Vec::new(),
            violation_results: Vec::new(),
            zk_verifications: 0,
            zk_proofs_generated: 0,
            zk_mismatches: 0,
            zk_mismatch_details: Vec::new(),
        };

        // Determine which functions to fuzz
        let functions: Vec<&FunctionDef> = if let Some(ref filter) = self.config.function_filter {
            self.contract
                .functions
                .iter()
                .filter(|f| f.name == *filter)
                .collect()
        } else {
            self.contract.functions.iter().collect()
        };

        // Calculate runs per function
        let func_count = functions.len().max(1) as u32;
        let runs_per_func = self.config.runs / func_count;
        let remainder = self.config.runs % func_count;

        let mut gen = InputGenerator::new(self.config.seed);

        for (i, func) in functions.iter().enumerate() {
            let extra = if (i as u32) < remainder { 1 } else { 0 };
            let func_runs = runs_per_func + extra;

            let (func_passed, func_violations, func_errors, func_results, zk_stats) =
                self.fuzz_function(func, func_runs, &mut gen);

            report.total_runs += func_runs;
            report.passed += func_passed;
            report.violations += func_violations;
            report.errors += func_errors;
            report
                .per_function
                .push((func.name.clone(), func_runs, func_passed, func_violations));
            report.violation_results.extend(func_results);

            // 累加 ZK 统计
            report.zk_verifications += zk_stats.verifications;
            report.zk_proofs_generated += zk_stats.proofs_generated;
            report.zk_mismatches += zk_stats.mismatches;
            report.zk_mismatch_details.extend(zk_stats.mismatch_details);
        }

        report
    }

    /// Fuzz a single function for N iterations
    fn fuzz_function(
        &self,
        func: &FunctionDef,
        runs: u32,
        gen: &mut InputGenerator,
    ) -> (u32, u32, u32, Vec<FuzzResult>, ZkStats) {
        let mut passed = 0u32;
        let mut violations = 0u32;
        let errors = 0u32;
        let mut violation_results = Vec::new();
        let mut zk_stats = ZkStats::default();

        // 检查函数是否涉及 record 操作（隐私路径）
        let involves_record = func.inputs.iter().any(|p| p.ty.contains("record"))
            || func.outputs.iter().any(|p| p.ty.contains("record"));

        for _ in 0..runs {
            // 生成随机输入
            let inputs = gen.generate_inputs(func, &self.contract.records);
            let input_strings: Vec<String> =
                inputs.iter().map(|(_, v)| v.to_leo_string()).collect();

            // 解析函数体指令
            let body_instructions = FuzzRunner::extract_instructions_from_content(
                &self.raw_content,
                &func.name,
            );

            // 阶段 1：符号执行
            let mut state = SymbolicState::with_inputs(inputs.clone());
            let mut all_violations = Vec::new();

            for inst in &body_instructions {
                let inst_violations =
                    execute_instruction(inst, &mut state, &func.name);
                all_violations.extend(inst_violations);
            }

            // 检查额外不变式
            if let Some(inv_violations) =
                invariants::check_function_invariants(func, &state, &self.contract, self.config.spec.as_ref())
            {
                all_violations.extend(inv_violations);
            }

            let symbolic_pass = all_violations.is_empty();

            // 阶段 2：ZK 验证（只在特定条件触发）
            let should_verify_with_leo = self.config.project_dir.is_some() && (
                self.config.verify_all_with_leo
                || !symbolic_pass
                || involves_record
            );

            if should_verify_with_leo {
                if let Some(project_dir) = &self.config.project_dir {
                    if let Some(leo_result) = crate::leo_runner::run_leo_function(
                        project_dir,
                        &func.name,
                        &input_strings,
                    ) {
                        zk_stats.verifications += 1;
                        if leo_result.proof_generated {
                            zk_stats.proofs_generated += 1;
                        }

                        // 对比符号执行和真实 ZK 结果
                        let mismatches = crate::leo_runner::compare_results(
                            symbolic_pass,
                            &all_violations,
                            &leo_result,
                        );
                        if !mismatches.is_empty() {
                            zk_stats.mismatches += 1;
                            zk_stats.mismatch_details.extend(mismatches.clone());

                            // 把 mismatch 加到 violation_results
                            for m in &mismatches {
                                violation_results.push(FuzzResult {
                                    function: func.name.clone(),
                                    inputs: inputs.clone(),
                                    input_strings: input_strings.clone(),
                                    outcome: FuzzOutcome::Violation {
                                        invariant: format!("zk_mismatch:{:?}", m.kind),
                                        detail: m.detail.clone(),
                                    },
                                });
                            }
                            violations += 1;
                            continue;
                        }
                    }
                }
            }

            // 记录结果
            if symbolic_pass {
                passed += 1;
            } else {
                violations += 1;
                let detail = all_violations.join("; ");
                violation_results.push(FuzzResult {
                    function: func.name.clone(),
                    inputs: inputs.clone(),
                    input_strings: input_strings.clone(),
                    outcome: FuzzOutcome::Violation {
                        invariant: "symbolic".to_string(),
                        detail,
                    },
                });
            }
        }

        (passed, violations, errors, violation_results, zk_stats)
    }

    /// Extract instructions from a function's body.
    pub fn extract_instructions_from_content(
        content: &str,
        func_name: &str,
    ) -> Vec<Instruction> {
        let mut instructions = Vec::new();
        let mut in_function = false;

        let function_header = format!("function {}:", func_name);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if trimmed.starts_with(&function_header) {
                in_function = true;
                continue;
            }

            if !in_function {
                continue;
            }

            if is_block_header(trimmed) {
                break;
            }

            if let Some(inst) = parse_instruction(trimmed) {
                instructions.push(inst);
            }
        }

        instructions
    }
}

/// Check if a line is a block header (from parser.rs)
pub fn is_block_header(line: &str) -> bool {
    line.starts_with("record ")
        || line.starts_with("mapping ")
        || line.starts_with("function ")
        || line.starts_with("finalize ")
        || line.starts_with("constructor")
        || line.starts_with("interface ")
}

// ============================================================================
// Report Formatting
// ============================================================================

impl FuzzReport {
    /// Pretty-print the fuzz report with colors
    pub fn pretty_print(&self) -> String {
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
            out.push_str(&format!(
                "\n{}\n",
                "Violations:".red().bold()
            ));

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
        if self.errors > 0 {
            out.push_str(&format!(
                "  {} Errors\n",
                format!("{}", self.errors).red()
            ));
        }

        // ZK 验证统计（核心：展示使用了 Aleo 隐私能力）
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

    /// Pretty-print a spec-directed invariant check report
    pub fn pretty_print_with_spec(&self, spec: &InvariantSpec) -> String {
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

        // ZK 验证统计
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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_operand() {
        assert_eq!(parse_operand("r0"), Operand::Register("r0".to_string()));
        assert_eq!(parse_operand("r5"), Operand::Register("r5".to_string()));
        assert_eq!(
            parse_operand("r0.amount"),
            Operand::FieldAccess {
                register: "r0".to_string(),
                field: "amount".to_string()
            }
        );
        assert_eq!(parse_operand("self.caller"), Operand::SelfCaller);
        assert_eq!(parse_operand("0u64"), Operand::Literal("0u64".to_string()));
        assert_eq!(
            parse_operand("100u64"),
            Operand::Literal("100u64".to_string())
        );
    }

    #[test]
    fn test_parse_add_instruction() {
        let inst = parse_instruction("add r2 r1 into r3;").unwrap();
        assert_eq!(
            inst,
            Instruction::Add {
                lhs: Operand::Register("r2".to_string()),
                rhs: Operand::Register("r1".to_string()),
                dest: "r3".to_string()
            }
        );
    }

    #[test]
    fn test_parse_sub_instruction() {
        let inst = parse_instruction("sub r0.amount r2 into r3;").unwrap();
        assert_eq!(
            inst,
            Instruction::Sub {
                lhs: Operand::FieldAccess {
                    register: "r0".to_string(),
                    field: "amount".to_string()
                },
                rhs: Operand::Register("r2".to_string()),
                dest: "r3".to_string()
            }
        );
    }

    #[test]
    fn test_parse_cast_instruction() {
        let inst = parse_instruction("cast r0.owner r3 into r4 as token.record;").unwrap();
        match inst {
            Instruction::Cast {
                fields,
                dest,
                as_type,
            } => {
                assert_eq!(fields.len(), 2);
                assert_eq!(dest, "r4");
                assert_eq!(as_type, "token.record");
            }
            _ => panic!("Expected Cast, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_get_or_use() {
        let inst = parse_instruction("get.or_use account[r0] 0u64 into r2;").unwrap();
        match inst {
            Instruction::GetOrUse {
                mapping,
                key,
                default,
                dest,
            } => {
                assert_eq!(mapping, "account");
                assert_eq!(key, "r0");
                assert_eq!(default, "0u64");
                assert_eq!(dest, "r2");
            }
            _ => panic!("Expected GetOrUse, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_set() {
        let inst = parse_instruction("set r3 into account[r0];").unwrap();
        match inst {
            Instruction::Set {
                value,
                mapping,
                key,
            } => {
                assert_eq!(value, "r3");
                assert_eq!(mapping, "account");
                assert_eq!(key, "r0");
            }
            _ => panic!("Expected Set, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_async() {
        let inst =
            parse_instruction("async mint_public r0 r1 into r2;").unwrap();
        match inst {
            Instruction::Async { func, args, dest } => {
                assert_eq!(func, "mint_public");
                assert_eq!(args, vec!["r0", "r1"]);
                assert_eq!(dest, "r2");
            }
            _ => panic!("Expected Async, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_async_with_self_caller() {
        let inst = parse_instruction(
            "async transfer_public self.caller r0 r1 into r2;",
        )
        .unwrap();
        match inst {
            Instruction::Async { func, args, dest } => {
                assert_eq!(func, "transfer_public");
                assert_eq!(args, vec!["self.caller", "r0", "r1"]);
                assert_eq!(dest, "r2");
            }
            _ => panic!("Expected Async, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_assert_eq() {
        let inst = parse_instruction("assert.eq edition 0u16;").unwrap();
        assert!(matches!(inst, Instruction::AssertEq { .. }));
    }

    #[test]
    fn test_parse_output() {
        let inst = parse_instruction("output r2 as token.record;").unwrap();
        match inst {
            Instruction::Output { src, ty } => {
                assert_eq!(src, "r2");
                assert_eq!(ty, "token.record");
            }
            _ => panic!("Expected Output, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_output_future() {
        let inst =
            parse_instruction("output r2 as token.aleo/mint_public.future;")
                .unwrap();
        match inst {
            Instruction::Output { src, ty } => {
                assert_eq!(src, "r2");
                assert_eq!(ty, "token.aleo/mint_public.future");
            }
            _ => panic!("Expected Output, got {:?}", inst),
        }
    }

    #[test]
    fn test_parse_literal_u64() {
        assert_eq!(parse_literal("0u64"), Some(SymValue::U64(0)));
        assert_eq!(parse_literal("100u64"), Some(SymValue::U64(100)));
        assert_eq!(parse_literal("18446744073709551615u64"), Some(SymValue::U64(u64::MAX)));
    }

    #[test]
    fn test_parse_literal_other() {
        assert_eq!(parse_literal("0u32"), Some(SymValue::U32(0)));
        assert_eq!(parse_literal("255u8"), Some(SymValue::U8(255)));
        assert_eq!(parse_literal("true"), Some(SymValue::Bool(true)));
        assert_eq!(parse_literal("false"), Some(SymValue::Bool(false)));
        assert_eq!(parse_literal("0group"), Some(SymValue::U64(0)));
    }

    // ==========================================================================
    // Symbolic Execution Tests
    // ==========================================================================

    #[test]
    fn test_symbolic_add() {
        let mut state = SymbolicState::new();
        state.set("r0", SymValue::U64(10));
        state.set("r1", SymValue::U64(20));

        let inst = Instruction::Add {
            lhs: Operand::Register("r0".to_string()),
            rhs: Operand::Register("r1".to_string()),
            dest: "r2".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert!(violations.is_empty());
        assert_eq!(state.get("r2"), Some(&SymValue::U64(30)));
    }

    #[test]
    fn test_symbolic_add_overflow() {
        let mut state = SymbolicState::new();
        state.set("r0", SymValue::U64(u64::MAX));
        state.set("r1", SymValue::U64(1));

        let inst = Instruction::Add {
            lhs: Operand::Register("r0".to_string()),
            rhs: Operand::Register("r1".to_string()),
            dest: "r2".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("OVERFLOW"));
    }

    #[test]
    fn test_symbolic_sub_normal() {
        let mut state = SymbolicState::new();
        state.set("r0", SymValue::U64(100));
        state.set("r1", SymValue::U64(30));

        let inst = Instruction::Sub {
            lhs: Operand::Register("r0".to_string()),
            rhs: Operand::Register("r1".to_string()),
            dest: "r2".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert!(violations.is_empty());
        assert_eq!(state.get("r2"), Some(&SymValue::U64(70)));
    }

    #[test]
    fn test_symbolic_sub_underflow() {
        let mut state = SymbolicState::new();
        state.set("r0", SymValue::U64(50));
        state.set("r1", SymValue::U64(100));

        let inst = Instruction::Sub {
            lhs: Operand::Register("r0".to_string()),
            rhs: Operand::Register("r1".to_string()),
            dest: "r2".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("UNDERFLOW"));
        assert_eq!(state.get("r2"), Some(&SymValue::U64(50u64.wrapping_sub(100))));
    }

    #[test]
    fn test_symbolic_field_access_sub_underflow() {
        let mut state = SymbolicState::new();
        let mut fields = HashMap::new();
        fields.insert("owner".to_string(), SymValue::Address("aleo1test".to_string()));
        fields.insert("amount".to_string(), SymValue::U64(50));
        state.set(
            "r0",
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );
        state.set("r2", SymValue::U64(100));

        let inst = Instruction::Sub {
            lhs: Operand::FieldAccess {
                register: "r0".to_string(),
                field: "amount".to_string(),
            },
            rhs: Operand::Register("r2".to_string()),
            dest: "r3".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "transfer_private");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("UNDERFLOW"), "Expected underflow, got: {}", violations[0]);
    }

    #[test]
    fn test_symbolic_cast() {
        let mut state = SymbolicState::new();
        let mut fields = HashMap::new();
        fields.insert("owner".to_string(), SymValue::Address("aleo1owner".to_string()));
        fields.insert("amount".to_string(), SymValue::U64(100));
        state.set(
            "r0",
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );
        state.set("r3", SymValue::U64(70));

        let inst = Instruction::Cast {
            fields: vec![
                Operand::FieldAccess {
                    register: "r0".to_string(),
                    field: "owner".to_string(),
                },
                Operand::Register("r3".to_string()),
            ],
            dest: "r4".to_string(),
            as_type: "token.record".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert!(violations.is_empty());

        let record = state.get("r4").unwrap();
        assert!(matches!(record, SymValue::Record { .. }));
        if let SymValue::Record { fields, .. } = record {
            assert!(fields.contains_key("owner"));
            assert!(fields.contains_key("amount"));
            assert_eq!(fields.get("amount").unwrap(), &SymValue::U64(70));
        }
    }

    #[test]
    fn test_symbolic_gt() {
        let mut state = SymbolicState::new();
        state.set("r0", SymValue::U64(100));
        state.set("r1", SymValue::U64(50));

        let inst = Instruction::Gt {
            lhs: Operand::Register("r0".to_string()),
            rhs: Operand::Register("r1".to_string()),
            dest: "r2".to_string(),
        };

        let violations = execute_instruction(&inst, &mut state, "test");
        assert!(violations.is_empty());
        assert_eq!(state.get("r2"), Some(&SymValue::Bool(true)));
    }

    #[test]
    fn test_extract_instructions_from_content() {
        let content = r#"function mint_private:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function transfer_private:
    input r0 as token.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.amount r2 into r3;
    cast r0.owner r3 into r4 as token.record;
    cast r1 r2 into r5 as token.record;
    output r4 as token.record;
    output r5 as token.record;
"#;

        let insts =
            FuzzRunner::extract_instructions_from_content(content, "transfer_private");
        assert!(insts.len() >= 6, "Expected at least 6 instructions, got {}", insts.len());
        let recognized: Vec<_> = insts.iter().filter(|i| !matches!(i, Instruction::Unknown(_))).collect();
        assert!(matches!(recognized[0], Instruction::Sub { .. }),
            "First recognized instruction should be Sub");
    }

    #[test]
    fn test_fuzz_report_empty() {
        let report = FuzzReport {
            config: FuzzConfig::default(),
            total_runs: 100,
            passed: 100,
            violations: 0,
            errors: 0,
            per_function: vec![("mint_private".to_string(), 100, 100, 0)],
            violation_results: vec![],
            zk_verifications: 0,
            zk_proofs_generated: 0,
            zk_mismatches: 0,
            zk_mismatch_details: vec![],
        };

        let output = report.pretty_print();
        assert!(output.contains("⚡ Fuzz Report"));
        assert!(output.contains("mint_private"));
        assert!(output.contains("100"));
    }

    #[test]
    fn test_fuzz_report_with_violations() {
        let report = FuzzReport {
            config: FuzzConfig::default(),
            total_runs: 200,
            passed: 180,
            violations: 20,
            errors: 0,
            per_function: vec![
                ("transfer_private".to_string(), 200, 180, 20),
            ],
            violation_results: vec![FuzzResult {
                function: "transfer_private".to_string(),
                inputs: vec![],
                input_strings: vec!["token { ... }".to_string(), "aleo1...".to_string(), "100u64".to_string()],
                outcome: FuzzOutcome::Violation {
                    invariant: "fuzz".to_string(),
                    detail: "UNDERFLOW in transfer_private: sub r0.amount r2 — 50 < 100 would underflow u64".to_string(),
                },
            }],
            zk_verifications: 0,
            zk_proofs_generated: 0,
            zk_mismatches: 0,
            zk_mismatch_details: vec![],
        };

        let output = report.pretty_print();
        assert!(output.contains("UNDERFLOW"));
        assert!(output.contains("transfer_private"));
        assert!(output.contains("20 violations"));
    }

    #[test]
    fn test_fuzz_report_with_zk_stats() {
        let report = FuzzReport {
            config: FuzzConfig::default(),
            total_runs: 100,
            passed: 95,
            violations: 5,
            errors: 0,
            per_function: vec![("mint_private".to_string(), 100, 95, 5)],
            violation_results: vec![],
            zk_verifications: 50,
            zk_proofs_generated: 47,
            zk_mismatches: 3,
            zk_mismatch_details: vec![],
        };

        let output = report.pretty_print();
        assert!(output.contains("Privacy Capability Used"));
        assert!(output.contains("50 ZK proof verifications"));
        assert!(output.contains("47 ZK proofs generated"));
        assert!(output.contains("3 Mismatches"));
    }
}