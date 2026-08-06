//! WASM bindings for LeoZap core fuzzer engine.
//!
//! Exposes key fuzzing functions to JavaScript so the entire fuzz pipeline
//! can run client-side in the browser — no server required.
//!
//! ## API
//! - `parse_contract(source)` → JSON Contract
//! - `fuzz_function(content, func_name, runs, seed, spec_content?)` → JSON result

use leo_zap_core::fuzzer::{execute_instruction, FuzzConfig, FuzzRunner};
use leo_zap_core::generator::InputGenerator;
use leo_zap_core::invariants;
use leo_zap_core::parser;
use leo_zap_core::spec;
use wasm_bindgen::prelude::*;

// ============================================================================
// Public API
// ============================================================================

/// Parse a .aleo contract source and return the parsed Contract as JSON.
#[wasm_bindgen]
pub fn parse_contract(source: &str) -> Result<String, JsValue> {
    let contract = parser::parse(source).map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&contract).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Fuzz a single function for N iterations and return a JSON result summary.
///
/// Returns a JSON object with:
/// - `passed`: number of passing iterations
/// - `violations`: number of violations found
/// - `violation_details`: array of violation detail strings
#[wasm_bindgen]
pub fn fuzz_function(
    content: &str,
    func_name: &str,
    runs: u32,
    seed: u64,
    spec_content: Option<String>,
) -> Result<String, JsValue> {
    // Parse contract
    let contract = parser::parse(content).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Find the function
    let func = contract
        .functions
        .iter()
        .find(|f| f.name == func_name)
        .ok_or_else(|| JsValue::from_str(&format!("function '{}' not found in contract", func_name)))?;

    // Parse spec if provided
    let spec = match &spec_content {
        Some(s) if !s.is_empty() => {
            match spec::parse_spec(s) {
                Ok(sp) => Some(sp),
                Err(e) => return Err(JsValue::from_str(&format!("spec parse error: {}", e))),
            }
        }
        _ => None,
    };

    // Build config
    let config = FuzzConfig {
        runs,
        seed,
        function_filter: Some(func_name.to_string()),
        include_edge_cases: true,
        spec,
        project_dir: None,       // No ZK in WASM
        verify_all_with_leo: false,
        source_dir: None,
    };

    // Generate inputs & run symbolic execution
    let mut gen = InputGenerator::new(seed);
    let mut passed = 0u32;
    let mut violations = 0u32;
    let mut violation_details: Vec<String> = Vec::new();

    for _ in 0..runs {
        let inputs = gen.generate_with_coverage(func, &contract.records);

        // Extract instructions
        let body_instructions =
            FuzzRunner::extract_instructions_from_content(content, func_name);

        // Symbolic execution
        let mut state = leo_zap_core::fuzzer::SymbolicState::with_inputs(inputs.clone());
        let mut all_violations = Vec::new();

        for inst in &body_instructions {
            let inst_violations =
                execute_instruction(inst, &mut state, func_name, &contract.records);
            all_violations.extend(inst_violations);
        }

        // Check invariants
        if let Some(inv_violations) =
            invariants::check_function_invariants(func, &state, &contract, config.spec.as_ref())
        {
            all_violations.extend(inv_violations);
        }

        if all_violations.is_empty() {
            passed += 1;
        } else {
            violations += 1;
            violation_details.push(all_violations.join("; "));
        }
    }

    // Build result
    let result = serde_json::json!({
        "function": func_name,
        "runs": runs,
        "passed": passed,
        "violations": violations,
        "violation_details": violation_details,
        "coverage_pct": 0.0_f64,
    });

    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a TOML invariant spec file and return the parsed spec as JSON.
#[wasm_bindgen]
pub fn parse_spec(spec_content: &str) -> Result<String, JsValue> {
    let spec = spec::parse_spec(spec_content).map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&spec).map_err(|e| JsValue::from_str(&e.to_string()))
}
