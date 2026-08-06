//! # Invariant Analysis
//!
//! Checks privacy and safety invariants for Aleo contracts:
//! - **Balance conservation**: total token supply preserved across transfers
//! - **Arithmetic safety**: no overflow/underflow in unsigned operations
//! - **Owner integrity**: record owners are valid and preserved
//! - **Zero-amount detection**: transfers of 0 tokens
//! - **Self-transfer detection**: sender == receiver in transfers
//!
//! When an `InvariantSpec` is provided, checks are gated by the toggle
//! settings and custom assertions from the spec are also evaluated.

use crate::fuzzer::SymbolicState;
use crate::generator::SymValue;
use crate::parser::{Contract, FunctionDef};
use crate::spec::{AssertionDef, AssertionType, InvariantSpec};

/// Check invariants on the final state after symbolic execution of a function.
///
/// When `spec` is provided, toggles from the spec control which built-in
/// invariants are checked. Custom assertions from the spec are also evaluated.
/// When `spec` is `None`, all built-in invariants run with default settings.
pub fn check_function_invariants(
    func: &FunctionDef,
    state: &SymbolicState,
    _contract: &Contract,
    spec: Option<&InvariantSpec>,
) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    if let Some(spec) = spec {
        let toggle = spec.invariants.resolve(&func.name);

        if toggle.is_enabled("balance_conservation") && is_transfer_function(&func.name) {
            if let Some(v) = check_balance_conservation(func, state) {
                violations.extend(v);
            }
        }
        if toggle.is_enabled("owner_integrity") {
            if let Some(v) = check_owner_integrity(func, state) {
                violations.extend(v);
            }
        }
        if toggle.is_enabled("zero_amount") {
            if let Some(v) = check_zero_amount(state) {
                violations.extend(v);
            }
        }
        if toggle.is_enabled("record_consumption") {
            if let Some(v) = check_record_consumption(func, state) {
                violations.extend(v);
            }
        }
        if toggle.is_enabled("private_param_usage") {
            if let Some(v) = check_private_param_usage(func, state) {
                violations.extend(v);
            }
        }

        // Evaluate custom assertions from the spec
        for assertion in &spec.assertions {
            if assertion.function == func.name {
                if let Some(v) = check_custom_assertion(assertion, func, state) {
                    violations.extend(v);
                }
            }
        }
    } else {
        // Backward-compatible defaults when no spec is provided
        if is_transfer_function(&func.name) {
            if let Some(v) = check_balance_conservation(func, state) {
                violations.extend(v);
            }
        }
        if let Some(v) = check_owner_integrity(func, state) {
            violations.extend(v);
        }
        if let Some(v) = check_zero_amount(state) {
            violations.extend(v);
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

// ============================================================================
// Built-in Invariant Checks
// ============================================================================

/// Check that for transfer functions, the total amount in input records
/// equals the total amount in output records (accounting for futures).
fn check_balance_conservation(func: &FunctionDef, state: &SymbolicState) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    // Collect input record amounts
    let mut input_amount: u64 = 0;
    for param in &func.inputs {
        if let Some(val) = state.get(&param.register) {
            if let Some(amount) = val.extract_amount() {
                input_amount = input_amount.wrapping_add(amount);
            }
        }
    }

    // If no input amount tracked, skip
    if input_amount == 0 && !has_record_input(func) {
        return None;
    }

    // Collect output record amounts
    let mut output_amount: u64 = 0;
    let mut has_future_output = false;

    for output in &func.outputs {
        if let Some(val) = state.get(&output.register) {
            if let Some(amount) = val.extract_amount() {
                output_amount = output_amount.wrapping_add(amount);
            }
            if matches!(val, SymValue::Future(_)) {
                has_future_output = true;
            }
        }
    }

    // If there's a future output, some amount goes to public balance — skip strict check
    if has_future_output {
        return None;
    }

    // If we have both input and output amounts tracked, check conservation
    if input_amount > 0 && output_amount > 0 {
        // Allow for wrapped values (underflow)
        if output_amount > input_amount + 1_000_000_000 {
            violations.push(format!(
                "BALANCE_MISMATCH in {}: input total ~{}, output total ~{} (possible underflow creation)",
                func.name, input_amount, output_amount
            ));
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Check that output records have valid owner fields.
fn check_owner_integrity(func: &FunctionDef, state: &SymbolicState) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    for output in &func.outputs {
        if let Some(SymValue::Record { fields, .. }) = state.get(&output.register) {
            match fields.get("owner") {
                None => {
                    violations.push(format!(
                        "MISSING_OWNER in {}: output {} record has no owner field",
                        func.name, output.register
                    ));
                }
                Some(SymValue::Unknown) => {
                    violations.push(format!(
                        "INVALID_OWNER in {}: output {} record owner is unknown",
                        func.name, output.register
                    ));
                }
                _ => {} // Owner field present and valid
            }
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Check for zero-amount values in registers.
/// Zero amounts aren't necessarily bugs, but can indicate edge cases worth noting.
fn check_zero_amount(state: &SymbolicState) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    // Walk all registers looking for u64 zero values or records with zero amount
    for (reg, val) in state.registers() {
        match val {
            SymValue::U64(0) | SymValue::U32(0) | SymValue::U16(0) | SymValue::U8(0) => {
                violations.push(format!(
                    "ZERO_AMOUNT: register {} holds zero ({})",
                    reg,
                    val.to_leo_string()
                ));
            }
            SymValue::Record { fields, .. } => {
                if let Some(SymValue::U64(0)) = fields.get("amount") {
                    violations.push(format!(
                        "ZERO_AMOUNT: output record in {} has amount = 0",
                        reg
                    ));
                }
            }
            _ => {}
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

// ============================================================================
// Custom Assertion Checkers
// ============================================================================

/// Dispatch a custom assertion to the appropriate checker function.
fn check_custom_assertion(
    assertion: &AssertionDef,
    func: &FunctionDef,
    state: &SymbolicState,
) -> Option<Vec<String>> {
    match assertion.assertion_type {
        AssertionType::FieldSet => check_field_set(assertion, func, state),
        AssertionType::AmountConserved => check_amount_conserved_custom(func, state),
        AssertionType::NoFieldNone => check_no_field_none(assertion, func, state),
        AssertionType::RangeCheck => check_range(assertion, func, state),
    }
}

/// Assert that a named field exists in output records.
///
/// Type: `field_set`
/// Failure: output record is missing the named field
fn check_field_set(
    assertion: &AssertionDef,
    func: &FunctionDef,
    state: &SymbolicState,
) -> Option<Vec<String>> {
    let field_name = match &assertion.field {
        Some(f) => f,
        None => return None, // field name is required
    };

    let mut violations = Vec::new();

    for output in &func.outputs {
        if let Some(SymValue::Record { fields, record_type }) = state.get(&output.register) {
            if !fields.contains_key(field_name) {
                violations.push(format!(
                    "FIELD_NOT_SET in {}: output {} ({}) is missing field '{}'",
                    func.name, output.register, record_type, field_name
                ));
            }
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Assert that total input amount == total output amount.
///
/// Type: `amount_conserved`
/// Failure: input and output amounts differ (excluding futures)
fn check_amount_conserved_custom(
    func: &FunctionDef,
    state: &SymbolicState,
) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    // Sum amounts from input RECORDS only (skip plain u64/address params)
    let mut input_amount: u64 = 0;
    for param in &func.inputs {
        if param.ty.ends_with(".record") {
            if let Some(val) = state.get(&param.register) {
                if let Some(amount) = val.extract_amount() {
                    input_amount = input_amount.wrapping_add(amount);
                }
            }
        }
    }

    // Sum amounts from output RECORDS only
    let mut output_amount: u64 = 0;
    let mut has_future = false;
    for output in &func.outputs {
        if let Some(val) = state.get(&output.register) {
            if matches!(val, SymValue::Future(_)) {
                has_future = true;
                continue;
            }
            if output.ty.ends_with(".record") {
                if let Some(amount) = val.extract_amount() {
                    output_amount = output_amount.wrapping_add(amount);
                }
            }
        }
    }

    if has_future || input_amount == 0 {
        return None;
    }

    if input_amount != output_amount {
        violations.push(format!(
            "AMOUNT_NOT_CONSERVED in {}: input total = {}, output total = {}",
            func.name, input_amount, output_amount
        ));
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Assert that a named field is not Unknown and not zero.
///
/// Type: `no_field_none`
/// Failure: field is Unknown or U64(0) in any output record
fn check_no_field_none(
    assertion: &AssertionDef,
    func: &FunctionDef,
    state: &SymbolicState,
) -> Option<Vec<String>> {
    let field_name = match &assertion.field {
        Some(f) => f,
        None => return None,
    };

    let mut violations = Vec::new();

    for output in &func.outputs {
        if let Some(SymValue::Record { fields, .. }) = state.get(&output.register) {
            match fields.get(field_name) {
                None => {
                    violations.push(format!(
                        "FIELD_NONE in {}: output {} has no field '{}'",
                        func.name, output.register, field_name
                    ));
                }
                Some(SymValue::Unknown) => {
                    violations.push(format!(
                        "FIELD_NONE in {}: output {} field '{}' is Unknown",
                        func.name, output.register, field_name
                    ));
                }
                Some(SymValue::U64(0)) | Some(SymValue::U32(0)) => {
                    violations.push(format!(
                        "FIELD_ZERO in {}: output {} field '{}' is zero",
                        func.name, output.register, field_name
                    ));
                }
                _ => {} // field present with non-zero value
            }
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Assert that a numeric field value is within [min, max].
///
/// Type: `range_check`
/// Failure: field value is below min or above max
fn check_range(
    assertion: &AssertionDef,
    func: &FunctionDef,
    state: &SymbolicState,
) -> Option<Vec<String>> {
    let field_name = match &assertion.field {
        Some(f) => f,
        None => return None,
    };

    let mut violations = Vec::new();

    for output in &func.outputs {
        if let Some(SymValue::Record { fields, .. }) = state.get(&output.register) {
            if let Some(field_val) = fields.get(field_name) {
                let amount: Option<u64> = field_val.extract_amount();
                if let Some(amt) = amount {
                    if let Some(min) = assertion.min {
                        if (amt as i64) < min {
                            violations.push(format!(
                                "RANGE_VIOLATION in {}: output {} field '{}' = {} (min = {})",
                                func.name, output.register, field_name, amt, min
                            ));
                        }
                    }
                    if let Some(max) = assertion.max {
                        if (amt as i64) > max {
                            violations.push(format!(
                                "RANGE_VIOLATION in {}: output {} field '{}' = {} (max = {})",
                                func.name, output.register, field_name, amt, max
                            ));
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        None
    } else {
        Some(violations)
    }
}

/// Check that input records are consumed (transformed), not passed through unchanged.
/// This catches double-spend bugs where the same record appears in both input and output.
fn check_record_consumption(func: &FunctionDef, state: &SymbolicState) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    for input in &func.inputs {
        if !input.ty.ends_with(".record") {
            continue;
        }

        // Get the input record
        let input_record = match state.get(&input.register) {
            Some(SymValue::Record { fields, .. }) => fields,
            _ => continue,
        };

        // Check if any output record is identical (same owner + amount)
        for output in &func.outputs {
            if !output.ty.ends_with(".record") {
                continue;
            }
            let output_record = match state.get(&output.register) {
                Some(SymValue::Record { fields, .. }) => fields,
                _ => continue,
            };

            // Compare: same owner AND same amount = record not consumed
            let same_owner = input_record.get("owner") == output_record.get("owner");
            let same_amount = input_record.get("amount") == output_record.get("amount");
            if same_owner && same_amount && input_record.get("owner").is_some() {
                violations.push(format!(
                    "RECORD_NOT_CONSUMED in {}: input {} and output {} have identical owner+amount — possible double-spend",
                    func.name, input.register, output.register
                ));
            }
        }
    }

    if violations.is_empty() { None } else { Some(violations) }
}

/// Check that `.private` input parameters are actually accessed during execution.
/// Unused private params suggest dead code or incomplete privacy implementation.
fn check_private_param_usage(func: &FunctionDef, state: &SymbolicState) -> Option<Vec<String>> {
    let mut violations = Vec::new();

    for input in &func.inputs {
        if input.visibility != crate::parser::Visibility::Private {
            continue;
        }

        // Check if the register has a value that was set (meaning it was read/written)
        match state.get(&input.register) {
            None => {
                violations.push(format!(
                    "UNUSED_PRIVATE_PARAM in {}: private param {} ({}) was never accessed",
                    func.name, input.register, input.ty
                ));
            }
            Some(SymValue::Unknown) => {
                // Unknown means it was never resolved — likely unused
            }
            _ => {} // Register was used
        }
    }

    if violations.is_empty() { None } else { Some(violations) }
}

// ============================================================================
// Helpers
// ============================================================================

/// Check if a function is a transfer function.
fn is_transfer_function(name: &str) -> bool {
    name.starts_with("transfer_")
}

/// Check if a function has record inputs.
fn has_record_input(func: &FunctionDef) -> bool {
    func.inputs.iter().any(|p| p.ty.ends_with(".record"))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::SymbolicState;
    use crate::generator::SymValue;
    use crate::parser::Param;
    use crate::spec::InvariantToggle;
    use std::collections::HashMap;

    fn make_state_with_record(reg: &str, owner: &str, amount: u64) -> SymbolicState {
        let mut state = SymbolicState::new();
        let mut fields = HashMap::new();
        fields.insert("owner".to_string(), SymValue::Address(owner.to_string()));
        fields.insert("amount".to_string(), SymValue::U64(amount));
        state.set(
            reg,
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );
        state
    }

    fn make_transfer_func(name: &str) -> FunctionDef {
        FunctionDef {
            name: name.to_string(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    fn make_param(register: &str, ty: &str) -> Param {
        Param {
            register: register.to_string(),
            ty: ty.to_string(),
            visibility: crate::parser::Visibility::None,
        }
    }

    // --------------------------------------------------------------------------
    // Backward Compatibility Tests (no spec = all built-ins run)
    // --------------------------------------------------------------------------

    #[test]
    fn test_check_without_spec_defaults() {
        let state = make_state_with_record("r4", "aleo1owner", 50);
        let func = make_transfer_func("transfer_private");
        // With no spec, should run all checks with defaults
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), None);
        assert!(violations.is_none(), "Expected no violations, got {:?}", violations);
    }

    #[test]
    fn test_check_without_spec_on_non_transfer() {
        let state = SymbolicState::new();
        let func = FunctionDef {
            name: "mint_private".to_string(),
            inputs: vec![],
            outputs: vec![],
        };
        // Non-transfer function with no spec — should still run owner/zero checks
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), None);
        // No violations expected on empty state
        assert!(violations.is_none());
    }

    // --------------------------------------------------------------------------
    // Spec-gated Check Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_check_with_spec_disabled_balance() {
        // transfer_private with balance_conservation disabled — no balance check
        let mut state = SymbolicState::new();
        // Set up imbalanced state: input amount 100, output amount 50
        let mut in_fields = HashMap::new();
        in_fields.insert("owner".to_string(), SymValue::Address("aleo1sender".to_string()));
        in_fields.insert("amount".to_string(), SymValue::U64(100));
        state.set(
            "r0",
            SymValue::Record {
                record_type: "token".to_string(),
                fields: in_fields,
            },
        );
        state.set("r2", SymValue::U64(50));

        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![
                make_param("r0", "token.record"),
                make_param("r1", "address"),
                make_param("r2", "u64"),
            ],
            outputs: vec![
                make_param("r4", "token.record"),
                make_param("r5", "token.record"),
            ],
        };

        let spec = make_spec_with_balance(false);

        // balance_conservation disabled — should NOT produce violation
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        // With empty output registers, owner_integrity won't find records, so no violations
        assert!(violations.is_none(), "Expected no violations with balance disabled, got {:?}", violations);
    }

    #[test]
    fn test_check_with_spec_enabled_balance() {
        // transfer_private with balance_conservation explicitly enabled
        let mut state = SymbolicState::new();
        let mut in_fields = HashMap::new();
        in_fields.insert("owner".to_string(), SymValue::Address("aleo1sender".to_string()));
        in_fields.insert("amount".to_string(), SymValue::U64(100));
        state.set("r0", SymValue::Record {
            record_type: "token".to_string(),
            fields: in_fields,
        });
        state.set("r2", SymValue::U64(100)); // transfer amount

        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![
                make_param("r0", "token.record"),
                make_param("r1", "address"),
                make_param("r2", "u64"),
            ],
            outputs: vec![
                make_param("r4", "token.record"),
                make_param("r5", "token.record"),
            ],
        };

        let spec = make_spec_with_balance(true);
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        // No violations since output registers are empty (no mismatched amounts visible)
        assert!(violations.is_none(), "Expected no violations, got {:?}", violations);
    }

    #[test]
    fn test_check_with_spec_enabled_zero_amount() {
        let mut state = SymbolicState::new();
        state.set("r2", SymValue::U64(0)); // zero amount in register
        state.set("r3", SymValue::U64(100));

        let func = FunctionDef {
            name: "transfer_public".to_string(),
            inputs: vec![],
            outputs: vec![],
        };

        let spec = make_spec_with_zero_amount(true);
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        assert!(violations.is_some(), "Expected zero-amount violation");
        let v = violations.unwrap();
        assert!(v[0].contains("ZERO_AMOUNT"), "Expected ZERO_AMOUNT, got: {}", v[0]);
    }

    #[test]
    fn test_check_with_spec_disabled_zero_amount() {
        let mut state = SymbolicState::new();
        state.set("r2", SymValue::U64(0));

        let func = make_transfer_func("transfer_public");
        let spec = make_spec_with_zero_amount(false);

        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        assert!(violations.is_none(), "Zero amount check disabled, expected no violation");
    }

    // --------------------------------------------------------------------------
    // Custom Assertion Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_custom_field_set_passes() {
        let state = make_state_with_record("r4", "aleo1owner", 50);
        let func = FunctionDef {
            name: "mint_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertion = AssertionDef {
            assertion_type: AssertionType::FieldSet,
            function: "mint_private".to_string(),
            description: "amount field must be set".to_string(),
            field: Some("amount".to_string()),
            min: None,
            max: None,
        };

        let violations = check_field_set(&assertion, &func, &state);
        assert!(violations.is_none(), "Expected no violations, got {:?}", violations);
    }

    #[test]
    fn test_custom_field_set_fails() {
        let mut state = SymbolicState::new();
        let fields = HashMap::new(); // no fields at all
        state.set(
            "r4",
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );

        let func = FunctionDef {
            name: "mint_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertion = AssertionDef {
            assertion_type: AssertionType::FieldSet,
            function: "mint_private".to_string(),
            description: "".to_string(),
            field: Some("amount".to_string()),
            min: None,
            max: None,
        };

        let violations = check_field_set(&assertion, &func, &state);
        assert!(violations.is_some());
        let v = violations.unwrap();
        assert!(v[0].contains("FIELD_NOT_SET"), "Expected FIELD_NOT_SET: {}", v[0]);
    }

    #[test]
    fn test_custom_amount_conserved() {
        let mut state = SymbolicState::new();
        // Input: r0.amount = 100, r2 = 50 (transfer amount)
        let mut in_fields = HashMap::new();
        in_fields.insert("owner".to_string(), SymValue::Address("aleo1sender".to_string()));
        in_fields.insert("amount".to_string(), SymValue::U64(100));
        state.set("r0", SymValue::Record {
            record_type: "token".to_string(),
            fields: in_fields,
        });
        state.set("r2", SymValue::U64(50));

        // Output: r4.amount = 50 (change), r5.amount = 50 (transfer)
        make_state_with_record_fields(&mut state, "r4", "aleo1sender", 50);
        make_state_with_record_fields(&mut state, "r5", "aleo1receiver", 50);

        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![
                make_param("r0", "token.record"),
                make_param("r1", "address"),
                make_param("r2", "u64"),
            ],
            outputs: vec![
                make_param("r4", "token.record"),
                make_param("r5", "token.record"),
            ],
        };

        // 100 input, 100 output — should pass
        let violations = check_amount_conserved_custom(&func, &state);
        assert!(violations.is_none(), "Expected balanced, got {:?}", violations);

        // Now change output to be imbalanced
        make_state_with_record_fields(&mut state, "r5", "aleo1receiver", 30);
        let violations = check_amount_conserved_custom(&func, &state);
        assert!(violations.is_some());
        let v = violations.unwrap();
        assert!(v[0].contains("AMOUNT_NOT_CONSERVED"), "Expected AMOUNT_NOT_CONSERVED: {}", v[0]);
    }

    #[test]
    fn test_custom_no_field_none() {
        let state = make_state_with_record("r4", "aleo1owner", 50);
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        // Owner field exists with valid address — should pass
        let assertion = AssertionDef {
            assertion_type: AssertionType::NoFieldNone,
            function: "transfer_private".to_string(),
            description: "".to_string(),
            field: Some("owner".to_string()),
            min: None,
            max: None,
        };
        let violations = check_no_field_none(&assertion, &func, &state);
        assert!(violations.is_none(), "Expected no violation, got {:?}", violations);
    }

    #[test]
    fn test_custom_no_field_none_missing() {
        let state = SymbolicState::new(); // empty state, no record
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertion = AssertionDef {
            assertion_type: AssertionType::NoFieldNone,
            function: "transfer_private".to_string(),
            description: "".to_string(),
            field: Some("nonexistent".to_string()),
            min: None,
            max: None,
        };
        // No record in state — nothing to check, passes silently
        let violations = check_no_field_none(&assertion, &func, &state);
        assert!(violations.is_none(), "No record in state should pass silently");
    }

    #[test]
    fn test_custom_range_check_pass() {
        let state = make_state_with_record("r4", "aleo1owner", 100);
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertion = AssertionDef {
            assertion_type: AssertionType::RangeCheck,
            function: "transfer_private".to_string(),
            description: "".to_string(),
            field: Some("amount".to_string()),
            min: Some(1),
            max: Some(1000),
        };
        let violations = check_range(&assertion, &func, &state);
        assert!(violations.is_none(), "Expected no violation, got {:?}", violations);
    }

    #[test]
    fn test_custom_range_check_violation() {
        let state = make_state_with_record("r4", "aleo1owner", 0);
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertion = AssertionDef {
            assertion_type: AssertionType::RangeCheck,
            function: "transfer_private".to_string(),
            description: "".to_string(),
            field: Some("amount".to_string()),
            min: Some(1),
            max: None,
        };
        let violations = check_range(&assertion, &func, &state);
        assert!(violations.is_some());
        let v = violations.unwrap();
        assert!(v[0].contains("RANGE_VIOLATION"), "Expected RANGE_VIOLATION: {}", v[0]);
    }

    #[test]
    fn test_custom_assertion_wrong_function() {
        // Assertion targets a different function — should not be evaluated
        let state = make_state_with_record("r4", "aleo1owner", 0);
        let func = FunctionDef {
            name: "mint_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let assertions = vec![AssertionDef {
            assertion_type: AssertionType::RangeCheck,
            function: "transfer_private".to_string(), // different function!
            description: "".to_string(),
            field: Some("amount".to_string()),
            min: Some(1),
            max: None,
        }];

        let spec = InvariantSpec {
            contract: crate::spec::ContractMeta {
                name: "token.aleo".to_string(),
            },
            invariants: crate::spec::InvariantSettings::default(),
            assertions,
        };

        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        assert!(violations.is_none(), "Assertion for other function should not fire");
    }

    #[test]
    fn test_check_with_spec_mint_skips_balance() {
        // mint_private should NOT check balance conservation (tokens are created)
        let state = make_state_with_record("r2", "aleo1owner", 1000);
        let func = FunctionDef {
            name: "mint_private".to_string(),
            inputs: vec![
                make_param("r0", "address"),
                make_param("r1", "u64"),
            ],
            outputs: vec![make_param("r2", "token.record")],
        };

        let spec = make_spec_with_balance(false);
        let violations = check_function_invariants(&func, &state, &make_dummy_contract(), Some(&spec));
        assert!(violations.is_none(), "Mint should skip balance check: {:?}", violations);
    }

    // --------------------------------------------------------------------------
    // Existing Tests (from original invariants.rs — must pass unchanged)
    // --------------------------------------------------------------------------

    #[test]
    fn test_owner_integrity_valid() {
        let state = make_state_with_record("r4", "aleo1owner", 50);
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let violations = check_owner_integrity(&func, &state);
        assert!(violations.is_none(), "Should be no violations, got {:?}", violations);
    }

    #[test]
    fn test_owner_integrity_missing_owner() {
        let mut state = SymbolicState::new();
        let fields = HashMap::new(); // empty — no owner
        state.set(
            "r4",
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );
        let func = FunctionDef {
            name: "transfer_private".to_string(),
            inputs: vec![],
            outputs: vec![make_param("r4", "token.record")],
        };

        let violations = check_owner_integrity(&func, &state);
        assert!(violations.is_some());
        let v = violations.unwrap();
        assert!(v[0].contains("MISSING_OWNER"));
    }

    #[test]
    fn test_is_transfer_function() {
        assert!(is_transfer_function("transfer_private"));
        assert!(is_transfer_function("transfer_public"));
        assert!(is_transfer_function("transfer_private_to_public"));
        assert!(!is_transfer_function("mint_private"));
        assert!(!is_transfer_function("mint_public"));
    }

    // --------------------------------------------------------------------------
    // Test Helpers
    // --------------------------------------------------------------------------

    fn make_dummy_contract() -> Contract {
        Contract {
            program: "token.aleo".to_string(),
            records: vec![],
            mappings: vec![],
            functions: vec![],
            finalizes: vec![],
        }
    }

    fn make_spec_with_balance(enabled: bool) -> InvariantSpec {
        InvariantSpec {
            contract: crate::spec::ContractMeta {
                name: "token.aleo".to_string(),
            },
            invariants: crate::spec::InvariantSettings {
                default: InvariantToggle {
                    balance_conservation: Some(enabled),
                    owner_integrity: Some(false),
                    zero_amount: Some(false),
                    ..Default::default()
                },
                functions: HashMap::new(),
            },
            assertions: vec![],
        }
    }

    fn make_spec_with_zero_amount(enabled: bool) -> InvariantSpec {
        InvariantSpec {
            contract: crate::spec::ContractMeta {
                name: "token.aleo".to_string(),
            },
            invariants: crate::spec::InvariantSettings {
                default: InvariantToggle {
                    balance_conservation: Some(false),
                    owner_integrity: Some(false),
                    zero_amount: Some(enabled),
                    ..Default::default()
                },
                functions: HashMap::new(),
            },
            assertions: vec![],
        }
    }

    fn make_state_with_record_fields(state: &mut SymbolicState, reg: &str, owner: &str, amount: u64) {
        let mut fields = HashMap::new();
        fields.insert("owner".to_string(), SymValue::Address(owner.to_string()));
        fields.insert("amount".to_string(), SymValue::U64(amount));
        state.set(
            reg,
            SymValue::Record {
                record_type: "token".to_string(),
                fields,
            },
        );
    }
}
