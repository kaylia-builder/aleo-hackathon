//! # Invariant Spec File Parser
//!
//! Parses TOML-format invariant specification files that define which
//! invariants to check for each contract function, plus custom assertions.
//!
//! ## Spec Format
//!
//! ```toml
//! [contract]
//! name = "token.aleo"
//!
//! [invariants.default]
//! balance_conservation = true
//! overflow_check = true
//! zero_amount = false
//!
//! [invariants.functions.mint_private]
//! balance_conservation = false
//!
//! [[assertions]]
//! type = "amount_conserved"
//! function = "transfer_private"
//! ```

use crate::parser::Contract;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// Data Structures
// ============================================================================

/// A parsed invariant specification file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantSpec {
    pub contract: ContractMeta,
    #[serde(default)]
    pub invariants: InvariantSettings,
    #[serde(default)]
    pub assertions: Vec<AssertionDef>,
}

/// Metadata about the contract this spec targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractMeta {
    pub name: String,
}

/// Global and per-function invariant toggle settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InvariantSettings {
    /// Default toggles applied to all functions
    #[serde(default)]
    pub default: InvariantToggle,
    /// Per-function overrides (function name → overridden toggles)
    #[serde(default)]
    pub functions: HashMap<String, InvariantToggle>,
}

impl InvariantSettings {
    /// Resolve the effective toggles for a function by merging per-function
    /// overrides onto the defaults. Function-level values take precedence.
    pub fn resolve(&self, func_name: &str) -> InvariantToggle {
        let mut effective = self.default.clone();
        if let Some(overrides) = self.functions.get(func_name) {
            if overrides.balance_conservation.is_some() {
                effective.balance_conservation = overrides.balance_conservation;
            }
            if overrides.owner_integrity.is_some() {
                effective.owner_integrity = overrides.owner_integrity;
            }
            if overrides.zero_amount.is_some() {
                effective.zero_amount = overrides.zero_amount;
            }
            if overrides.self_transfer.is_some() {
                effective.self_transfer = overrides.self_transfer;
            }
            if overrides.overflow_check.is_some() {
                effective.overflow_check = overrides.overflow_check;
            }
            if overrides.record_consumption.is_some() {
                effective.record_consumption = overrides.record_consumption;
            }
            if overrides.private_param_usage.is_some() {
                effective.private_param_usage = overrides.private_param_usage;
            }
        }
        effective
    }
}

/// Per-invariant on/off toggles. All fields are `Option<bool>` so that
/// per-function overrides only need to specify the invariants they change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InvariantToggle {
    /// Token supply is preserved across non-mint operations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_conservation: Option<bool>,
    /// Output records must have valid owner fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_integrity: Option<bool>,
    /// Flag zero-amount operations as suspicious
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_amount: Option<bool>,
    /// Flag self-transfers (sender == receiver)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_transfer: Option<bool>,
    /// Check for unsigned integer overflow in arithmetic
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overflow_check: Option<bool>,
    /// Verify input records are consumed (transformed, not passed through)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_consumption: Option<bool>,
    /// Flag unused .private input parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_param_usage: Option<bool>,
}

impl InvariantToggle {
    /// Check if a named invariant is enabled, with hard-coded defaults.
    ///
    /// Safety invariants (balance_conservation, owner_integrity, overflow_check)
    /// default to **enabled**. Informational invariants (zero_amount, self_transfer)
    /// default to **disabled** to reduce noise.
    pub fn is_enabled(&self, name: &str) -> bool {
        match name {
            "balance_conservation" => self.balance_conservation.unwrap_or(true),
            "owner_integrity" => self.owner_integrity.unwrap_or(true),
            "zero_amount" => self.zero_amount.unwrap_or(false),
            "self_transfer" => self.self_transfer.unwrap_or(false),
            "overflow_check" => self.overflow_check.unwrap_or(true),
            "record_consumption" => self.record_consumption.unwrap_or(true),
            "private_param_usage" => self.private_param_usage.unwrap_or(false),
            _ => true,
        }
    }
}

/// Types of custom assertions that can be defined in the spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AssertionType {
    /// Assert that a named field exists in output records
    FieldSet,
    /// Assert that total input amount == total output amount
    AmountConserved,
    /// Assert that a named field is not Unknown or zero
    NoFieldNone,
    /// Assert that a numeric field value is within [min, max]
    RangeCheck,
}

/// A custom assertion definition from the spec file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionDef {
    /// The type of assertion
    #[serde(rename = "type")]
    pub assertion_type: AssertionType,
    /// Which function this assertion applies to
    pub function: String,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// Target field name (for field_set, no_field_none, range_check)
    #[serde(default)]
    pub field: Option<String>,
    /// Minimum value (for range_check)
    #[serde(default)]
    pub min: Option<i64>,
    /// Maximum value (for range_check)
    #[serde(default)]
    pub max: Option<i64>,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// Parser Entry Point
// ============================================================================

/// Parse a TOML invariant spec string into an `InvariantSpec`.
///
/// # Example
///
/// ```ignore
/// let content = r#"
/// [contract]
/// name = "token.aleo"
/// "#;
/// let spec = parse_spec(content).unwrap();
/// assert_eq!(spec.contract.name, "token.aleo");
/// ```
pub fn parse_spec(content: &str) -> Result<InvariantSpec, SpecError> {
    let spec: InvariantSpec = toml::from_str(content)?;
    Ok(spec)
}

/// Validate a spec against a contract, returning non-fatal warnings.
///
/// Checks:
/// - Contract name in spec matches `contract.program`
/// - Per-function overrides reference functions that exist in the contract
/// - Custom assertions reference functions that exist in the contract
pub fn validate_spec(spec: &InvariantSpec, contract: &Contract) -> Vec<String> {
    let mut warnings = Vec::new();

    if spec.contract.name != contract.program {
        warnings.push(format!(
            "spec contract name '{}' does not match contract program '{}'",
            spec.contract.name, contract.program
        ));
    }

    let func_names: std::collections::HashSet<&str> = contract
        .functions
        .iter()
        .map(|f| f.name.as_str())
        .collect();

    for func_name in spec.invariants.functions.keys() {
        if !func_names.contains(func_name.as_str()) {
            warnings.push(format!(
                "function '{}' in spec.invariants.functions not found in contract",
                func_name
            ));
        }
    }

    for assertion in &spec.assertions {
        if !func_names.contains(assertion.function.as_str()) {
            warnings.push(format!(
                "assertion references function '{}' not found in contract",
                assertion.function
            ));
        }
    }

    warnings
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------------------------
    // Parse Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_parse_minimal_spec() {
        let content = r#"
[contract]
name = "token.aleo"
"#;
        let spec = parse_spec(content).unwrap();
        assert_eq!(spec.contract.name, "token.aleo");
        assert!(spec.assertions.is_empty());
        // Toggles should all be None (unset)
        assert_eq!(spec.invariants.default.balance_conservation, None);
        assert_eq!(spec.invariants.default.owner_integrity, None);
        assert_eq!(spec.invariants.default.zero_amount, None);
        assert_eq!(spec.invariants.default.self_transfer, None);
        assert_eq!(spec.invariants.default.overflow_check, None);
    }

    #[test]
    fn test_parse_full_spec() {
        let content = r#"
[contract]
name = "token.aleo"

[invariants.default]
balance_conservation = true
owner_integrity = true
zero_amount = false
self_transfer = false
overflow_check = true

[invariants.functions.mint_private]
balance_conservation = false

[[assertions]]
type = "amount_conserved"
function = "transfer_private"
description = "Balance must be preserved"

[[assertions]]
type = "range_check"
function = "transfer_private"
field = "amount"
min = 1
max = 1000000
description = "Amount in valid range"
"#;
        let spec = parse_spec(content).unwrap();
        assert_eq!(spec.contract.name, "token.aleo");

        // Check default toggles
        assert_eq!(spec.invariants.default.balance_conservation, Some(true));
        assert_eq!(spec.invariants.default.zero_amount, Some(false));

        // Check per-function override
        let mint_toggle = spec.invariants.functions.get("mint_private").unwrap();
        assert_eq!(mint_toggle.balance_conservation, Some(false));
        // Only balance_conservation was overridden; others should be None
        assert_eq!(mint_toggle.owner_integrity, None);

        // Check assertions
        assert_eq!(spec.assertions.len(), 2);
        assert_eq!(spec.assertions[0].assertion_type, AssertionType::AmountConserved);
        assert_eq!(spec.assertions[0].function, "transfer_private");
        assert_eq!(spec.assertions[1].assertion_type, AssertionType::RangeCheck);
        assert_eq!(spec.assertions[1].field, Some("amount".to_string()));
        assert_eq!(spec.assertions[1].min, Some(1));
        assert_eq!(spec.assertions[1].max, Some(1000000));
    }

    #[test]
    fn test_parse_empty_invariants() {
        let content = r#"
[contract]
name = "empty.aleo"
"#;
        let spec = parse_spec(content).unwrap();
        // Should have no assertion and all defaults as None
        assert!(spec.assertions.is_empty());
        assert_eq!(spec.invariants.default.balance_conservation, None);
        assert!(spec.invariants.functions.is_empty());
    }

    #[test]
    fn test_parse_all_assertion_types() {
        let content = r#"
[contract]
name = "test.aleo"

[[assertions]]
type = "field_set"
function = "mint"
field = "amount"

[[assertions]]
type = "amount_conserved"
function = "transfer"

[[assertions]]
type = "no_field_none"
function = "transfer"
field = "owner"

[[assertions]]
type = "range_check"
function = "transfer"
field = "amount"
min = 1
"#;
        let spec = parse_spec(content).unwrap();
        assert_eq!(spec.assertions.len(), 4);
        assert_eq!(spec.assertions[0].assertion_type, AssertionType::FieldSet);
        assert_eq!(spec.assertions[1].assertion_type, AssertionType::AmountConserved);
        assert_eq!(spec.assertions[2].assertion_type, AssertionType::NoFieldNone);
        assert_eq!(spec.assertions[3].assertion_type, AssertionType::RangeCheck);
    }

    #[test]
    fn test_parse_invalid_toml() {
        let result = parse_spec("this is not valid toml {{{");
        assert!(result.is_err());
        match result.unwrap_err() {
            SpecError::Parse(_) => {} // expected
            _ => panic!("expected Parse error"),
        }
    }

    // --------------------------------------------------------------------------
    // Toggle Resolve Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_toggle_resolve_no_override() {
        let settings = InvariantSettings {
            default: InvariantToggle {
                balance_conservation: Some(true),
                zero_amount: Some(false),
                ..Default::default()
            },
            functions: HashMap::new(),
        };

        let resolved = settings.resolve("any_function");
        assert_eq!(resolved.balance_conservation, Some(true));
        assert_eq!(resolved.zero_amount, Some(false));
    }

    #[test]
    fn test_toggle_resolve_with_override() {
        let mut functions = HashMap::new();
        functions.insert(
            "mint_private".to_string(),
            InvariantToggle {
                balance_conservation: Some(false), // override: mint creates tokens
                ..Default::default()
            },
        );

        let settings = InvariantSettings {
            default: InvariantToggle {
                balance_conservation: Some(true),
                owner_integrity: Some(true),
                ..Default::default()
            },
            functions,
        };

        let resolved = settings.resolve("mint_private");
        // This function overrides balance_conservation
        assert_eq!(resolved.balance_conservation, Some(false));
        // But inherits owner_integrity from defaults
        assert_eq!(resolved.owner_integrity, Some(true));
    }

    #[test]
    fn test_toggle_resolve_partial_override() {
        // A function that only overrides zero_amount should inherit everything else
        let mut functions = HashMap::new();
        functions.insert(
            "transfer_private".to_string(),
            InvariantToggle {
                zero_amount: Some(true), // flag zero transfers
                ..Default::default()
            },
        );

        let settings = InvariantSettings {
            default: InvariantToggle {
                balance_conservation: Some(true),
                owner_integrity: Some(true),
                zero_amount: Some(false),
                overflow_check: Some(true),
                ..Default::default()
            },
            functions,
        };

        let resolved = settings.resolve("transfer_private");
        assert_eq!(resolved.balance_conservation, Some(true));
        assert_eq!(resolved.owner_integrity, Some(true));
        assert_eq!(resolved.zero_amount, Some(true)); // overridden
        assert_eq!(resolved.overflow_check, Some(true));
    }

    // --------------------------------------------------------------------------
    // is_enabled Tests
    // --------------------------------------------------------------------------

    #[test]
    fn test_is_enabled_defaults() {
        // All None = use hard-coded defaults
        let toggle = InvariantToggle::default();

        // Safety invariants default to true
        assert!(toggle.is_enabled("balance_conservation"));
        assert!(toggle.is_enabled("owner_integrity"));
        assert!(toggle.is_enabled("overflow_check"));

        // Informational invariants default to false
        assert!(!toggle.is_enabled("zero_amount"));
        assert!(!toggle.is_enabled("self_transfer"));

        // Unknown invariant names default to true
        assert!(toggle.is_enabled("some_unknown_check"));
    }

    #[test]
    fn test_is_enabled_explicit() {
        let toggle = InvariantToggle {
            balance_conservation: Some(false),
            zero_amount: Some(true),
            ..Default::default()
        };

        assert!(!toggle.is_enabled("balance_conservation"));
        assert!(toggle.is_enabled("zero_amount"));
        // owner_integrity inherits hard-coded default (true) because field is None
        assert!(toggle.is_enabled("owner_integrity"));
    }

    // --------------------------------------------------------------------------
    // validate_spec Tests
    // --------------------------------------------------------------------------

    fn make_test_contract() -> Contract {
        Contract {
            program: "token.aleo".to_string(),
            records: vec![],
            mappings: vec![],
            functions: vec![
                crate::parser::FunctionDef {
                    name: "mint_private".to_string(),
                    inputs: vec![],
                    outputs: vec![],
                },
                crate::parser::FunctionDef {
                    name: "transfer_private".to_string(),
                    inputs: vec![],
                    outputs: vec![],
                },
            ],
            finalizes: vec![],
        }
    }

    #[test]
    fn test_validate_spec_valid() {
        let spec = InvariantSpec {
            contract: ContractMeta {
                name: "token.aleo".to_string(),
            },
            invariants: InvariantSettings::default(),
            assertions: vec![AssertionDef {
                assertion_type: AssertionType::AmountConserved,
                function: "transfer_private".to_string(),
                description: "".to_string(),
                field: None,
                min: None,
                max: None,
            }],
        };

        let warnings = validate_spec(&spec, &make_test_contract());
        assert!(warnings.is_empty(), "expected no warnings, got {:?}", warnings);
    }

    #[test]
    fn test_validate_spec_name_mismatch() {
        let spec = InvariantSpec {
            contract: ContractMeta {
                name: "wrong.aleo".to_string(),
            },
            invariants: InvariantSettings::default(),
            assertions: vec![],
        };

        let warnings = validate_spec(&spec, &make_test_contract());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("does not match"));
    }

    #[test]
    fn test_validate_spec_unknown_function() {
        let mut functions = HashMap::new();
        functions.insert(
            "nonexistent_func".to_string(),
            InvariantToggle::default(),
        );
        let spec = InvariantSpec {
            contract: ContractMeta {
                name: "token.aleo".to_string(),
            },
            invariants: InvariantSettings {
                default: InvariantToggle::default(),
                functions,
            },
            assertions: vec![AssertionDef {
                assertion_type: AssertionType::FieldSet,
                function: "also_nonexistent".to_string(),
                description: "".to_string(),
                field: None,
                min: None,
                max: None,
            }],
        };

        let warnings = validate_spec(&spec, &make_test_contract());
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("nonexistent_func"));
        assert!(warnings[1].contains("also_nonexistent"));
    }
}
