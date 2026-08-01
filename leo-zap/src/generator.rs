//! # Random Input Generator
//!
//! Generates random but valid values for Aleo types.
//! Used by the fuzzer to create test inputs for contract functions.
//!
//! Supports: address, u8-u64, i8-i64, bool, field, group, records.
//! Includes edge cases (0, 1, max, min) for numeric types.

use crate::parser::{FunctionDef, Param, RecordDef};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Symbolic Values
// ============================================================================

/// A value tracked during symbolic execution of .aleo instructions.
/// Covers all Aleo types relevant to the fuzzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SymValue {
    /// An Aleo address: "aleo1..."
    Address(String),
    /// Unsigned integers
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    /// Signed integers
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    /// A boolean
    Bool(bool),
    /// A record with named fields
    Record {
        record_type: String,
        fields: HashMap<String, SymValue>,
    },
    /// A future (opaque — we can't inspect inside)
    Future(String),
    /// Placeholder for values we couldn't determine
    Unknown,
}

impl SymValue {
    /// Get the u64 value if this is a U64 variant
    pub fn as_u64(&self) -> Option<u64> {
        if let SymValue::U64(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    /// Get a record field by name
    pub fn get_field(&self, name: &str) -> Option<&SymValue> {
        if let SymValue::Record { fields, .. } = self {
            fields.get(name)
        } else {
            None
        }
    }

    /// Try to determine the "amount" of this value for balance tracking.
    /// For u64, returns the value. For records, returns the "amount" field.
    pub fn extract_amount(&self) -> Option<u64> {
        match self {
            SymValue::U64(v) => Some(*v),
            SymValue::Record { fields, .. } => {
                fields.get("amount").and_then(|v| v.as_u64())
            }
            _ => None,
        }
    }

    /// Format as a string suitable for display or leo execute input
    pub fn to_leo_string(&self) -> String {
        match self {
            SymValue::Address(a) => a.clone(),
            SymValue::U8(v) => format!("{}u8", v),
            SymValue::U16(v) => format!("{}u16", v),
            SymValue::U32(v) => format!("{}u32", v),
            SymValue::U64(v) => format!("{}u64", v),
            SymValue::U128(v) => format!("{}u128", v),
            SymValue::I8(v) => format!("{}i8", v),
            SymValue::I16(v) => format!("{}i16", v),
            SymValue::I32(v) => format!("{}i32", v),
            SymValue::I64(v) => format!("{}i64", v),
            SymValue::I128(v) => format!("{}i128", v),
            SymValue::Bool(v) => format!("{}", v),
            SymValue::Record {
                record_type,
                fields,
            } => {
                let mut parts: Vec<String> = fields
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_leo_string()))
                    .collect();
                // Include _nonce for proper record format
                parts.push("_nonce: 0group".to_string());
                format!("{} {{ {} }}", record_type, parts.join(", "))
            }
            SymValue::Future(s) => s.clone(),
            SymValue::Unknown => "<unknown>".to_string(),
        }
    }
}

// ============================================================================
// Input Generator
// ============================================================================

/// Configuration for the input generator
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// If true, mix in edge cases (0, max, min) alongside random values
    pub include_edge_cases: bool,
    /// Probability (0.0-1.0) of using an edge case instead of random
    pub edge_case_ratio: f64,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            include_edge_cases: true,
            edge_case_ratio: 0.05, // 5% edge cases
        }
    }
}

/// Generates random Aleo values for fuzzing contract functions.
pub struct InputGenerator {
    rng: StdRng,
    config: GeneratorConfig,
}

impl InputGenerator {
    /// Create a new generator with the given seed for reproducibility.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            config: GeneratorConfig::default(),
        }
    }

    /// Create a new generator with custom config.
    pub fn with_config(seed: u64, config: GeneratorConfig) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            config,
        }
    }

    /// Generate inputs for all parameters of a function.
    /// Returns pairs of (register_name, SymValue) for each input parameter.
    pub fn generate_inputs(
        &mut self,
        func: &FunctionDef,
        records: &[RecordDef],
    ) -> Vec<(String, SymValue)> {
        func.inputs
            .iter()
            .map(|param| {
                let value = self.gen_param_value(param, records);
                (param.register.clone(), value)
            })
            .collect()
    }

    /// Generate a value for a single function parameter.
    fn gen_param_value(&mut self, param: &Param, records: &[RecordDef]) -> SymValue {
        // If the type is a record reference (e.g., "token.record"), generate a record
        if param.ty.ends_with(".record") {
            let record_name = param.ty.trim_end_matches(".record");
            // Find the record definition
            if let Some(record_def) = records.iter().find(|r| r.name == record_name) {
                return self.gen_record(record_def);
            }
            // If no matching definition, fall back to generating by name
            return self.gen_record_by_name(record_name);
        }

        // If the type is a future reference, generate a placeholder
        if param.ty.contains(".future") {
            return SymValue::Future(param.ty.clone());
        }

        // Otherwise, generate based on the base type
        self.gen_scalar(&param.ty)
    }

    /// Generate a record value from a record definition.
    pub fn gen_record(&mut self, record_def: &RecordDef) -> SymValue {
        let mut fields = HashMap::new();
        for field in &record_def.fields {
            let value = self.gen_scalar(&field.ty);
            fields.insert(field.name.clone(), value);
        }
        SymValue::Record {
            record_type: record_def.name.clone(),
            fields,
        }
    }

    /// Generate a record value by name (when definition is unknown).
    fn gen_record_by_name(&mut self, name: &str) -> SymValue {
        let mut fields = HashMap::new();
        // Guess common fields based on contract patterns
        fields.insert("owner".to_string(), self.gen_address());
        fields.insert("amount".to_string(), self.gen_u64());
        SymValue::Record {
            record_type: name.to_string(),
            fields,
        }
    }

    /// Generate a scalar value for a given type string.
    pub fn gen_scalar(&mut self, ty: &str) -> SymValue {
        // Maybe use an edge case
        if self.config.include_edge_cases && self.rng.gen::<f64>() < self.config.edge_case_ratio {
            if let Some(edge) = self.gen_edge_case(ty) {
                return edge;
            }
        }

        match ty {
            "address" => self.gen_address(),
            "u8" => SymValue::U8(self.rng.gen::<u8>()),
            "u16" => SymValue::U16(self.rng.gen::<u16>()),
            "u32" => SymValue::U32(self.rng.gen::<u32>()),
            "u64" => self.gen_u64(),
            "u128" => SymValue::U128(self.rng.gen::<u128>()),
            "i8" => SymValue::I8(self.rng.gen::<i8>()),
            "i16" => SymValue::I16(self.rng.gen::<i16>()),
            "i32" => SymValue::I32(self.rng.gen::<i32>()),
            "i64" => SymValue::I64(self.rng.gen::<i64>()),
            "i128" => SymValue::I128(self.rng.gen::<i128>()),
            "bool" => SymValue::Bool(self.rng.gen::<bool>()),
            "field" => {
                // Generate a random field element (as hex)
                let bytes: [u8; 32] = self.rng.gen();
                SymValue::U128(u128::from_le_bytes(bytes[..16].try_into().unwrap()))
                    // Fall back to u64 for simplicity in fuzzing
            }
            "group" => {
                // Generate a random group element placeholder
                SymValue::U128(self.rng.gen::<u128>())
            }
            // For unknown types, try to match patterns
            _ if ty.contains("address") => self.gen_address(),
            _ if ty.contains("u64") => self.gen_u64(),
            _ if ty.contains("u32") => SymValue::U32(self.rng.gen()),
            _ if ty.contains("u16") => SymValue::U16(self.rng.gen()),
            _ if ty.contains("u8") => SymValue::U8(self.rng.gen()),
            _ => SymValue::U64(self.rng.gen::<u64>()), // default for unknown
        }
    }

    /// Generate edge cases for a given type.
    fn gen_edge_case(&mut self, ty: &str) -> Option<SymValue> {
        let cases: &[SymValue] = match ty {
            "u8" => &[
                SymValue::U8(0),
                SymValue::U8(1),
                SymValue::U8(u8::MAX),
                SymValue::U8(u8::MAX - 1),
            ],
            "u16" => &[
                SymValue::U16(0),
                SymValue::U16(1),
                SymValue::U16(u16::MAX),
                SymValue::U16(u16::MAX - 1),
            ],
            "u32" => &[
                SymValue::U32(0),
                SymValue::U32(1),
                SymValue::U32(u32::MAX),
                SymValue::U32(u32::MAX - 1),
            ],
            "u64" => &[
                SymValue::U64(0),
                SymValue::U64(1),
                SymValue::U64(u64::MAX),
                SymValue::U64(u64::MAX - 1),
                SymValue::U64(u64::MAX / 2),
            ],
            "u128" => &[
                SymValue::U128(0),
                SymValue::U128(1),
                SymValue::U128(u128::MAX),
                SymValue::U128(u128::MAX - 1),
            ],
            "i8" => &[
                SymValue::I8(0),
                SymValue::I8(1),
                SymValue::I8(-1),
                SymValue::I8(i8::MAX),
                SymValue::I8(i8::MIN),
            ],
            "i16" => &[
                SymValue::I16(0),
                SymValue::I16(1),
                SymValue::I16(-1),
                SymValue::I16(i16::MAX),
                SymValue::I16(i16::MIN),
            ],
            "i32" => &[
                SymValue::I32(0),
                SymValue::I32(1),
                SymValue::I32(-1),
                SymValue::I32(i32::MAX),
                SymValue::I32(i32::MIN),
            ],
            "i64" => &[
                SymValue::I64(0),
                SymValue::I64(1),
                SymValue::I64(-1),
                SymValue::I64(i64::MAX),
                SymValue::I64(i64::MIN),
            ],
            "i128" => &[
                SymValue::I128(0),
                SymValue::I128(1),
                SymValue::I128(-1),
                SymValue::I128(i128::MAX),
                SymValue::I128(i128::MIN),
            ],
            "bool" => &[SymValue::Bool(true), SymValue::Bool(false)],
            _ => return None,
        };
        let idx = self.rng.gen_range(0..cases.len());
        Some(cases[idx].clone())
    }

    /// Generate a random Aleo address.
    /// Aleo addresses are bech32m encoded: "aleo1" + 51 base58 characters.
    fn gen_address(&mut self) -> SymValue {
        // Generate 32 random bytes to simulate the address data
        let bytes: [u8; 32] = self.rng.gen();
        // Simple base58-like encoding (lowercase alphanumeric for display)
        const CHARS: &[u8] = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
        let mut encoded = String::with_capacity(51);
        // Map bytes to charset for a valid-looking address
        for i in 0..51 {
            let idx = (bytes[i % 32] as usize + i * 7) % CHARS.len();
            encoded.push(CHARS[idx] as char);
        }
        SymValue::Address(format!("aleo1{}", encoded))
    }

    /// Generate a random u64, with occasional edge values.
    fn gen_u64(&mut self) -> SymValue {
        SymValue::U64(self.rng.gen::<u64>())
    }

    /// Generate a specific u64 value (for testing).
    pub fn gen_specific_u64(&self, val: u64) -> SymValue {
        SymValue::U64(val)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{FunctionDef, Param, RecordDef, RecordField, Visibility};

    fn make_record_def() -> RecordDef {
        RecordDef {
            name: "token".to_string(),
            fields: vec![
                RecordField {
                    name: "owner".to_string(),
                    ty: "address".to_string(),
                    visibility: Visibility::Private,
                },
                RecordField {
                    name: "amount".to_string(),
                    ty: "u64".to_string(),
                    visibility: Visibility::Private,
                },
            ],
        }
    }

    fn make_function(name: &str, inputs: Vec<Param>) -> FunctionDef {
        FunctionDef {
            name: name.to_string(),
            inputs,
            outputs: vec![],
        }
    }

    #[test]
    fn test_gen_address() {
        let mut gen = InputGenerator::new(42);
        let addr = gen.gen_address();
        match &addr {
            SymValue::Address(a) => {
                assert!(a.starts_with("aleo1"), "Address should start with aleo1: {}", a);
                assert_eq!(a.len(), 56, "Address should be 56 chars (aleo1 + 51 base58): {}", a.len());
            }
            _ => panic!("Expected Address, got {:?}", addr),
        }
    }

    #[test]
    fn test_gen_u64() {
        let mut gen = InputGenerator::new(42);
        let val = gen.gen_u64();
        assert!(matches!(val, SymValue::U64(_)));
    }

    #[test]
    fn test_gen_record() {
        let mut gen = InputGenerator::new(42);
        let record_def = make_record_def();
        let record = gen.gen_record(&record_def);
        match &record {
            SymValue::Record {
                record_type, fields, ..
            } => {
                assert_eq!(record_type, "token");
                assert!(fields.contains_key("owner"));
                assert!(fields.contains_key("amount"));
                match fields.get("owner").unwrap() {
                    SymValue::Address(a) => assert!(a.starts_with("aleo1")),
                    _ => panic!("owner should be Address"),
                }
                match fields.get("amount").unwrap() {
                    SymValue::U64(_) => {}
                    _ => panic!("amount should be U64"),
                }
            }
            _ => panic!("Expected Record, got {:?}", record),
        }
    }

    #[test]
    fn test_gen_inputs_for_function() {
        let mut gen = InputGenerator::new(42);
        let records = vec![make_record_def()];

        let func = make_function(
            "transfer_private",
            vec![
                Param {
                    register: "r0".to_string(),
                    ty: "token.record".to_string(),
                    visibility: Visibility::None,
                },
                Param {
                    register: "r1".to_string(),
                    ty: "address".to_string(),
                    visibility: Visibility::Private,
                },
                Param {
                    register: "r2".to_string(),
                    ty: "u64".to_string(),
                    visibility: Visibility::Private,
                },
            ],
        );

        let inputs = gen.generate_inputs(&func, &records);
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0].0, "r0");
        assert!(matches!(inputs[0].1, SymValue::Record { .. }));
        assert_eq!(inputs[1].0, "r1");
        assert!(matches!(inputs[1].1, SymValue::Address(_)));
        assert_eq!(inputs[2].0, "r2");
        assert!(matches!(inputs[2].1, SymValue::U64(_)));
    }

    #[test]
    fn test_deterministic_output() {
        let mut gen1 = InputGenerator::new(12345);
        let mut gen2 = InputGenerator::new(12345);

        let val1 = gen1.gen_u64();
        let val2 = gen2.gen_u64();
        assert_eq!(val1, val2, "Same seed should produce same output");
    }

    #[test]
    fn test_different_seed_different_output() {
        let mut gen1 = InputGenerator::new(42);
        let mut gen2 = InputGenerator::new(99);

        // Collect 10 values from each
        let vals1: Vec<_> = (0..10).map(|_| gen1.gen_u64()).collect();
        let vals2: Vec<_> = (0..10).map(|_| gen2.gen_u64()).collect();
        assert_ne!(vals1, vals2, "Different seeds should produce different output");
    }

    #[test]
    fn test_edge_cases_included() {
        let mut gen = InputGenerator::with_config(
            42,
            GeneratorConfig {
                include_edge_cases: true,
                edge_case_ratio: 1.0, // always use edge cases
            },
        );

        // Generate several u64 values — should all be edge cases
        for _ in 0..20 {
            let val = gen.gen_scalar("u64");
            if let SymValue::U64(v) = val {
                assert!(
                    v == 0 || v == 1 || v == u64::MAX || v == u64::MAX - 1 || v == u64::MAX / 2,
                    "Expected edge case, got {}",
                    v
                );
            }
        }
    }

    #[test]
    fn test_edge_cases_disabled() {
        let mut gen = InputGenerator::with_config(
            42,
            GeneratorConfig {
                include_edge_cases: false,
                ..Default::default()
            },
        );

        // With edge cases disabled, all values should be random (extremely unlikely to hit only edges)
        let mut found_non_edge = false;
        for _ in 0..100 {
            let val = gen.gen_scalar("u64");
            if let SymValue::U64(v) = val {
                if v != 0 && v != 1 && v != u64::MAX && v != u64::MAX - 1 && v != u64::MAX / 2 {
                    found_non_edge = true;
                    break;
                }
            }
        }
        assert!(found_non_edge, "Should find non-edge values when edge cases disabled");
    }

    #[test]
    fn test_sym_value_to_leo_string() {
        assert_eq!(
            SymValue::U64(100).to_leo_string(),
            "100u64"
        );
        assert_eq!(
            SymValue::U32(42).to_leo_string(),
            "42u32"
        );
        assert_eq!(
            SymValue::I64(-5).to_leo_string(),
            "-5i64"
        );
        assert_eq!(
            SymValue::Bool(true).to_leo_string(),
            "true"
        );

        let addr = SymValue::Address("aleo1abc123".to_string());
        assert_eq!(addr.to_leo_string(), "aleo1abc123");
    }

    #[test]
    fn test_sym_value_extract_amount() {
        assert_eq!(SymValue::U64(100).extract_amount(), Some(100));

        let mut fields = HashMap::new();
        fields.insert("owner".to_string(), SymValue::Address("aleo1test".to_string()));
        fields.insert("amount".to_string(), SymValue::U64(500));
        let record = SymValue::Record {
            record_type: "token".to_string(),
            fields,
        };
        assert_eq!(record.extract_amount(), Some(500));

        // Record without amount field
        let fields2 = HashMap::new();
        let record2 = SymValue::Record {
            record_type: "token".to_string(),
            fields: fields2,
        };
        assert_eq!(record2.extract_amount(), None);
    }

    #[test]
    fn test_gen_future_param() {
        let mut gen = InputGenerator::new(42);
        let param = Param {
            register: "r0".to_string(),
            ty: "token.aleo/mint_public.future".to_string(),
            visibility: Visibility::None,
        };
        let val = gen.gen_param_value(&param, &[]);
        match val {
            SymValue::Future(s) => assert!(s.contains(".future"), "Future should contain .future"),
            _ => panic!("Expected Future, got {:?}", val),
        }
    }
}
