//! # LeoZap Core
//!
//! Pure fuzzer engine for Aleo `.aleo` contracts.
//! No external tool dependencies (no `leo` CLI, no `snarkvm`).
//!
//! This library is designed to be compiled to both native and WASM targets.
//!
//! ## Modules
//! - `parser` — parse `.aleo` contract structure
//! - `generator` — random input generation with coverage-guided corpus
//! - `fuzzer` — symbolic execution engine + fuzz runner
//! - `invariants` — privacy and safety invariant checks
//! - `spec` — TOML invariant spec file parsing

pub mod parser;
pub mod generator;
pub mod fuzzer;
pub mod invariants;
pub mod spec;
