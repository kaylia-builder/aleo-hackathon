//! # Web Dashboard Server
//!
//! Axum-based web server providing a browser UI for LeoZap.
//! Users configure fuzz parameters in a web form, the fuzzer runs
//! in the background, and results stream to the browser via SSE.
//!
//! ## Architecture
//! - `POST /api/fuzz` — start a fuzz run, returns `{run_id}`
//! - `GET /api/fuzz/:id/events` — SSE stream of FuzzEvent objects
//! - `GET /api/fuzz/:id/report` — final FuzzReport JSON
//! - `GET /` — dashboard HTML page

use crate::fuzzer::{self, FuzzConfig, FuzzReport};
use crate::parser;
use crate::spec;
use crate::web_templates::DASHBOARD_HTML;
use axum::{
    extract::{Path, State},
    response::{sse::{Event, Sse}, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

// ============================================================================
// Request / Response Types
// ============================================================================

/// Incoming fuzz request from the web UI form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRequest {
    pub file_path: String,
    pub spec_path: Option<String>,
    pub project_dir: Option<String>,
    pub source_dir: Option<String>,
    pub runs: u32,
    pub seed: u64,
    pub function_filter: Option<String>,
    pub verify_all: bool,
}

/// Events streamed to the browser during a fuzz run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FuzzEvent {
    /// Fuzz run has started
    #[serde(rename = "started")]
    Started { run_id: String, total_runs: u32 },
    /// A single iteration completed
    #[serde(rename = "iteration")]
    Iteration {
        iteration: u32,
        function: String,
        outcome: String,     // "pass" or "violation"
        detail: Option<String>,
        passed: u32,
        violations: u32,
    },
    /// ZK verification performed for an iteration
    #[serde(rename = "zk_verification")]
    ZkVerification {
        iteration: u32,
        function: String,
        proof_generated: bool,
        mismatch: bool,
        mismatch_detail: Option<String>,
        total_zk_proofs: u32,
        total_zk_mismatches: u32,
    },
    /// Periodic progress snapshot (every 10 iterations)
    #[serde(rename = "progress")]
    Progress {
        per_function: Vec<(String, u32, u32, u32)>,
    },
    /// Fuzz run completed successfully
    #[serde(rename = "complete")]
    Complete { report: FuzzReport },
    /// Fuzz run failed with an error
    #[serde(rename = "error")]
    Error { message: String },
}

// ============================================================================
// Shared State
// ============================================================================

/// Per-run session: stores events and provides streaming to clients
struct RunSession {
    /// All events emitted so far (replayed to new SSE clients)
    events: std::sync::Mutex<Vec<FuzzEvent>>,
    /// Broadcast channel for live events (new clients subscribe after replay)
    tx: broadcast::Sender<FuzzEvent>,
    /// Whether the fuzz run has completed
    completed: std::sync::Mutex<bool>,
}

/// Global server state
struct AppState {
    sessions: Mutex<HashMap<String, Arc<RunSession>>>,
}

// ============================================================================
// Route Handlers
// ============================================================================

/// `GET /` — serve the dashboard HTML page
async fn serve_dashboard() -> axum::response::Html<&'static str> {
    axum::response::Html(DASHBOARD_HTML)
}

/// `POST /api/fuzz` — start a new fuzz run
async fn start_fuzz(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FuzzRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let run_id = uuid::Uuid::new_v4().to_string();

    // Create broadcast channel for this run
    let (tx, _rx) = broadcast::channel::<FuzzEvent>(512);
    let session = Arc::new(RunSession {
        events: std::sync::Mutex::new(Vec::new()),
        tx: tx.clone(),
        completed: std::sync::Mutex::new(false),
    });

    // Store session
    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(run_id.clone(), session.clone());
    }

    // Spawn background fuzz task
    let session_clone = session.clone();
    let state_clone = state.clone();
    let run_id_clone = run_id.clone();
    tokio::task::spawn_blocking(move || {
        run_fuzz_background(&run_id_clone, req, session_clone, state_clone);
    });

    Ok(Json(serde_json::json!({ "run_id": run_id })))
}

/// `GET /api/fuzz/:id/events` — SSE stream for a fuzz run.
/// Since fuzz runs complete quickly, we poll for completion then replay all stored events.
async fn fuzz_events(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, (axum::http::StatusCode, String)> {
    // Wait for fuzz to complete (with timeout)
    let session = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&run_id)
            .cloned()
            .ok_or_else(|| {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    format!("run {} not found ({} active sessions)", run_id, sessions.len()),
                )
            })?
    };
    // Drop the sessions lock so we don't deadlock
    drop(state);

    // Poll until complete or timeout (max ~30 seconds)
    for _ in 0..300 {
        if *session.completed.lock().unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Replay all stored events
    let stored_events = session.events.lock().unwrap().clone();
    let stream = tokio_stream::iter(stored_events.into_iter().map(|event| {
        let json = serde_json::to_string(&event).unwrap_or_default();
        Ok(Event::default().data(json))
    }));
    Ok(Sse::new(stream))
}

/// `GET /api/fuzz/:id/report` — get final report for a completed run
async fn fuzz_report(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<FuzzReport>, (axum::http::StatusCode, String)> {
    // The report is only available via the SSE stream completion event.
    // For simplicity, we return an error if the session is still active.
    let sessions = state.sessions.lock().await;
    if sessions.contains_key(&run_id) {
        Err((
            axum::http::StatusCode::CONFLICT,
            "Run still in progress. Wait for the SSE stream to complete.".to_string(),
        ))
    } else {
        Err((
            axum::http::StatusCode::NOT_FOUND,
            "Run not found or already cleaned up. Reports are delivered via SSE.".to_string(),
        ))
    }
}

// ============================================================================
// Background Fuzz Runner
// ============================================================================

/// Run the fuzzer synchronously in a background thread, pushing events to the broadcast channel.
fn run_fuzz_background(
    run_id: &str,
    req: FuzzRequest,
    session: Arc<RunSession>,
    app_state: Arc<AppState>,
) {
    /// Helper: send event via broadcast AND store in session for replay
    fn emit(session: &RunSession, event: FuzzEvent) {
        let _ = session.tx.send(event.clone());
        session.events.lock().unwrap().push(event);
    }

    emit(&session, FuzzEvent::Started {
        run_id: run_id.to_string(),
        total_runs: req.runs,
    });

    // If source_dir is set, auto-compile first
    let aleo_path = if let Some(ref src_dir) = req.source_dir {
        let src_path = std::path::PathBuf::from(src_dir);
        match crate::leo_compiler::build_project(&src_path) {
            Ok(path) => path,
            Err(e) => {
                emit(&session, FuzzEvent::Error {
                    message: format!("leo build failed: {}", e),
                });
                cleanup_session(run_id, &app_state);
                return;
            }
        }
    } else {
        std::path::PathBuf::from(&req.file_path)
    };

    // Read .aleo file
    let content = match std::fs::read_to_string(&aleo_path) {
        Ok(c) => c,
        Err(e) => {
            emit(&session, FuzzEvent::Error {
                message: format!("Failed to read {}: {}", aleo_path.display(), e),
            });
            cleanup_session(run_id, &app_state);
            return;
        }
    };

    // Parse contract
    let contract = match parser::parse(&content) {
        Ok(c) => c,
        Err(e) => {
            emit(&session, FuzzEvent::Error {
                message: format!("Failed to parse contract: {}", e),
            });
            cleanup_session(run_id, &app_state);
            return;
        }
    };

    // Parse spec if provided
    let spec = match &req.spec_path {
        Some(path) if !path.is_empty() => {
            match std::fs::read_to_string(path) {
                Ok(spec_content) => match spec::parse_spec(&spec_content) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        emit(&session, FuzzEvent::Error {
                            message: format!("Failed to parse spec: {}", e),
                        });
                        cleanup_session(run_id, &app_state);
                        return;
                    }
                },
                Err(e) => {
                    emit(&session, FuzzEvent::Error {
                        message: format!("Failed to read spec {}: {}", path, e),
                    });
                    cleanup_session(run_id, &app_state);
                    return;
                }
            }
        }
        _ => None,
    };

    // Determine seed
    let seed = if req.seed == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(42)
    } else {
        req.seed
    };

    // Build config — treat empty strings as None
    let function_filter = req.function_filter
        .filter(|s| !s.is_empty());
    let project_dir = req.project_dir
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    let config = FuzzConfig {
        runs: req.runs,
        seed,
        function_filter,
        include_edge_cases: true,
        spec: spec.clone(),
        project_dir,
        verify_all_with_leo: req.verify_all,
        source_dir: req.source_dir.map(std::path::PathBuf::from),
    };

    let raw_content = content.clone();

    // Run the fuzzer synchronously with event emission
    let report = run_fuzz_with_events(&config, &contract, &raw_content, &session);

    // Mark complete and send final report
    *session.completed.lock().unwrap() = true;
    emit(&session, FuzzEvent::Complete { report });
}

/// Run the fuzzer with per-iteration event callbacks.
/// Replicates the core loop from FuzzRunner::fuzz_function but emits events.
fn run_fuzz_with_events(
    config: &FuzzConfig,
    contract: &parser::Contract,
    raw_content: &str,
    session: &RunSession,
) -> FuzzReport {
    // Helper to emit event (defined inside the free function — reuse the pattern)
    let emit = |event: FuzzEvent| {
        let _ = session.tx.send(event.clone());
        session.events.lock().unwrap().push(event);
    };
    let mut report = FuzzReport {
        config: config.clone(),
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
            coverage_pct: 0.0,
    };

    let functions: Vec<&parser::FunctionDef> = if let Some(ref filter) = config.function_filter {
        contract.functions.iter().filter(|f| f.name == *filter).collect()
    } else {
        contract.functions.iter().collect()
    };

    let func_count = functions.len().max(1) as u32;
    let runs_per_func = config.runs / func_count;
    let remainder = config.runs % func_count;

    let mut gen = crate::generator::InputGenerator::new(config.seed);
    let mut iteration = 0u32;

    for (fi, func) in functions.iter().enumerate() {
        let extra = if (fi as u32) < remainder { 1 } else { 0 };
        let func_runs = runs_per_func + extra;

        let involves_record = func.inputs.iter().any(|p| p.ty.contains("record"))
            || func.outputs.iter().any(|p| p.ty.contains("record"));

        for _ in 0..func_runs {
            iteration += 1;
            report.total_runs += 1;

            let inputs = gen.generate_inputs(func, &contract.records);
            let input_strings: Vec<String> =
                inputs.iter().map(|(_, v)| v.to_leo_string()).collect();

            let body_instructions =
                fuzzer::FuzzRunner::extract_instructions_from_content(raw_content, &func.name);

            // Symbolic execution
            let mut state = fuzzer::SymbolicState::with_inputs(inputs.clone());
            let mut all_violations = Vec::new();

            for inst in &body_instructions {
                let inst_violations =
                    fuzzer::execute_instruction(inst, &mut state, &func.name, &contract.records);
                all_violations.extend(inst_violations);
            }

            if let Some(inv_violations) = crate::invariants::check_function_invariants(
                func, &state, contract, config.spec.as_ref(),
            ) {
                all_violations.extend(inv_violations);
            }

            let symbolic_pass = all_violations.is_empty();

            // ZK verification
            let should_verify = config.project_dir.is_some() && (
                config.verify_all_with_leo || !symbolic_pass || involves_record
            );

            if should_verify {
                if let Some(ref project_dir) = config.project_dir {
                    if let Some(leo_result) = crate::leo_runner::run_leo_function(
                        project_dir,
                        &func.name,
                        &input_strings,
                    ) {
                        report.zk_verifications += 1;
                        if leo_result.proof_generated {
                            report.zk_proofs_generated += 1;
                        }

                        let mismatches = crate::leo_runner::compare_results(
                            symbolic_pass,
                            &all_violations,
                            &leo_result,
                        );

                        let has_mismatch = !mismatches.is_empty();
                        let mismatch_detail = mismatches.first().map(|m| m.detail.clone());

                        if has_mismatch {
                            report.zk_mismatches += 1;
                            report.zk_mismatch_details.extend(mismatches.clone());

                            for m in &mismatches {
                                report.violation_results.push(fuzzer::FuzzResult {
                                    function: func.name.clone(),
                                    inputs: inputs.clone(),
                                    input_strings: input_strings.clone(),
                                    outcome: fuzzer::FuzzOutcome::Violation {
                                        invariant: format!("zk_mismatch:{:?}", m.kind),
                                        detail: m.detail.clone(),
                                    },
                                });
                            }
                            report.violations += 1;
                        }

                        emit(FuzzEvent::ZkVerification {
                            iteration,
                            function: func.name.clone(),
                            proof_generated: leo_result.proof_generated,
                            mismatch: has_mismatch,
                            mismatch_detail,
                            total_zk_proofs: report.zk_proofs_generated,
                            total_zk_mismatches: report.zk_mismatches,
                        });

                        if has_mismatch {
                            // Already counted as violation, skip normal pass/violation counting
                            continue;
                        }
                    }
                }
            }

            // Count result
            if symbolic_pass {
                report.passed += 1;
            } else {
                report.violations += 1;
                let detail = all_violations.join("; ");
                report.violation_results.push(fuzzer::FuzzResult {
                    function: func.name.clone(),
                    inputs: inputs.clone(),
                    input_strings: input_strings.clone(),
                    outcome: fuzzer::FuzzOutcome::Violation {
                        invariant: "symbolic".to_string(),
                        detail: detail.clone(),
                    },
                });
            }

            emit(FuzzEvent::Iteration {
                iteration,
                function: func.name.clone(),
                outcome: if symbolic_pass { "pass".to_string() } else { "violation".to_string() },
                detail: if symbolic_pass { None } else { Some(all_violations.join("; ")) },
                passed: report.passed,
                violations: report.violations,
            });

            // Send periodic progress
            if iteration % 10 == 0 {
                let per_func: Vec<(String, u32, u32, u32)> = report
                    .per_function
                    .iter()
                    .cloned()
                    .collect();
                emit(FuzzEvent::Progress { per_function: per_func });
            }
        }

        // Update per-function stats
        let func_passed = report.passed;
        let func_violations = report.violations;
        report.per_function.push((
            func.name.clone(),
            func_runs,
            func_passed.saturating_sub(report.per_function.iter().map(|f| f.2).sum()),
            func_violations.saturating_sub(report.per_function.iter().map(|f| f.3).sum()),
        ));
    }

    report
}

/// Remove a session from the global state
fn cleanup_session(run_id: &str, state: &Arc<AppState>) {
    let state = state.clone();
    let run_id = run_id.to_string();
    tokio::task::spawn(async move {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&run_id);
    });
}

// ============================================================================
// Server Entry Point
// ============================================================================

/// Start the LeoZap web dashboard server.
/// Blocks until the server exits.
pub async fn start_server(port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/fuzz", axum::routing::post(start_fuzz))
        .route("/api/fuzz/:id/events", get(fuzz_events))
        .route("/api/fuzz/:id/report", get(fuzz_report))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("");
    println!("  \u{1f981}  LeoZap Dashboard ready at http://localhost:{}", port);
    println!("  \u{1f512}  Open your browser and start fuzzing Aleo contracts");
    println!("");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
