// =============================================================================
// LeoZap Web UI — Client-side fuzzer with WASM + optional server fallback
// =============================================================================

// --- State ---
let charts = {};
let eventSource = null;
let currentRunId = null;
let wasmModule = null;
let useWasm = false;
let running = false;
let uploadedContent = null;
let uploadedFileName = null;

const $ = (id) => document.getElementById(id);

// --- Mode detection ---
function setMode(mode) {
  const badge = $('mode-badge');
  if (mode === 'wasm') {
    useWasm = true;
    badge.textContent = '⚡ WASM (in-browser)';
    badge.className = 'mode-badge mode-wasm';
    // Enable file upload, disable server-only fields
    $('source-dir').disabled = true;
    $('project-dir').disabled = true;
    $('verify-all').disabled = true;
  } else if (mode === 'server') {
    useWasm = false;
    badge.textContent = '🌐 Server Mode';
    badge.className = 'mode-badge mode-server';
    $('source-dir').disabled = false;
    $('project-dir').disabled = false;
    $('verify-all').disabled = false;
  } else {
    badge.textContent = 'JS Fallback';
    badge.className = 'mode-badge';
  }
}

// Try to load WASM module
async function initWasm() {
  try {
    const wasm = await import('./leo_zap_wasm.js');
    await wasm.default();
    wasmModule = wasm;
    setMode('wasm');
    addLog('<span class="pass">⚡ WASM module loaded — fuzzing runs in-browser (no server needed)</span>');
  } catch (e) {
    console.warn('WASM not available, trying server mode:', e.message);
    // Try to detect if there's a server on the same origin
    try {
      const resp = await fetch('/api/fuzz', { method: 'HEAD' });
      if (resp.ok || resp.status === 405) { // 405 = method not allowed (HEAD not supported by POST endpoint)
        setMode('server');
        addLog('<span style="color:var(--yellow)">🌐 Connected to server backend</span>');
        return;
      }
    } catch (_) {}
    setMode('fallback');
    addLog('<span style="color:var(--dim)">ℹ️ No WASM and no server detected. Upload .aleo files directly for local processing.</span>');
  }
}

// --- UI Helpers ---
function setStatus(state, text) {
  const dot = $('status-indicator').querySelector('.status-dot');
  dot.className = 'status-dot dot-' + state;
  $('status-indicator').lastChild.textContent = ' ' + text;
}

function addLog(html) {
  const container = $('log-container');
  container.innerHTML += '<div class="log-entry">' + html + '</div>';
  container.scrollTop = container.scrollHeight;
}

function formatIter(i, total) {
  return '#' + String(i).padStart(String(total).length, '0');
}

function updateStat(id, val) {
  $(id).textContent = val;
  $(id).style.transform = 'scale(1.1)';
  setTimeout(() => { $(id).style.transform = 'scale(1)'; }, 150);
}

function updateProgressBars(perFunction) {
  const container = $('progress-bars');
  container.innerHTML = '';
  for (const [name, total, passed, violations] of perFunction) {
    const passPct = total > 0 ? (passed / total * 100).toFixed(0) : 0;
    container.innerHTML += `
      <div class="progress-bar-wrap">
        <div class="progress-bar-label">
          <span style="color:var(--purple)">${name}</span>
          <span>${passed}/${total} <span style="color:var(--green)">(${passPct}%)</span></span>
        </div>
        <div class="progress-bar-track">
          <div class="progress-bar-fill fill-pass" style="width:${passPct}%"></div>
        </div>
      </div>`;
  }
}

function renderCharts(report) {
  $('charts-section').style.display = '';
  $('zk-highlight').style.display = '';

  const ctx1 = $('chart-donut').getContext('2d');
  if (charts.donut) charts.donut.destroy();
  charts.donut = new Chart(ctx1, {
    type: 'doughnut',
    data: {
      labels: ['Passed', 'Violations', 'Errors'],
      datasets: [{
        data: [report.passed, report.violations, report.errors],
        backgroundColor: ['#3fb950', '#f85149', '#d2991d'],
        borderColor: '#0d1117',
        borderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { position: 'bottom', labels: { color: '#c9d1d9', font: { size: 12 } } } }
    }
  });

  const ctx2 = $('chart-bar').getContext('2d');
  if (charts.bar) charts.bar.destroy();
  const funcNames = report.per_function.map(f => f[0]);
  const funcPassed = report.per_function.map(f => f[2]);
  const funcViolations = report.per_function.map(f => f[3]);
  charts.bar = new Chart(ctx2, {
    type: 'bar',
    data: {
      labels: funcNames,
      datasets: [
        { label: 'Passed', data: funcPassed, backgroundColor: '#3fb950' },
        { label: 'Violations', data: funcViolations, backgroundColor: '#f85149' },
      ]
    },
    options: {
      responsive: true,
      scales: { x: { stacked: true, ticks: { color: '#8b949e' } }, y: { stacked: true, ticks: { color: '#8b949e' } } },
      plugins: { legend: { labels: { color: '#c9d1d9', font: { size: 12 } } } }
    }
  });

  $('zk-verify-count').textContent = report.zk_verifications || 0;
  $('zk-mismatch-count').textContent = report.zk_mismatches || 0;
}

function resetUI() {
  updateStat('stat-passed', '—');
  updateStat('stat-violations', '—');
  updateStat('stat-zk-proofs', '—');
  updateStat('stat-mismatches', '—');
  $('progress-section').style.display = 'none';
  $('charts-section').style.display = 'none';
  $('zk-highlight').style.display = 'none';
  $('log-container').innerHTML = '<div class="log-entry"><span class="iter">—</span>Starting fuzz run...</div>';
  Object.values(charts).forEach(c => c.destroy());
  charts = {};
}

// =============================================================================
// WASM Fuzz Runner
// =============================================================================

async function runFuzzWasm(body) {
  const totalRuns = body.runs;
  let passed = 0, violations = 0;
  const perFuncMap = {};

  addLog('<span class="iter">===</span> Fuzz started (WASM): ' + totalRuns + ' runs (seed: ' + body.seed + ')');

  try {
    // Parse the contract
    const contractJson = wasmModule.parse_contract(uploadedContent);
    const contract = JSON.parse(contractJson);
    const functions = body.function_filter
      ? contract.functions.filter(f => f.name === body.function_filter)
      : contract.functions;
    const funcCount = functions.length || 1;
    const runsPerFunc = Math.floor(totalRuns / funcCount);

    for (let fi = 0; fi < functions.length; fi++) {
      const func = functions[fi];
      const funcRuns = fi < (totalRuns % funcCount) ? runsPerFunc + 1 : runsPerFunc;

      // Run fuzz for this function in batches (keep UI responsive)
      for (let batch = 0; batch < funcRuns; batch += 50) {
        if (!running) break;
        const batchSize = Math.min(50, funcRuns - batch);

        const batchSeed = BigInt(body.seed + fi * 100000 + batch);
        const batchResult = wasmModule.fuzz_function(
          uploadedContent,
          func.name,
          batchSize,
          batchSeed,
          body.spec_content || null
        );
        const result = JSON.parse(batchResult);

        passed += result.passed || 0;
        violations += result.violations || 0;
        const totalDone = passed + violations;

        // Update per-function stats
        perFuncMap[func.name] = [func.name, funcRuns,
          (perFuncMap[func.name] ? perFuncMap[func.name][2] : 0) + (result.passed || 0),
          (perFuncMap[func.name] ? perFuncMap[func.name][3] : 0) + (result.violations || 0)
        ];

        updateStat('stat-passed', passed);
        updateStat('stat-violations', violations);
        updateProgressBars(Object.values(perFuncMap));
        $('progress-section').style.display = '';

        // Log a batch summary
        if (result.violations > 0) {
          addLog('<span class="iter">' + formatIter(totalDone, totalRuns) + '</span> <span class="fn-name">' + func.name + '</span> <span class="violation">' + result.violations + ' violation(s)</span>');
        } else if (batch === 0 || batch + batchSize >= funcRuns) {
          addLog('<span class="iter">' + formatIter(totalDone, totalRuns) + '</span> <span class="fn-name">' + func.name + '</span> <span class="pass">' + result.passed + ' passed</span>');
        }

        // Yield to keep UI responsive
        await new Promise(r => setTimeout(r, 0));
      }
    }

    // Build final report
    const perFunction = Object.values(perFuncMap);
    const report = {
      passed, violations, errors: 0, total_runs: totalRuns,
      per_function: perFunction,
      violation_results: [],
      zk_verifications: 0, zk_proofs_generated: 0,
      zk_mismatches: 0, zk_mismatch_details: [],
      coverage_pct: 0.0,
    };

    renderCharts(report);
    addLog('<span class="iter">===</span> <span class="pass">COMPLETE (WASM): ' + passed + ' passed, ' + violations + ' violations</span>');
    addLog('<span class="iter">===</span> <span style="color:var(--dim)">Note: ZK verification not available in browser mode. Use CLI/server for leo run verification.</span>');
    setStatus('done', 'Complete (WASM)');
  } catch (err) {
    addLog('<span class="violation">WASM Error: ' + err.message + '</span>');
    setStatus('idle', 'Error');
    console.error('WASM fuzz error:', err);
  } finally {
    running = false;
    $('btn-run').disabled = false;
    $('btn-stop').style.display = 'none';
  }
}

// =============================================================================
// Server Fuzz Runner (SSE)
// =============================================================================

async function runFuzzServer(body) {
  try {
    const resp = await fetch('/api/fuzz', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const err = await resp.text();
      addLog('<span class="violation">Error: ' + err + '</span>');
      throw new Error(err);
    }
    const { run_id } = await resp.json();
    currentRunId = run_id;

    // Connect SSE
    eventSource = new EventSource('/api/fuzz/' + run_id + '/events');
    let totalRuns = 0;
    let perFuncMap = {};

    eventSource.onmessage = (ev) => {
      const event = JSON.parse(ev.data);
      switch (event.type) {
        case 'started':
          totalRuns = event.total_runs;
          addLog('<span class="iter">===</span> Fuzz started (server): ' + totalRuns + ' total runs (seed: ' + body.seed + ')');
          break;

        case 'iteration':
          if (event.outcome === 'pass') {
            addLog('<span class="iter">' + formatIter(event.iteration, totalRuns) + '</span> <span class="fn-name">' + event.function + '</span> <span class="pass">PASS</span>');
          } else {
            addLog('<span class="iter">' + formatIter(event.iteration, totalRuns) + '</span> <span class="fn-name">' + event.function + '</span> <span class="violation">VIOLATION: ' + (event.detail || event.outcome) + '</span>');
          }
          updateStat('stat-passed', event.passed);
          updateStat('stat-violations', event.violations);
          break;

        case 'zk_verification':
          updateStat('stat-zk-proofs', event.total_zk_proofs);
          updateStat('stat-mismatches', event.total_zk_mismatches);
          if (event.mismatch) {
            addLog('<span class="iter">' + formatIter(event.iteration, totalRuns) + '</span> <span class="fn-name">' + event.function + '</span> <span class="zk-fail">ZK MISMATCH: ' + (event.mismatch_detail || 'mismatch') + '</span>');
          } else if (event.proof_generated) {
            addLog('<span class="iter">' + formatIter(event.iteration, totalRuns) + '</span> <span class="fn-name">' + event.function + '</span> <span class="zk-ok">ZK proof verified</span>');
          }
          break;

        case 'progress':
          if (event.per_function) {
            perFuncMap = {};
            for (const f of event.per_function) {
              perFuncMap[f[0]] = [f[0], f[1], f[2], f[3]];
            }
            updateProgressBars(Object.values(perFuncMap));
            $('progress-section').style.display = '';
          }
          break;

        case 'complete':
          eventSource.close();
          eventSource = null;
          updateStat('stat-passed', event.report.passed);
          updateStat('stat-violations', event.report.violations);
          updateStat('stat-zk-proofs', event.report.zk_proofs_generated);
          updateStat('stat-mismatches', event.report.zk_mismatches);
          if (event.report.per_function) {
            updateProgressBars(event.report.per_function);
            $('progress-section').style.display = '';
          }
          renderCharts(event.report);
          addLog('<span class="iter">===</span> <span class="pass">COMPLETE: ' + event.report.passed + ' passed, ' + event.report.violations + ' violations, ' + event.report.zk_mismatches + ' ZK mismatches</span>');
          setStatus('done', 'Complete');
          running = false;
          $('btn-run').disabled = false;
          $('btn-stop').style.display = 'none';
          break;

        case 'error':
          eventSource.close();
          eventSource = null;
          addLog('<span class="violation">FATAL: ' + event.message + '</span>');
          setStatus('idle', 'Error');
          running = false;
          $('btn-run').disabled = false;
          $('btn-stop').style.display = 'none';
          break;
      }
    };

    eventSource.onerror = () => {
      if (eventSource && eventSource.readyState === EventSource.CLOSED) {
        setStatus('done', 'Connection closed');
        running = false;
        $('btn-run').disabled = false;
        $('btn-stop').style.display = 'none';
      }
    };

  } catch (err) {
    setStatus('idle', 'Error');
    running = false;
    $('btn-run').disabled = false;
    $('btn-stop').style.display = 'none';
    console.error('Fuzz request failed:', err);
  }
}

// =============================================================================
// Form Submit Handler
// =============================================================================

$('fuzz-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  if (eventSource) { eventSource.close(); eventSource = null; }
  running = true;

  const body = {
    file_path: $('file-path').value,
    spec_path: $('spec-path').value || null,
    project_dir: $('project-dir').value || null,
    source_dir: $('source-dir').value || null,
    runs: parseInt($('runs').value),
    seed: parseInt($('seed').value),
    function_filter: $('function-filter').value || null,
    verify_all: $('verify-all').checked,
    spec_content: null,
  };

  $('btn-run').disabled = true;
  $('btn-stop').style.display = '';
  setStatus('running', 'Running...');
  resetUI();

  if (useWasm && uploadedContent) {
    // WASM mode: run entirely in browser
    body.file_path = uploadedFileName || 'uploaded.aleo';
    await runFuzzWasm(body);
  } else {
    // Server mode: POST to API
    // If we have uploaded content but no server, upload it first
    if (uploadedContent && !useWasm) {
      // Upload to server for processing
      try {
        const formData = new FormData();
        const blob = new Blob([uploadedContent], { type: 'text/plain' });
        formData.append('file', blob, uploadedFileName || 'upload.aleo');
        const uploadResp = await fetch('/api/upload', { method: 'POST', body: formData });
        const uploadData = await uploadResp.json();
        if (uploadData.ok) {
          body.file_path = uploadData.path;
        }
      } catch (err) {
        console.error('Upload failed:', err);
      }
    }
    await runFuzzServer(body);
  }
});

// =============================================================================
// File Upload (drag & drop — reads locally, no server upload needed)
// =============================================================================

const dropZone = $('drop-zone');
const fileInput = $('file-upload');
const filePathInput = $('file-path');
const uploadStatus = $('upload-status');
const fileNameDisplay = $('file-name-display');

function readFile(file) {
  uploadStatus.innerHTML = '<span style="color:var(--yellow)">⏳ Reading file...</span>';
  const reader = new FileReader();
  reader.onload = function(e) {
    uploadedContent = e.target.result;
    uploadedFileName = file.name;
    filePathInput.value = file.name;
    fileNameDisplay.textContent = '📄 ' + file.name + ' (' + (file.size/1024).toFixed(1) + ' KB) — ready for fuzzing';
    uploadStatus.innerHTML = '<span style="color:var(--green)">✅ Loaded locally — no server upload needed</span>';
  };
  reader.onerror = function() {
    uploadStatus.innerHTML = '<span style="color:var(--red)">❌ Failed to read file</span>';
  };
  reader.readAsText(file);
}

// Click to browse
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) readFile(fileInput.files[0]);
});

// Drag events
['dragenter','dragover'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault();
  dropZone.style.borderColor = 'var(--accent)';
  dropZone.style.background = '#0a2a1a';
}));
['dragleave','drop'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault();
  dropZone.style.borderColor = 'var(--border)';
  dropZone.style.background = 'var(--bg)';
}));
dropZone.addEventListener('drop', ev => {
  ev.preventDefault();
  const file = ev.dataTransfer.files[0];
  if (file && (file.name.endsWith('.aleo') || file.name.endsWith('.leo'))) {
    readFile(file);
  } else {
    uploadStatus.innerHTML = '<span style="color:var(--red)">❌ Only .aleo or .leo files</span>';
  }
});

$('btn-stop').addEventListener('click', () => {
  running = false;
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  setStatus('idle', 'Stopped');
  $('btn-run').disabled = false;
  $('btn-stop').style.display = 'none';
  addLog('<span class="iter">===</span> <span class="violation">Run stopped by user</span>');
});

// =============================================================================
// Init
// =============================================================================

initWasm();
