/// Embedded HTML dashboard for the LeoZap web UI.
///
/// This is a single-page application served directly from the binary.
/// Uses vanilla JS + Chart.js CDN for charts — no build step needed.
pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LeoZap — Aleo Contract Fuzzer</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --dim: #8b949e;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d2991d;
    --cyan: #58a6ff;
    --purple: #a371f7;
    --orange: #db6d28;
    --accent: #00e5a0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: var(--bg);
    color: var(--text);
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
  }
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 16px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px;
  }
  header h1 { font-size: 24px; color: var(--accent); }
  header span { color: var(--dim); font-size: 14px; }
  .badge {
    font-size: 11px; padding: 3px 8px; border-radius: 12px; font-weight: 600;
    background: #1a3a2a; color: var(--accent); border: 1px solid var(--accent);
  }

  /* Form */
  form {
    display: grid; grid-template-columns: 1fr 1fr 1fr;
    gap: 12px; padding: 20px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px;
  }
  form label { font-size: 12px; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }
  form input, form select { width: 100%; padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: inherit; font-size: 14px; }
  form input:focus, form select:focus { outline: none; border-color: var(--accent); }
  .form-full { grid-column: 1 / -1; display: flex; gap: 10px; align-items: flex-end; }
  .btn {
    padding: 10px 24px; border: none; border-radius: 6px; font-size: 14px;
    font-weight: 600; cursor: pointer; font-family: inherit;
  }
  .btn-run { background: var(--accent); color: #000; }
  .btn-run:hover { opacity: 0.85; }
  .btn-run:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-stop { background: var(--red); color: #fff; }

  /* Stats grid */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center;
  }
  .stat-card .value { font-size: 36px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .stat-card .label { font-size: 11px; color: var(--dim); text-transform: uppercase; margin-top: 4px; }
  .stat-pass .value { color: var(--green); }
  .stat-violation .value { color: var(--red); }
  .stat-zk .value { color: var(--cyan); }
  .stat-mismatch .value { color: var(--orange); }

  /* Progress section */
  .progress-section { margin-bottom: 24px; }
  .progress-section h3 { font-size: 14px; color: var(--dim); margin-bottom: 10px; text-transform: uppercase; }
  .progress-bar-wrap { margin-bottom: 8px; }
  .progress-bar-label { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 3px; }
  .progress-bar-track { height: 8px; background: var(--bg); border-radius: 4px; overflow: hidden; }
  .progress-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
  .fill-pass { background: var(--green); }
  .fill-violation { background: var(--red); }
  .fill-running { background: var(--yellow); width: 100% !important; animation: pulse 1.2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }

  /* Event log */
  .log-section { margin-bottom: 24px; }
  .log-section h3 { font-size: 14px; color: var(--dim); margin-bottom: 10px; text-transform: uppercase; }
  .log-container {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; max-height: 300px; overflow-y: auto; padding: 12px;
    font-size: 13px; font-family: 'SF Mono', 'Fira Code', monospace;
  }
  .log-entry { padding: 3px 0; border-bottom: 1px solid rgba(48,54,61,0.5); }
  .log-entry .iter { color: var(--dim); margin-right: 8px; }
  .log-entry .fn-name { color: var(--purple); }
  .log-entry .pass { color: var(--green); }
  .log-entry .violation { color: var(--red); }
  .log-entry .zk-ok { color: var(--cyan); }
  .log-entry .zk-fail { color: var(--orange); }

  /* Charts */
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
  .chart-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .chart-card h3 { font-size: 13px; color: var(--dim); margin-bottom: 12px; text-transform: uppercase; }
  .chart-card canvas { max-height: 220px; }

  /* ZK highlight card */
  .zk-highlight {
    background: linear-gradient(135deg, #0d1f2d, #0a1628);
    border: 1px solid var(--cyan);
    border-radius: 8px; padding: 20px; margin-bottom: 24px;
  }
  .zk-highlight h2 { color: var(--cyan); font-size: 18px; margin-bottom: 12px; }
  .zk-highlight p { color: var(--dim); font-size: 14px; line-height: 1.6; }

  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .dot-idle { background: var(--dim); }
  .dot-running { background: var(--yellow); animation: pulse 0.8s infinite; }
  .dot-done { background: var(--green); }

  footer { text-align: center; color: var(--dim); font-size: 12px; padding: 24px 0; border-top: 1px solid var(--border); margin-top: 24px; }

  @media (max-width: 768px) {
    form { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .charts-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<header>
  <h1>&#x1f981; LeoZap</h1>
  <span>Aleo Contract Fuzzer + Privacy Invariant Checker</span>
  <span class="badge">ZK VERIFICATION</span>
</header>

<form id="fuzz-form">
  <div>
    <label>.aleo File</label>
    <input type="text" id="file-path" value="contracts/token_safe/build/token/token.aleo" required>
  </div>
  <div>
    <label>OR: Leo Source Dir (auto-build)</label>
    <input type="text" id="source-dir" placeholder="e.g. contracts/token_safe">
  </div>
  <div>
    <label>Spec File (optional)</label>
    <input type="text" id="spec-path" placeholder="Leave empty for fuzz mode">
  </div>
  <div>
    <label>Project Dir (for ZK)</label>
    <input type="text" id="project-dir" placeholder="Optional: Leo project dir">
  </div>
  <div>
    <label>Runs</label>
    <input type="number" id="runs" value="200" min="1" max="10000">
  </div>
  <div>
    <label>Seed (0 = random)</label>
    <input type="number" id="seed" value="0" min="0">
  </div>
  <div>
    <label>Function Filter</label>
    <input type="text" id="function-filter" placeholder="All functions">
  </div>
  <div class="form-full">
    <button type="submit" class="btn btn-run" id="btn-run">&#x26a1; Run Fuzz</button>
    <button type="button" class="btn btn-stop" id="btn-stop" style="display:none">&#x25a0; Stop</button>
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
      <input type="checkbox" id="verify-all" style="width:auto;">
      <span>Verify ALL with ZK (slow)</span>
    </label>
    <span id="status-indicator" style="font-size:13px;">
      <span class="status-dot dot-idle"></span> Ready
    </span>
  </div>
</form>

<div class="stats-grid">
  <div class="stat-card stat-pass">
    <div class="value" id="stat-passed">—</div>
    <div class="label">Passed</div>
  </div>
  <div class="stat-card stat-violation">
    <div class="value" id="stat-violations">—</div>
    <div class="label">Violations</div>
  </div>
  <div class="stat-card stat-zk">
    <div class="value" id="stat-zk-proofs">—</div>
    <div class="label">ZK Proofs Generated</div>
  </div>
  <div class="stat-card stat-mismatch">
    <div class="value" id="stat-mismatches">—</div>
    <div class="label">ZK Mismatches (Real Bugs)</div>
  </div>
</div>

<div class="progress-section" id="progress-section" style="display:none">
  <h3>Per-Function Progress</h3>
  <div id="progress-bars"></div>
</div>

<div class="log-section">
  <h3>Event Log</h3>
  <div class="log-container" id="log-container">
    <div class="log-entry"><span class="iter">—</span>Waiting for fuzz run to start...</div>
  </div>
</div>

<div class="charts-grid" id="charts-section" style="display:none">
  <div class="chart-card">
    <h3>Results Overview</h3>
    <canvas id="chart-donut"></canvas>
  </div>
  <div class="chart-card">
    <h3>Per-Function Breakdown</h3>
    <canvas id="chart-bar"></canvas>
  </div>
</div>

<div class="zk-highlight" id="zk-highlight" style="display:none">
  <h2>&#x1f512; Aleo Privacy Capability Used</h2>
  <p>
    Each ZK verification calls <code>leo run</code> to generate a real zero-knowledge proof via <strong>snarkVM</strong>.
    The symbolic execution result is compared against the real ZK execution.
    <strong>Mismatches</strong> between the two indicate genuine privacy-semantic bugs &mdash;
    cases where the contract's privacy invariants are violated.
  </p>
  <p style="margin-top:8px;font-size:13px;color:var(--dim);">
    &#x2705; <span id="zk-verify-count">0</span> ZK verifications performed &nbsp;|&nbsp;
    &#x274c; <span id="zk-mismatch-count">0</span> mismatches detected
  </p>
</div>

<footer>
  LeoZap — Property-based fuzzer + privacy invariant checker for Aleo &middot; Built with Rust
</footer>

<script>
  let charts = {};
  let eventSource = null;
  let currentRunId = null;

  const $ = (id) => document.getElementById(id);

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
    // Animate
    $(id).style.transform = 'scale(1.1)';
    setTimeout(() => { $(id).style.transform = 'scale(1)'; }, 150);
  }

  function updateProgressBars(perFunction) {
    const container = $('progress-bars');
    container.innerHTML = '';
    for (const [name, total, passed, violations] of perFunction) {
      const passPct = total > 0 ? (passed / total * 100).toFixed(0) : 0;
      const violPct = total > 0 ? (violations / total * 100).toFixed(0) : 0;
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

    $('zk-verify-count').textContent = report.zk_verifications;
    $('zk-mismatch-count').textContent = report.zk_mismatches;
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

  $('fuzz-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    if (eventSource) { eventSource.close(); eventSource = null; }

    const body = {
      file_path: $('file-path').value,
      spec_path: $('spec-path').value || null,
      project_dir: $('project-dir').value || null,
      source_dir: $('source-dir').value || null,
      runs: parseInt($('runs').value),
      seed: parseInt($('seed').value),
      function_filter: $('function-filter').value || null,
      verify_all: $('verify-all').checked,
    };

    $('btn-run').disabled = true;
    $('btn-stop').style.display = '';
    setStatus('running', 'Running...');
    resetUI();

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
            addLog('<span class="iter">===</span> Fuzz started: ' + totalRuns + ' total runs (seed: ' + body.seed + ')');
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
            $('btn-run').disabled = false;
            $('btn-stop').style.display = 'none';
            break;

          case 'error':
            eventSource.close();
            eventSource = null;
            addLog('<span class="violation">FATAL: ' + event.message + '</span>');
            setStatus('idle', 'Error');
            $('btn-run').disabled = false;
            $('btn-stop').style.display = 'none';
            break;
        }
      };

      eventSource.onerror = () => {
        if (eventSource && eventSource.readyState === EventSource.CLOSED) {
          setStatus('done', 'Connection closed');
          $('btn-run').disabled = false;
          $('btn-stop').style.display = 'none';
        }
      };

    } catch (err) {
      setStatus('idle', 'Error');
      $('btn-run').disabled = false;
      $('btn-stop').style.display = 'none';
      console.error('Fuzz request failed:', err);
    }
  });

  $('btn-stop').addEventListener('click', () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    setStatus('idle', 'Stopped');
    $('btn-run').disabled = false;
    $('btn-stop').style.display = 'none';
    addLog('<span class="iter">===</span> <span class="violation">Run stopped by user</span>');
  });
</script>
</body>
</html>"##;
