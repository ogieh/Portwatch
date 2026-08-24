/* ─────────────────────────────────────────
   PortWatch — app.js
   Connects to Flask backend at /api/scan and /api/history
   No external libraries — plain fetch()
───────────────────────────────────────── */

const API_BASE = 'http://127.0.0.1:5000';

/* ── DOM REFS ── */
const targetInput    = document.getElementById('targetInput');
const scanBtn        = document.getElementById('scanBtn');
const scanWrapper    = document.getElementById('scanWrapper');
const scanningState  = document.getElementById('scanningState');
const scanningTarget = document.getElementById('scanningTarget');
const resultsSection = document.getElementById('resultsSection');
const errorToast     = document.getElementById('errorToast');
const toastMsg       = document.getElementById('toastMsg');

/* ── SCAN INPUT: glow ring on focus ── */
targetInput.addEventListener('focus', () => scanWrapper.classList.add('active'));
targetInput.addEventListener('blur',  () => scanWrapper.classList.remove('active'));

targetInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

/* ── FETCH WITH TIMEOUT ──
   Wraps fetch() with a hard client-side ceiling so a genuinely hung network
   request (not the scan itself -- that has its own backend watchdog) can
   never leave the UI stuck forever with no feedback. */
async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/* ── START SCAN ── */
async function startScan() {
  const target = targetInput.value.trim();
  if (!target) {
    showError('Enter a target domain or IP address first.');
    return;
  }

  setScanningState(true, target);
  updateProgress(0, 'Queued', 0);

  try {
    const startRes = await fetchWithTimeout(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    }, 10000);

    if (!startRes.ok) {
      const err = await startRes.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${startRes.status}`);
    }

    const { job_id, target: sanitizedTarget } = await startRes.json();
    if (sanitizedTarget) scanningTarget.textContent = sanitizedTarget;

    const data = await pollScanStatus(job_id);
    renderResults(data);
    loadHistory();
  } catch (err) {
    if (err.name === 'AbortError') {
      showError('Could not reach the backend — is it running on port 5000?');
    } else {
      showError(err.message || 'Scan failed — check that the backend is running.');
    }
  } finally {
    setScanningState(false);
  }
}

/* ── POLL SCAN STATUS ──
   Backend runs the scan in a background thread; this polls its real
   stage/elapsed progress rather than faking a bar with a timer. Finished
   job results are cached server-side for a few minutes, so a transient
   network blip on one poll is retried rather than aborting the whole scan. */
async function pollScanStatus(jobId) {
  const POLL_INTERVAL_MS = 1200;
  const MAX_CONSECUTIVE_FAILURES = 5;
  let consecutiveFailures = 0;

  while (true) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

    let res;
    try {
      res = await fetchWithTimeout(`${API_BASE}/api/scan/status/${jobId}`, {}, 8000);
    } catch (err) {
      consecutiveFailures++;
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        throw new Error('Lost connection to the backend while scanning.');
      }
      continue; // transient network blip -- retry on next poll
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${res.status}`);
    }
    consecutiveFailures = 0;
    const status = await res.json();

    updateProgress(status.progress_pct, status.stage_label, status.elapsed);

    if (status.status === 'done') {
      return status.result;
    }
    if (status.status === 'error') {
      throw new Error(status.error || 'Scan failed.');
    }
    // otherwise still "running" -- keep polling
  }
}

function updateProgress(pct, stageLabel, elapsedSeconds) {
  const fill = document.getElementById('progressBarFill');
  const stageEl = document.getElementById('scanningStageLabel');
  const elapsedEl = document.getElementById('progressElapsed');

  if (fill) fill.style.width = `${pct}%`;
  if (stageEl) stageEl.textContent = stageLabel;
  if (elapsedEl) elapsedEl.textContent = `${elapsedSeconds}s elapsed`;
}

/* ── SCANNING STATE ── */
function setScanningState(active, target = '') {
  scanBtn.disabled = active;
  targetInput.disabled = active;

  if (active) {
    scanningTarget.textContent = target;
    scanningState.classList.remove('hidden');
    resultsSection.classList.add('hidden');
  } else {
    scanningState.classList.add('hidden');
  }
}

/* ── RENDER RESULTS ── */
function renderResults(data) {
  // Header
  document.getElementById('resultTarget').textContent = data.target;
  document.getElementById('resultTs').textContent = formatTs(data.timestamp);

  // Risk pill strip
  const strip = document.getElementById('resultRiskStrip');
  strip.innerHTML = '';
  const riskCounts = countRisks(data.ports || []);
  for (const [level, count] of Object.entries(riskCounts)) {
    if (count > 0) {
      const pill = document.createElement('span');
      pill.className = `risk-pill ${level}`;
      pill.textContent = `${count} ${level}`;
      strip.appendChild(pill);
    }
  }

  // Summary (prefer the detailed narrative report; fall back to the short summary)
  document.getElementById('summaryText').textContent =
    data.narrative_summary || data.summary || 'No summary available.';

  // Ports table
  renderPortsTable(data.ports || []);

  // SSL / HTTP findings
  renderFindings(data.ports || []);

  // Raw output
  const rawLines = buildRawOutput(data.ports || []);
  document.getElementById('rawOutput').textContent =
    rawLines.length ? rawLines.join('\n') : 'No raw NSE output.';

  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function countRisks(ports) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const p of ports) {
    if (p.risk in counts) counts[p.risk]++;
  }
  return counts;
}

/* ── PORTS TABLE ── */
function renderPortsTable(ports) {
  const tbody = document.getElementById('portsBody');
  const count = document.getElementById('portCount');
  tbody.innerHTML = '';

  const open = ports.filter(p => p.state === 'open');
  count.textContent = `${open.length} open`;

  if (!open.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="5" style="color:var(--muted);text-align:center;padding:20px;">No open ports found.</td>`;
    tbody.appendChild(tr);
    return;
  }

  for (const port of open) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="port-number">${port.port}</span></td>
      <td><span class="state-badge open">open</span></td>
      <td>${escHtml(port.service || '—')}</td>
      <td><span class="version-text">${escHtml(port.version || '—')}</span></td>
      <td><span class="risk-dot ${port.risk || 'low'}">${port.risk || 'low'}</span></td>
    `;
    tbody.appendChild(tr);
  }
}

/* ── SSL / HTTP FINDINGS ── */
function renderFindings(ports) {
  const sslEl  = document.getElementById('sslFindings');
  const httpEl = document.getElementById('httpFindings');
  const sslItems  = [];
  const httpItems = [];

  for (const port of ports) {
    if (!port.scripts) continue;
    const scripts = port.scripts;

    // SSL findings
    if (scripts['ssl-cert']) {
      sslItems.push(makeFinding('🔒', `SSL Cert on :${port.port}`, scripts['ssl-cert']));
    }
    if (scripts['ssl-enum-ciphers']) {
      const weak = /weak|rc4|des|3des|export/i.test(scripts['ssl-enum-ciphers']);
      sslItems.push(makeFinding(
        weak ? '⚠' : '✓',
        `Ciphers on :${port.port}`,
        weak ? 'Weak ciphers detected — see raw output.' : 'No obviously weak ciphers.'
      ));
    }
    if (scripts['ssl-dh-params']) {
      const vuln = /logjam|vulnerable|weak/i.test(scripts['ssl-dh-params']);
      sslItems.push(makeFinding(
        vuln ? '⚠' : '✓',
        `DH Params on :${port.port}`,
        vuln ? 'Weak DH params (Logjam risk).' : 'DH parameters look acceptable.'
      ));
    }

    // HTTP findings
    if (scripts['http-security-headers']) {
      const missing = extractMissingHeaders(scripts['http-security-headers']);
      if (missing.length) {
        httpItems.push(makeFinding('⚠', `Missing headers on :${port.port}`, missing.join(', ')));
      } else {
        httpItems.push(makeFinding('✓', `Headers on :${port.port}`, 'Security headers present.'));
      }
    }
    if (scripts['http-methods']) {
      const dangerous = /PUT|DELETE|TRACE|CONNECT/i.exec(scripts['http-methods']);
      if (dangerous) {
        httpItems.push(makeFinding('⚠', `Dangerous method on :${port.port}`, `${dangerous[0]} is allowed — consider disabling.`));
      }
    }
    if (scripts['http-auth-finder']) {
      httpItems.push(makeFinding('ℹ', `Auth on :${port.port}`, scripts['http-auth-finder'].split('\n')[0]));
    }

    // Vuln scripts
    for (const [key, val] of Object.entries(scripts)) {
      if (key.startsWith('http-vuln-') && val && /VULNERABLE/i.test(val)) {
        httpItems.push(makeFinding('🚨', `${key} on :${port.port}`, 'VULNERABLE — see raw output for details.'));
      }
    }
  }

  sslEl.innerHTML  = sslItems.length  ? sslItems.join('')  : '<p class="finding-empty">No SSL data in this scan.</p>';
  httpEl.innerHTML = httpItems.length ? httpItems.join('') : '<p class="finding-empty">No HTTP header data in this scan.</p>';
}

function makeFinding(icon, key, text) {
  return `
    <div class="finding-item">
      <span class="finding-icon">${icon}</span>
      <span class="finding-text">
        <span class="finding-key">${escHtml(key)}</span>
        ${escHtml(text)}
      </span>
    </div>
  `;
}

function extractMissingHeaders(raw) {
  const known = ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options','Referrer-Policy','Permissions-Policy'];
  return known.filter(h => raw.toLowerCase().includes('missing') && raw.includes(h));
}

/* ── RAW OUTPUT ── */
function buildRawOutput(ports) {
  const lines = [];
  for (const port of ports) {
    if (!port.scripts || !Object.keys(port.scripts).length) continue;
    lines.push(`── PORT ${port.port} ─────────────────────`);
    for (const [key, val] of Object.entries(port.scripts)) {
      if (val) {
        lines.push(`\n[${key}]`);
        lines.push(val);
      }
    }
    lines.push('');
  }
  return lines;
}

/* ── RAW TOGGLE ── */
function toggleRaw() {
  const body = document.getElementById('rawBody');
  const icon = document.getElementById('rawToggleIcon');
  if (body.classList.contains('hidden')) {
    body.classList.remove('hidden');
    icon.textContent = '▾ collapse';
  } else {
    body.classList.add('hidden');
    icon.textContent = '▸ expand';
  }
}

/* ── HISTORY ── */
async function loadHistory() {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/history`, {}, 8000);
    if (!res.ok) return;
    const scans = await res.json();
    renderHistory(scans);
    setBackendStatus(true);
  } catch {
    // History load failure is non-critical — just show empty state
    renderHistory([]);
    setBackendStatus(false);
  }
}

function renderHistory(scans) {
  const tbody  = document.getElementById('historyBody');
  const hcount = document.getElementById('historyCount');
  const empty  = document.getElementById('historyEmpty');

  tbody.innerHTML = '';
  hcount.textContent = `${scans.length} scan${scans.length !== 1 ? 's' : ''}`;

  if (!scans.length) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  for (const scan of scans) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="history-id">#${scan.id}</td>
      <td class="history-target">${escHtml(scan.target)}</td>
      <td class="history-ts">${formatTs(scan.timestamp)}</td>
      <td class="history-summary">${escHtml(scan.summary || '—')}</td>
      <td><button class="load-btn" onclick="loadScanById(${scan.id})">Load</button></td>
    `;
    tbody.appendChild(tr);
  }
}

async function loadScanById(id) {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/history/${id}`, {}, 8000);
    if (!res.ok) throw new Error('Not found');
    const data = await res.json();
    renderResults(data);
  } catch (err) {
    showError('Could not load scan #' + id);
  }
}

/* ── ERROR TOAST ── */
let toastTimer;
function showError(msg) {
  toastMsg.textContent = msg;
  errorToast.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => errorToast.classList.add('hidden'), 5000);
}

/* ── UTILS ── */
function formatTs(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch { return ts; }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

/* ── BACKEND STATUS INDICATOR ── */
function setBackendStatus(online) {
  const dot = document.getElementById('statusDot');
  const label = document.getElementById('statusLabel');
  if (!dot || !label) return;
  dot.className = `status-dot ${online ? 'online' : 'offline'}`;
  label.textContent = online ? 'Backend online' : 'Backend unreachable';
}

async function checkBackendHealth() {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/api/health`, {}, 5000);
    setBackendStatus(res.ok);
  } catch {
    setBackendStatus(false);
  }
}

/* ── INIT ── */
window.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  loadHistory();
  targetInput.focus();
  setInterval(checkBackendHealth, 20000); // periodic re-check, not just at load
});
