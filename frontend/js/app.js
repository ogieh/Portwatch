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
const profileSelect  = document.getElementById('profileSelect');
const scanHint       = document.getElementById('scanHint');
const credToggle     = document.getElementById('credToggle');
const scanningState  = document.getElementById('scanningState');
const scanningTarget = document.getElementById('scanningTarget');
const scanningSub    = document.getElementById('scanningSub');
const resultsSection = document.getElementById('resultsSection');
const errorToast     = document.getElementById('errorToast');
const toastMsg       = document.getElementById('toastMsg');

let currentScanId = null;
let diffBaseline  = null;
let lastScans     = [];

const PROFILE_INFO = {
  quick: {
    hint: 'Top 20 ports, no scripts — fastest, roughly 15–60 seconds',
    sub: 'Quick scan — top 20 ports, no scripts'
  },
  standard: {
    hint: 'Top 100 ports with NSE web scripts — may take 60–300 seconds',
    sub: 'Running Nmap with NSE scripts — please wait'
  },
  deep: {
    hint: 'Top 1000 ports with NSE web scripts — can take several minutes',
    sub: 'Deep scan — top 1000 ports, longer timeouts, please wait'
  }
};

profileSelect.addEventListener('change', () => {
  const info = PROFILE_INFO[profileSelect.value] || PROFILE_INFO.standard;
  scanHint.textContent = info.hint;
});

credToggle.addEventListener('change', () => {
  const info = PROFILE_INFO[profileSelect.value] || PROFILE_INFO.standard;
  scanHint.textContent = credToggle.checked
    ? `${info.hint} — credential checks ON: sends failed logins, may lock accounts`
    : info.hint;
});

/* ── SCAN INPUT: glow ring on focus ── */
targetInput.addEventListener('focus', () => scanWrapper.classList.add('active'));
targetInput.addEventListener('blur',  () => scanWrapper.classList.remove('active'));

targetInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

/* ── START SCAN ── */
async function startScan() {
  const target = targetInput.value.trim();
  if (!target) {
    showError('Enter a target domain or IP address first.');
    return;
  }

  setScanningState(true, target);

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, profile: profileSelect.value, credential_checks: credToggle.checked })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${res.status}`);
    }

    const data = await res.json();
    renderResults(data);
    loadHistory();
  } catch (err) {
    showError(err.message || 'Scan failed — check that the backend is running.');
  } finally {
    setScanningState(false);
  }
}

/* ── SCANNING STATE ── */
function setScanningState(active, target = '') {
  scanBtn.disabled = active;
  targetInput.disabled = active;
  profileSelect.disabled = active;
  credToggle.disabled = active;

  if (active) {
    const info = PROFILE_INFO[profileSelect.value] || PROFILE_INFO.standard;
    scanningSub.textContent = info.sub;
    scanningTarget.textContent = target;
    scanningState.classList.remove('hidden');
    resultsSection.classList.add('hidden');
  } 
  else {
    scanningState.classList.add('hidden');
  }


/* ── RENDER RESULTS ── */
function renderResults(data) {
  currentScanId = data.id || null;

  // Header
  document.getElementById('resultTarget').textContent = data.target;
  const profileBadge = document.getElementById('resultProfile');
}
  if (data.profile) {
    profileBadge.textContent = data.profile;
    profileBadge.classList.remove('hidden');
  } 
  else {
    profileBadge.textContent = '';
    profileBadge.classList.add('hidden');
  }
  renderGrade(data.risk);
  document.getElementById('reportBtn').classList.toggle('hidden', !currentScanId);
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

  // Summary
  document.getElementById('summaryText').textContent =
    data.summary || 'No summary available.';

  // Ports table
  renderPortsTable(data.ports || []);

  // SSL / HTTP findings
  renderFindings(data.ports || []);

  // Compliance / framework mapping
  renderCompliance(data.compliance || []);

  // Credential & lockout checks
  renderCredChecks(data.credential_checks);

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
}

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
}

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

/* ── RISK GRADE ── */
function renderGrade(risk) {
  const el = document.getElementById('resultGrade');
  const grade = risk && risk.grade;
  if (!grade) {
    el.textContent = '';
    el.classList.add('hidden');
    el.className = 'grade-badge hidden';
    return;
  }
  const score = (risk.score !== undefined && risk.score !== null) ? ` · ${risk.score}/100` : '';
  el.textContent = `${grade}${score}`;
  el.className = `grade-badge grade-${grade}`;
  el.classList.remove('hidden');
}

/* ── COMPLIANCE / FRAMEWORK MAPPING ── */
function renderCompliance(tags) {
  const list = document.getElementById('complianceList');
  const count = document.getElementById('complianceCount');

  count.textContent = tags.length ? `${tags.length} mapped` : '';

  if (!tags.length) {
    list.innerHTML = '<p class="finding-empty">No framework mappings for this scan.</p>';
    return;
  }

  list.innerHTML = tags.map(tag => `
    <div class="compliance-item">
      <span class="compliance-cat">${escHtml(tag.category)}</span>
      <div class="compliance-body">
        <span class="compliance-name">${escHtml(tag.name)}</span>
        <ul class="compliance-evidence">
          ${tag.evidence.map(e => `<li>${escHtml(e)}</li>`).join('')}
        </ul>
      </div>
    </div>
  `).join('');
}

/* ── CREDENTIAL & LOCKOUT CHECKS ── */
const VERDICT_META = {
  none_observed: { icon: '🚨', cls: 'verdict-bad',  label: 'No rate limiting observed' },
  throttled:     { icon: '✓',  cls: 'verdict-ok',   label: 'Throttled' },
  lockout:       { icon: '✓',  cls: 'verdict-ok',   label: 'Lockout protection' },
  captcha:       { icon: '✓',  cls: 'verdict-ok',   label: 'CAPTCHA protection' }
};

function renderCredChecks(cc) {
  const card = document.getElementById('credCard');
  const list = document.getElementById('credFindings');
  const count = document.getElementById('credCount');

  if (!cc || !cc.enabled) {
    card.classList.add('hidden');
    list.innerHTML = '';
    count.textContent = '';
    return;
  }

  const items = [];
  for (const f of cc.http_login_findings || []) {
    const meta = VERDICT_META[f.verdict] || { icon: '?', cls: '', label: f.verdict };
    items.push(`
      <div class="finding-item">
        <span class="finding-icon">${meta.icon}</span>
        <span class="finding-text">
          <span class="verdict-chip ${meta.cls}">${escHtml(meta.label)}</span>
          <span class="finding-key">${escHtml(f.url)}</span>
          ${escHtml(f.detail)}
        </span>
      </div>`);
  }
  for (const d of cc.db_findings || []) {
    items.push(`
      <div class="finding-item">
        <span class="finding-icon">${d.vulnerable ? '🚨' : '✓'}</span>
        <span class="finding-text">
          ${d.vulnerable ? '<span class="verdict-chip verdict-bad">Vulnerable</span>' : '<span class="verdict-chip verdict-ok">OK</span>'}
          <span class="finding-key">Port ${escHtml(d.port)} · ${escHtml(d.check)}</span>
          ${escHtml(d.detail)}
        </span>
      </div>`);
  }

  const total = (cc.http_login_findings || []).length + (cc.db_findings || []).length;
  count.textContent = total ? `${total} checked` : '';
  list.innerHTML = total
    ? items.join('')
    : '<p class="finding-empty">Checks ran but no login endpoints or credential-protected services were found to test.</p>';
  if (cc.error) {
    list.innerHTML += `<p class="finding-empty">Partial failure: ${escHtml(cc.error)}</p>`;
  }
  card.classList.remove('hidden');
}

/* ── SCAN COMPARISON ── */
async function onCompareClick(id) {
  const scan = lastScans.find(s => s.id === id);
  const target = scan ? scan.target : '';

  if (!diffBaseline) {
    diffBaseline = { id, target };
    markBaselineRow(id);
    showInfo(`Baseline set: scan #${id}. Now click Compare on another scan of ${target}.`);
    return;
  }

  if (diffBaseline.id === id) {
    clearDiff();
    showInfo('Comparison cancelled — baseline cleared.');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/history/${diffBaseline.id}/diff/${id}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `Server returned ${res.status}`);
    renderDiff(body);
    clearBaselineRow();
    diffBaseline = { id, target };
    markBaselineRow(id);
  } catch (err) {
    clearDiff();
    showError(err.message || 'Could not compare those scans.');
  }
}

function markBaselineRow(id) {
  clearBaselineRow();
  const tr = document.querySelector(`#historyBody tr[data-scanid="${id}"]`);
  if (tr) tr.classList.add('baseline-row');
}

function clearBaselineRow() {
  document.querySelectorAll('#historyBody tr.baseline-row')
    .forEach(tr => tr.classList.remove('baseline-row'));
}

function renderDiff(diff) {
  const section = document.getElementById('diffSection');
  const body = document.getElementById('diffBody');

  let deltaHtml = '<p class="finding-empty">Score not comparable — one of these scans predates scoring.</p>';
  if (diff.score_delta !== null && diff.score_delta !== undefined) {
    const d = diff.score_delta;
    const dir = d > 0 ? { sym: '▲', cls: 'delta-up', word: 'improved' }
              : d < 0 ? { sym: '▼', cls: 'delta-down', word: 'declined' }
              :         { sym: '■', cls: 'delta-flat', word: 'unchanged' };
    deltaHtml = `
      <span class="score-delta ${dir.cls}">
        <span class="delta-sym">${dir.sym}</span>
        ${escHtml(diff.before.risk_score)} → ${escHtml(diff.after.risk_score)}
        (${d > 0 ? '+' : ''}${d})
      </span>
      <span class="delta-word ${dir.cls}">Risk score ${dir.word}</span>`;
    if (diff.grade_change) {
      deltaHtml += `<span class="grade-change">Grade ${escHtml(diff.grade_change.from)} → ${escHtml(diff.grade_change.to)}</span>`;
    }
  }

  const portPill = p => `
    <span class="diff-port" title="${escHtml(p.version || '')}">
      <strong>${escHtml(p.port)}</strong> ${escHtml(p.service || '—')}
    </span>`;

  const openedHtml  = diff.opened_ports.length
    ? diff.opened_ports.map(portPill).join('')
    : '<p class="finding-empty">None.</p>';
  const closedHtml  = diff.closed_ports.length
    ? diff.closed_ports.map(portPill).join('')
    : '<p class="finding-empty">None.</p>';

  let changedHtml = '<p class="finding-empty">No service or version changes.</p>';
  if (diff.changed_ports.length) {
    changedHtml = `
      <table class="ports-table">
        <thead><tr><th>Port</th><th>Before</th><th>After</th></tr></thead>
        <tbody>
          ${diff.changed_ports.map(c => `
            <tr>
              <td><span class="port-number">${escHtml(c.port)}</span></td>
              <td>${escHtml(c.from.service || '—')} <span class="version-text">${escHtml(c.from.version || '')}</span></td>
              <td>${escHtml(c.to.service || '—')} <span class="version-text">${escHtml(c.to.version || '')}</span></td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  const warningHtml = diff.warning
    ? `<p class="diff-warning">⚠ ${escHtml(diff.warning)}</p>`
    : '';

  body.innerHTML = `
    <div class="diff-meta">
      <span class="mono">#${escHtml(diff.before.id)} (${formatTs(diff.before.timestamp)})</span>
      <span class="diff-arrow">→</span>
      <span class="mono">#${escHtml(diff.after.id)} (${formatTs(diff.after.timestamp)})</span>
      <span class="profile-badge">${escHtml(diff.target)}</span>
    </div>
    ${warningHtml}
    <div class="diff-score">${deltaHtml}</div>
    <div class="diff-grid">
      <div>
        <h4 class="diff-heading opened-h">Opened ports (${diff.opened_ports.length})</h4>
        ${openedHtml}
      </div>
      <div>
        <h4 class="diff-heading closed-h">Closed ports (${diff.closed_ports.length})</h4>
        ${closedHtml}
      </div>
    </div>
    <h4 class="diff-heading">Service / version changes</h4>
    ${changedHtml}
  `;

  section.classList.remove('hidden');
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function clearDiff() {
  diffBaseline = null;
  clearBaselineRow();
  document.getElementById('diffSection').classList.add('hidden');
}

/* ── REPORT ── */
function openCurrentReport() {
  if (currentScanId) openReport(currentScanId);
}

function openReport(id) {
  window.open(`${API_BASE}/api/report/${id}`, '_blank');
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
  } 
  else {
    body.classList.add('hidden');
    icon.textContent = '▸ expand';
  }
}

/* ── HISTORY ── */
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (!res.ok) return;
    const scans = await res.json();
    renderHistory(scans);
  } 
  catch {
    // History load failure is non-critical — just show empty state
    renderHistory([]);
  }
}

function renderHistory(scans) {
  const tbody  = document.getElementById('historyBody');
  const hcount = document.getElementById('historyCount');
  const empty  = document.getElementById('historyEmpty');

  tbody.innerHTML = '';
  lastScans = scans;
  hcount.textContent = `${scans.length} scan${scans.length !== 1 ? 's' : ''}`;

  if (!scans.length) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  for (const scan of scans) {
    const tr = document.createElement('tr');
    tr.dataset.scanid = scan.id;
    const gradeCell = scan.risk_grade
      ? `<span class="grade-badge grade-${escHtml(scan.risk_grade)}">${escHtml(scan.risk_grade)}</span>`
      : '<span class="version-text">—</span>';
    tr.innerHTML = `
      <td class="history-id">#${scan.id}</td>
      <td class="history-target">${escHtml(scan.target)}</td>
      <td><span class="profile-badge">${escHtml(scan.profile || 'standard')}</span></td>
      <td class="history-ts">${formatTs(scan.timestamp)}</td>
      <td>${gradeCell}</td>
      <td class="history-summary">${escHtml(scan.summary || '—')}</td>
      <td>
        <div class="history-actions">
          <button class="load-btn" onclick="loadScanById(${scan.id})">Load</button>
          <button class="load-btn" onclick="onCompareClick(${scan.id})">Compare</button>
          <button class="load-btn" onclick="openReport(${scan.id})">Report</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

async function loadScanById(id) {
  try {
    const res = await fetch(`${API_BASE}/api/history/${id}`);
    if (!res.ok) throw new Error('Not found');
    const data = await res.json();
    renderResults(data);
  } 
  catch (err) {
    showError('Could not load scan #' + id);
  }
}

/* ── ERROR TOAST ── */
let toastTimer;
function showToast(msg, type = 'error') {
  toastMsg.textContent = msg;
  errorToast.classList.remove('hidden');
  errorToast.classList.toggle('toast--info', type === 'info');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => errorToast.classList.add('hidden'), 5000);
}

function showError(msg) { showToast(msg, 'error'); }
function showInfo(msg)  { showToast(msg, 'info'); }

/* ── UTILS ── */
function formatTs(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } 
  catch { return ts; }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

/* ── INIT ── */
window.addEventListener('DOMContentLoaded', () => {
  loadHistory();
  targetInput.focus();
});
