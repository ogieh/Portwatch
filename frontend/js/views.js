/* ─────────────────────────────────────────
   PortWatch Pro - views.js
   Each Views.<name>(mount, params) renders a page into the main content area.
   Views never touch the router directly; they call go() (exposed by app.js).
───────────────────────────────────────── */

const Views = (() => {
  const e = UI.esc;
  const SEV_COLORS = { critical: '#B91C1C', high: '#EF4444', medium: '#F59E0B', low: '#22C55E', info: '#60A5FA' };

  // ══════════════════════ DASHBOARD ══════════════════════
  async function dashboard(mount) {
    mount.innerHTML = loading('Loading dashboard…');
    let d;
    try { d = await API.dashboard(); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }

    const k = d.kpis;
    const kpis = [
      { label: 'Projects', value: k.projects, cls: '' },
      { label: 'Total scans', value: k.total_scans, cls: '' },
      { label: 'Avg score', value: k.avg_score ?? '-', cls: scoreCls(k.avg_score), foot: '/ 100' },
      { label: 'Critical findings', value: k.critical_findings, cls: k.critical_findings ? 'crit' : 'good' },
      { label: 'High findings', value: k.high_findings, cls: k.high_findings ? 'warn' : 'good' },
      { label: 'Unique CVEs', value: k.unique_cves, cls: k.unique_cves ? 'warn' : '' },
    ];

    mount.innerHTML = `
      <div class="page-head">
        <div>
          <div class="page-title">Security posture</div>
          <div class="page-sub">Continuous attack-surface monitoring across all projects</div>
        </div>
        <button class="btn btn-primary" data-newscan>${UI.icon('scan')} New scan</button>
      </div>

      <div class="kpi-grid">
        ${kpis.map(kpiCard).join('')}
      </div>

      <div class="dash-grid">
        <div class="card">
          <div class="card-header"><span class="card-eyebrow">Risk score trend</span>
            <span class="card-count">last ${d.score_trend.length} scans</span></div>
          <div class="card-body">${trendChart(d.score_trend)}</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-eyebrow">Grade distribution</span></div>
          <div class="card-body">${gradeDist(d.grade_distribution)}</div>
        </div>
      </div>

      <div class="dash-grid" style="margin-top:18px;">
        <div class="card">
          <div class="card-header"><span class="card-eyebrow">Top exposures</span>
            <span class="card-count">${d.top_exposures.length}</span></div>
          <div class="card-body no-pad">${topExposures(d.top_exposures)}</div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-eyebrow">Open findings by severity</span></div>
          <div class="card-body">${sevBars(d.severity_totals)}</div>
        </div>
      </div>

      <div class="card" style="margin-top:18px;">
        <div class="card-header"><span class="card-eyebrow">Recent scans</span></div>
        <div class="card-body no-pad">${recentScans(d.recent_scans)}</div>
      </div>
    `;

    mount.querySelector('[data-newscan]').onclick = () => openScanModal();
    mount.querySelectorAll('[data-scan]').forEach(row =>
      row.onclick = () => go(`scan/${row.dataset.scan}`));
    mount.querySelectorAll('[data-exp]').forEach(row =>
      row.onclick = () => go(`scan/${row.dataset.exp}`));
  }

  function kpiCard(k) {
    return `<div class="kpi">
      <div class="kpi-label">${e(k.label)}</div>
      <div class="kpi-value ${k.cls}">${e(k.value)}</div>
      ${k.foot ? `<div class="kpi-foot">${e(k.foot)}</div>` : ''}
    </div>`;
  }

  function trendChart(trend) {
    if (!trend.length) return emptyInline('No scored scans yet.');
    const max = 100;
    return `<div class="trend-wrap"><div class="bars">
      ${trend.map(t => {
        const h = Math.max(3, (t.score / max) * 150);
        const color = t.score >= 75 ? 'var(--low)' : t.score >= 60 ? 'var(--med)' : 'var(--high)';
        return `<div class="bar-col" title="${e(t.target)}: ${e(t.score)}/100">
          <span class="bar-val">${e(t.score)}</span>
          <div class="bar" style="height:${h}px;background:${color};"></div>
          <span class="bar-label">#${e(t.id)}</span>
        </div>`;
      }).join('')}
    </div></div>`;
  }

  function gradeDist(dist) {
    const order = ['A', 'B', 'C', 'D', 'F'];
    const colors = { A: '#22C55E', B: '#84CC16', C: '#F59E0B', D: '#F97316', F: '#EF4444' };
    const total = order.reduce((s, g) => s + (dist[g] || 0), 0);
    if (!total) return emptyInline('No graded projects yet.');
    const segs = order.filter(g => dist[g]).map(g => ({ label: g, value: dist[g], color: colors[g] }));
    return `<div class="donut-wrap">
      ${UI.donut(segs)}
      <div class="donut-legend">
        ${order.map(g => `<div class="legend-row">
          <span class="legend-dot" style="background:${colors[g]}"></span>
          Grade ${g} <span class="muted" style="margin-left:auto;font-family:var(--mono);">${dist[g] || 0}</span>
        </div>`).join('')}
      </div>
    </div>`;
  }

  function sevBars(totals) {
    const order = ['critical', 'high', 'medium', 'low'];
    const max = Math.max(1, ...order.map(s => totals[s] || 0));
    if (order.every(s => !totals[s])) return emptyInline('No open findings. ');
    return `<div class="sev-bars">${order.map(s => `
      <div class="sev-row">
        <span style="text-transform:capitalize;">${s}</span>
        <div class="sev-track"><div class="sev-fill" style="width:${((totals[s] || 0) / max) * 100}%;background:${SEV_COLORS[s]}"></div></div>
        <span class="mono" style="text-align:right;">${totals[s] || 0}</span>
      </div>`).join('')}</div>`;
  }

  function topExposures(items) {
    if (!items.length) return emptyInline('No critical or high exposures. Clean surface.');
    return `<table class="tbl"><tbody>
      ${items.map(x => `<tr class="clickable" data-exp="${x.scan_id}">
        <td>${UI.riskPill(x.severity)}</td>
        <td><div style="font-weight:600;">${e(x.title)}</div>
            <div class="muted" style="font-size:0.76rem;">${e(x.target)} · port ${e(x.port)}</div></td>
        <td class="mono muted" style="font-size:0.74rem;">${(x.cve || []).join(', ') || '-'}</td>
      </tr>`).join('')}
    </tbody></table>`;
  }

  function recentScans(scans) {
    if (!scans.length) return emptyInline('No scans yet. Run your first scan.');
    return `<table class="tbl">
      <thead><tr><th>#</th><th>Target</th><th>Profile</th><th>When</th><th>Grade</th><th></th></tr></thead>
      <tbody>${scans.map(s => `<tr class="clickable" data-scan="${s.id}">
        <td class="mono muted">${s.id}</td>
        <td class="mono">${e(s.target)}</td>
        <td><span class="profile-badge">${e(s.profile)}</span></td>
        <td class="muted">${UI.fmtRelative(s.timestamp)}</td>
        <td>${gradeOrStatus(s)}</td>
        <td class="mono muted">${triggerMark(s.trigger)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  }

  // ══════════════════════ PROJECTS ══════════════════════
  async function projects(mount) {
    mount.innerHTML = loading('Loading projects…');
    let list;
    try { list = await API.listProjects(); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }

    mount.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">Projects</div>
          <div class="page-sub">Group targets by client, environment, or engagement</div></div>
        <button class="btn btn-primary" data-new>+ New project</button>
      </div>
      ${list.length ? `<div class="kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(260px,1fr));">
        ${list.map(projectCard).join('')}
      </div>` : emptyState('projects', 'No projects yet',
        'Projects organize your scans. Create one to start monitoring a target.',
        'Create project', 'new')}
    `;

    const newBtn = mount.querySelector('[data-new]');
    if (newBtn) newBtn.onclick = openProjectModal;
    const emptyBtn = mount.querySelector('[data-action="new"]');
    if (emptyBtn) emptyBtn.onclick = openProjectModal;
    mount.querySelectorAll('[data-project]').forEach(card =>
      card.onclick = () => go(`project/${card.dataset.project}`));
  }

  function projectCard(p) {
    const latest = p.latest_scan;
    return `<div class="kpi" style="cursor:pointer;" data-project="${p.id}">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;">
        <div style="font-weight:600;font-size:1rem;overflow:hidden;text-overflow:ellipsis;">${e(p.name)}</div>
        ${latest ? UI.gradeBadge(latest.risk_grade) : ''}
      </div>
      <div class="muted" style="font-size:0.8rem;margin:6px 0 12px;min-height:2.4em;">${e(p.description || 'No description')}</div>
      <div style="display:flex;justify-content:space-between;font-size:0.76rem;color:var(--faint);">
        <span>${p.scan_count} scan${p.scan_count === 1 ? '' : 's'}</span>
        <span>${p.avg_score != null ? `avg ${p.avg_score}/100` : 'not scanned'}</span>
      </div>
    </div>`;
  }

  // ══════════════════════ PROJECT DETAIL ══════════════════════
  async function projectDetail(mount, id) {
    mount.innerHTML = loading('Loading project…');
    let p;
    try { p = await API.getProject(id); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }

    mount.innerHTML = `
      <div class="page-head">
        <div>
          <div class="page-sub"><a data-back style="cursor:pointer;">← Projects</a></div>
          <div class="page-title">${e(p.name)}</div>
          <div class="page-sub">${e(p.description || '')}</div>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="btn btn-ghost btn-sm" data-edit>Edit</button>
          <button class="btn btn-danger btn-sm" data-del>Delete</button>
          <button class="btn btn-primary" data-scan>${UI.icon('scan')} New scan</button>
        </div>
      </div>

      <div class="kpi-grid">
        ${kpiCard({ label: 'Scans', value: p.scan_count, cls: '' })}
        ${kpiCard({ label: 'Avg score', value: p.avg_score ?? '-', cls: scoreCls(p.avg_score), foot: '/ 100' })}
        ${kpiCard({ label: 'Latest grade', value: p.latest_scan?.risk_grade ?? '-', cls: '' })}
        ${kpiCard({ label: 'Last scanned', value: p.latest_scan ? UI.fmtRelative(p.latest_scan.timestamp) : '-', cls: '' })}
      </div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Authorised scope</span>
        <span class="card-count">${(p.allowed_targets || []).length ? `${p.allowed_targets.length} target${p.allowed_targets.length === 1 ? '' : 's'}` : 'no allowlist'}</span></div>
        <div class="card-body">${scopeList(p.allowed_targets)}</div></div>

      <div class="card">
        <div class="card-header"><span class="card-eyebrow">Scan history</span>
          <span class="card-count">${p.scans.length}</span></div>
        <div class="card-body no-pad">${scanHistory(p.scans)}</div>
      </div>
    `;

    mount.querySelector('[data-back]').onclick = () => go('projects');
    mount.querySelector('[data-scan]').onclick = () => openScanModal(p.id);
    mount.querySelector('[data-edit]').onclick = () => openProjectModal(p);
    mount.querySelector('[data-del]').onclick = async () => {
      const ok = await UI.confirm({ title: 'Delete project?',
        message: `This permanently deletes "${p.name}" and all ${p.scan_count} of its scans.`,
        confirmLabel: 'Delete project' });
      if (!ok) return;
      try { await API.deleteProject(p.id); UI.toast('Project deleted', 'success'); go('projects'); }
      catch (err) { UI.toast(err.message, 'error'); }
    };
    mount.querySelectorAll('[data-scanrow]').forEach(row =>
      row.querySelector('.td-actions')
        ? bindScanRow(row) : (row.onclick = () => go(`scan/${row.dataset.scanrow}`)));
  }

  function bindScanRow(row) {
    row.onclick = (ev) => {
      if (ev.target.closest('[data-cmp]')) return;
      go(`scan/${row.dataset.scanrow}`);
    };
    const rep = row.querySelector('[data-report]');
    if (rep) rep.onclick = (ev) => { ev.stopPropagation(); API.openReport(rep.dataset.report).catch(err => UI.toast(err.message, 'error')); };
  }

  function scopeList(targets) {
    if (!targets || !targets.length) {
      return `<p class="finding-empty">No allowlist set. Any target can be scanned in this project once you confirm authorisation on each scan. Add allowed targets under Edit to restrict scope.</p>`;
    }
    return `<div style="display:flex;flex-wrap:wrap;gap:6px;">${targets.map(t => `<span class="cve-tag">${e(t)}</span>`).join('')}</div>`;
  }

  function gradeOrStatus(s) {
    if (s.status && s.status !== 'completed') return statusPill(s.status);
    return UI.gradeBadge(s.risk_grade);
  }

  function statusPill(status) {
    const cls = { queued: 'pill-info', running: 'pill-open', failed: 'pill-high', cancelled: 'pill-closed', completed: 'pill-low' }[status] || 'pill-info';
    return `<span class="pill ${cls}">${e(status)}</span>`;
  }

  function triggerMark(trigger) {
    if (trigger === 'scheduled') return '<span title="scheduled">&#x27F3;</span>';
    if (trigger === 'api') return '<span title="API key">api</span>';
    return '';
  }

  function scanHistory(scans) {
    if (!scans.length) return emptyInline('No scans in this project yet.');
    return `<table class="tbl">
      <thead><tr><th>#</th><th>Target</th><th>Profile</th><th>Scanned</th><th>Score</th><th>Grade</th><th></th></tr></thead>
      <tbody>${scans.map(s => `<tr class="clickable" data-scanrow="${s.id}">
        <td class="mono muted">${s.id}</td>
        <td class="mono">${e(s.target)} <span class="muted">${triggerMark(s.trigger)}</span></td>
        <td><span class="profile-badge">${e(s.profile)}</span></td>
        <td class="muted">${UI.fmtDate(s.timestamp)}</td>
        <td class="mono">${s.risk_score ?? '-'}</td>
        <td>${gradeOrStatus(s)}</td>
        <td class="td-actions">${s.status === 'completed' ? `<button class="btn btn-ghost btn-sm" data-cmp data-report="${s.id}">Report</button>` : ''}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  }

  // ══════════════════════ SCAN DETAIL ══════════════════════
  async function scanDetail(mount, id) {
    mount.innerHTML = loading('Loading scan…');
    let s;
    try { s = await API.getScan(id); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }

    if (s.status === 'queued' || s.status === 'running') { watchScan(mount, s); return; }
    if (s.status === 'failed' || s.status === 'cancelled') { failedScan(mount, s); return; }

    const risk = s.risk || {};
    const openPorts = (s.ports || []).filter(p => p.state === 'open')
      .sort((a, b) => riskRank(a.risk) - riskRank(b.risk) || a.port - b.port);
    const intel = s.intel || [];
    const compliance = s.compliance || [];

    mount.innerHTML = `
      <div class="page-head">
        <div><div class="page-sub"><a data-back style="cursor:pointer;">← Back</a></div>
          <div class="detail-strip">
            <span class="detail-target">${e(s.target)}</span>
            <span class="profile-badge">${e(s.profile)}</span>
            ${UI.gradeBadge(risk.grade, true)}
          </div>
          <div class="page-sub">Scan #${e(s.id)} · ${UI.fmtDate(s.timestamp)} · ${e(s.engine || 'nmap')} engine${s.trigger === 'scheduled' ? ' · scheduled' : s.trigger === 'api' ? ' · via API key' : ''}${s.duration_seconds != null ? ` · ${e(s.duration_seconds)}s` : ''}${s.authorised ? ' · authorisation recorded' : ''}</div>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="btn btn-ghost" data-report>Open report</button>
          <button class="btn btn-danger btn-sm" data-del>Delete</button>
        </div>
      </div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Executive summary</span>
        <span class="card-count">score ${risk.score ?? '-'}/100</span></div>
        <div class="card-body"><p class="summary-text">${e(s.summary)}</p></div></div>

      ${intel.length ? `<div class="card"><div class="card-header">
        <span class="card-eyebrow">Vulnerability intelligence</span>
        <span class="card-count">${intel.length} finding${intel.length === 1 ? '' : 's'}</span></div>
        <div class="card-body"><div class="finding-list">${intel.map(intelFinding).join('')}</div></div></div>` : ''}

      <div class="card"><div class="card-header"><span class="card-eyebrow">Open ports & services</span>
        <span class="card-count">${openPorts.length} open</span></div>
        <div class="card-body no-pad">${portsTable(openPorts)}</div></div>

      <div class="findings-grid" style="margin-top:18px;">
        <div class="card"><div class="card-header"><span class="card-eyebrow">Score breakdown</span></div>
          <div class="card-body">${breakdown(risk)}</div></div>
        <div class="card"><div class="card-header"><span class="card-eyebrow">OWASP Top 10 mapping</span>
          <span class="card-count">${compliance.length}</span></div>
          <div class="card-body">${complianceList(compliance)}</div></div>
      </div>

      ${credSection(s.credential_checks)}

      <div class="card" style="margin-top:18px;"><div class="card-header card-header--toggle" data-rawtoggle>
        <span class="card-eyebrow">Raw NSE output</span><span class="toggle-icon" id="rawTog">▸ expand</span></div>
        <div class="card-body hidden" id="rawBody"><pre class="raw-output">${e(rawOutput(s.ports))}</pre></div></div>
    `;

    mount.querySelector('[data-back]').onclick = () => history.length > 1 ? history.back() : go('dashboard');
    mount.querySelector('[data-report]').onclick = () => API.openReport(s.id).catch(err => UI.toast(err.message, 'error'));
    mount.querySelector('[data-del]').onclick = async () => {
      const ok = await UI.confirm({ title: 'Delete scan?', message: `Scan #${s.id} of ${s.target} will be permanently removed.`, confirmLabel: 'Delete scan' });
      if (!ok) return;
      try { await API.deleteScan(s.id); UI.toast('Scan deleted', 'success');
        go(s.project_id ? `project/${s.project_id}` : 'dashboard'); }
      catch (err) { UI.toast(err.message, 'error'); }
    };
    const rawToggle = mount.querySelector('[data-rawtoggle]');
    rawToggle.onclick = () => {
      const body = mount.querySelector('#rawBody');
      const tog = mount.querySelector('#rawTog');
      const hidden = body.classList.toggle('hidden');
      tog.textContent = hidden ? '▸ expand' : '▾ collapse';
    };
  }

  // Live progress for a queued/running scan: polls until it settles.
  function watchScan(mount, s) {
    let timer = null;
    const render = (scan) => {
      mount.innerHTML = `<div class="card"><div class="card-body"><div class="scanning">
        <div class="pulse-ring"></div>
        <div class="scanning-text"><div class="scanning-label">${scan.status === 'queued' ? 'Queued' : 'Scanning'} ${e(scan.target)}</div>
          <div class="scanning-sub">${e(scan.profile)} profile${scan.credential_checks ? ' with credential checks' : ''} · scan #${e(scan.id)} · ${e(scan.status)}</div></div>
        <div style="margin-left:auto;display:flex;gap:8px;">
          <button class="btn btn-ghost btn-sm" data-cancel>Cancel scan</button>
        </div>
      </div></div></div>`;
      mount.querySelector('[data-cancel]').onclick = async () => {
        try { await API.cancelScan(scan.id); UI.toast('Scan cancelled', 'info'); }
        catch (err) { UI.toast(err.message, 'error'); }
      };
    };
    render(s);
    const poll = async () => {
      if (!document.body.contains(mount) || currentPath() !== `scan/${s.id}`) return;
      try {
        const scan = await API.getScan(s.id);
        if (scan.status === 'queued' || scan.status === 'running') { timer = setTimeout(poll, 1500); return; }
        if (scan.status === 'completed') UI.toast(`Scan complete: grade ${scan.risk.grade}`, 'success');
        else if (scan.status === 'failed') UI.toast('Scan failed', 'error');
        go(`scan/${s.id}`);
      } catch (err) { UI.toast(err.message, 'error'); }
    };
    timer = setTimeout(poll, 1000);
  }

  function failedScan(mount, s) {
    const failed = s.status === 'failed';
    mount.innerHTML = `
      <div class="page-head">
        <div><div class="page-sub"><a data-back style="cursor:pointer;">← Back</a></div>
          <div class="detail-strip"><span class="detail-target">${e(s.target)}</span>
            <span class="profile-badge">${e(s.profile)}</span>${statusPill(s.status)}</div>
          <div class="page-sub">Scan #${e(s.id)} · ${UI.fmtDate(s.timestamp)}${s.duration_seconds != null ? ` · ${e(s.duration_seconds)}s` : ''}</div>
        </div>
        <div style="display:flex;gap:10px;">
          <button class="btn btn-primary btn-sm" data-retry>Scan again</button>
          <button class="btn btn-danger btn-sm" data-del>Delete</button>
        </div>
      </div>
      <div class="card"><div class="card-header"><span class="card-eyebrow">${failed ? 'Scan failed' : 'Scan cancelled'}</span></div>
        <div class="card-body"><p class="summary-text">${e(s.error || (failed ? 'The scan did not complete.' : 'The scan was cancelled before it finished.'))}</p>
        ${failed ? '<p class="muted" style="font-size:0.82rem;margin-top:10px;">Common causes: the host is unreachable from this network, it drops all probes, or the scan exceeded its time ceiling. Try the quick profile, or check the target from the machine running PortWatch.</p>' : ''}
        </div></div>`;
    mount.querySelector('[data-back]').onclick = () => go(s.project_id ? `project/${s.project_id}` : 'dashboard');
    mount.querySelector('[data-retry]').onclick = () => openScanModal(s.project_id, s.target);
    mount.querySelector('[data-del]').onclick = async () => {
      const ok = await UI.confirm({ title: 'Delete scan?', message: `Scan #${s.id} will be permanently removed.`, confirmLabel: 'Delete scan' });
      if (!ok) return;
      try { await API.deleteScan(s.id); UI.toast('Scan deleted', 'success'); go(s.project_id ? `project/${s.project_id}` : 'dashboard'); }
      catch (err) { UI.toast(err.message, 'error'); }
    };
  }

  function intelFinding(f) {
    const color = SEV_COLORS[f.severity] || '#64748B';
    const cves = (f.cve || []).map(c => `<span class="cve-tag">${e(c)}</span>`).join(' ');
    const cvss = (typeof f.cvss === 'number') ? `<span class="muted" style="font-size:0.74rem;">CVSS ${f.cvss.toFixed(1)}</span>` : '';
    return `<div class="finding">
      <div class="finding-sev" style="background:${color}"></div>
      <div class="finding-body">
        <div class="finding-title">${UI.riskPill(f.severity)} ${e(f.title)} ${cves} ${cvss}</div>
        <div class="finding-meta">Port ${e(f.port)} · ${e(f.service)} · <em>${e(f.confidence)}</em> · ${e(f.evidence)}</div>
        <div class="finding-fix"><strong>Fix:</strong> ${e(f.remediation)}</div>
      </div>
    </div>`;
  }

  function portsTable(ports) {
    if (!ports.length) return emptyInline('No open ports detected in the scanned range.');
    return `<table class="tbl">
      <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Risk</th></tr></thead>
      <tbody>${ports.map(p => `<tr>
        <td class="mono">${e(p.port)}</td>
        <td>${UI.statePill(p.state)}</td>
        <td>${e(p.service)}</td>
        <td class="muted">${e(p.version)}</td>
        <td>${UI.riskPill(p.risk)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  }

  function breakdown(risk) {
    const items = risk.breakdown || [];
    if (!items.length) return emptyInline('Perfect score, no deductions.');
    return `<div class="breakdown-list">
      ${items.map(b => `<div class="breakdown-row"><span>${e(b.reason)}</span><span class="breakdown-pts">${e(b.points)}</span></div>`).join('')}
      <div class="breakdown-row" style="font-weight:700;border-top:2px solid var(--border);margin-top:4px;padding-top:8px;">
        <span>Final score</span><span class="mono">${e(risk.score)}/100</span></div>
    </div>`;
  }

  function complianceList(tags) {
    if (!tags.length) return emptyInline('No framework mappings for this scan.');
    return `<div class="finding-list">${tags.map(t => `
      <div class="finding"><div class="finding-sev" style="background:var(--med)"></div>
        <div class="finding-body">
          <div class="finding-title">${e(t.category)}: ${e(t.name)}</div>
          <ul style="margin:6px 0 0 16px;font-size:0.8rem;color:var(--muted);">
            ${t.evidence.map(ev => `<li>${e(ev)}</li>`).join('')}
          </ul>
        </div></div>`).join('')}</div>`;
  }

  function credSection(cc) {
    if (!cc) return '';
    const http = cc.http_login_findings || [];
    const db = cc.db_findings || [];
    if (!http.length && !db.length && !cc.error)
      return `<div class="card" style="margin-top:18px;"><div class="card-header"><span class="card-eyebrow">Credential & lockout checks</span></div>
        <div class="card-body"><p class="finding-empty">Enabled, but no login endpoints or credential-protected services were found.</p></div></div>`;
    const rows = [
      ...http.map(f => credRow(f.url, f.verdict, f.detail)),
      ...db.map(d => credRow(`Port ${d.port}`, d.vulnerable ? 'vulnerable' : 'ok', `${d.check}: ${d.detail}`)),
    ].join('');
    return `<div class="card" style="margin-top:18px;"><div class="card-header"><span class="card-eyebrow">Credential & lockout checks</span></div>
      <div class="card-body no-pad"><table class="tbl"><thead><tr><th>Endpoint</th><th>Verdict</th><th>Detail</th></tr></thead>
      <tbody>${rows}</tbody></table>
      ${cc.error ? `<p class="finding-empty" style="padding:12px 18px;">Partial failure: ${e(cc.error)}</p>` : ''}</div></div>`;
  }

  function credRow(label, verdict, detail) {
    const good = ['throttled', 'lockout', 'captcha', 'ok'].includes(verdict);
    const pill = `<span class="pill ${good ? 'pill-low' : 'pill-high'}">${e(verdict)}</span>`;
    return `<tr><td class="mono" style="font-size:0.8rem;">${e(label)}</td><td>${pill}</td><td class="muted">${e(detail)}</td></tr>`;
  }

  function rawOutput(ports) {
    const lines = [];
    (ports || []).forEach(p => {
      const scripts = p.scripts || {};
      const names = Object.keys(scripts);
      if (!names.length) return;
      lines.push(`── Port ${p.port} (${p.service}) ──`);
      names.forEach(n => { lines.push(`  [${n}]`); lines.push('  ' + String(scripts[n]).replace(/\n/g, '\n  ')); });
      lines.push('');
    });
    return lines.length ? lines.join('\n') : 'No NSE script output in this scan.';
  }

  // ══════════════════════ SCHEDULES ══════════════════════
  async function schedules(mount) {
    mount.innerHTML = loading('Loading schedules…');
    let list, projects;
    try { [list, projects] = await Promise.all([API.listSchedules(), API.listProjects()]); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }
    const projName = (pid) => (projects.find(p => p.id === pid) || {}).name || `#${pid}`;

    mount.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">Scheduled scans</div>
          <div class="page-sub">Automatically re-scan targets on a cadence for continuous monitoring</div></div>
        <button class="btn btn-primary" data-new ${projects.length ? '' : 'disabled title="Create a project first"'}>+ New schedule</button>
      </div>
      ${list.length ? `<div class="card"><div class="card-body no-pad"><table class="tbl">
        <thead><tr><th>Target</th><th>Project</th><th>Profile</th><th>Every</th><th>Last run</th><th>Next run</th><th>Status</th><th></th></tr></thead>
        <tbody>${list.map(s => `<tr>
          <td class="mono">${e(s.target)}</td>
          <td>${e(projName(s.project_id))}</td>
          <td><span class="profile-badge">${e(s.profile)}</span></td>
          <td class="muted">${e(s.interval_hours)}h</td>
          <td class="muted">${s.last_run ? UI.fmtRelative(s.last_run) : 'never'}</td>
          <td class="muted">${s.enabled ? UI.fmtRelative(s.next_run) : '-'}</td>
          <td><span class="pill ${s.enabled ? 'pill-low' : 'pill-closed'}">${s.enabled ? 'active' : 'paused'}</span>
              ${s.authorised ? '' : '<span class="pill pill-high" title="No authorisation recorded for this target">unauthorised</span>'}</td>
          <td class="td-actions">
            ${s.authorised ? `<button class="btn btn-ghost btn-sm" data-run="${s.id}">Run now</button>`
                           : `<button class="btn btn-ghost btn-sm" data-authorise="${s.id}">Confirm authorisation</button>`}
            <button class="btn btn-ghost btn-sm" data-toggle="${s.id}" data-en="${s.enabled}">${s.enabled ? 'Pause' : 'Resume'}</button>
            <button class="btn btn-danger btn-sm" data-del="${s.id}">✕</button>
          </td>
        </tr>`).join('')}</tbody></table></div></div>`
        : emptyState('schedule', 'No schedules yet',
          'Schedule recurring scans to catch new exposures as soon as they appear.',
          projects.length ? 'Create schedule' : '', 'new')}
    `;

    const newBtn = mount.querySelector('[data-new]');
    if (newBtn && !newBtn.disabled) newBtn.onclick = () => openScheduleModal(projects);
    const emptyBtn = mount.querySelector('[data-action="new"]');
    if (emptyBtn) emptyBtn.onclick = () => openScheduleModal(projects);

    mount.querySelectorAll('[data-run]').forEach(b => b.onclick = async () => {
      b.disabled = true; b.textContent = 'Queuing…';
      try { const r = await API.runSchedule(b.dataset.run);
        UI.toast(`Scan #${r.scan.id} queued`, 'success'); go(`scan/${r.scan.id}`); }
      catch (err) { UI.toast(err.message, 'error'); b.disabled = false; b.textContent = 'Run now'; }
    });
    mount.querySelectorAll('[data-authorise]').forEach(b => b.onclick = async () => {
      const ok = await UI.confirm({ title: 'Confirm authorisation', danger: false, confirmLabel: 'I am authorised',
        message: 'Confirm that you own this target or have explicit written permission to scan it on a schedule. This consent is recorded in the audit log.' });
      if (!ok) return;
      try { await API.updateSchedule(b.dataset.authorise, { authorised: true }); UI.toast('Authorisation recorded', 'success'); go('schedules'); }
      catch (err) { UI.toast(err.message, 'error'); }
    });
    mount.querySelectorAll('[data-toggle]').forEach(b => b.onclick = async () => {
      try { await API.updateSchedule(b.dataset.toggle, { enabled: b.dataset.en !== 'true' }); go('schedules'); }
      catch (err) { UI.toast(err.message, 'error'); }
    });
    mount.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
      const ok = await UI.confirm({ title: 'Delete schedule?', message: 'This stops the recurring scan.', confirmLabel: 'Delete' });
      if (!ok) return;
      try { await API.deleteSchedule(b.dataset.del); UI.toast('Schedule deleted', 'success'); go('schedules'); }
      catch (err) { UI.toast(err.message, 'error'); }
    });
  }

  // ══════════════════════ SETTINGS ══════════════════════
  async function settings(mount) {
    mount.innerHTML = loading('Loading settings…');
    let channels, health, apiKeys, audit;
    try { [channels, health, apiKeys, audit] = await Promise.all([API.listChannels(), API.health(), API.listApiKeys(), API.audit(50)]); }
    catch (err) { mount.innerHTML = errorState(err.message); return; }
    const user = API.currentUser();

    mount.innerHTML = `
      <div class="page-head"><div><div class="page-title">Settings</div>
        <div class="page-sub">Account, notifications, and engine status</div></div></div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Account</span>
          <button class="btn btn-ghost btn-sm" data-logoutall title="Invalidate every signed-in device, including this one">Sign out everywhere</button></div>
        <div class="card-body">
          <div class="form-row">
            <div class="field"><label>Name</label><div class="input" style="background:var(--surface2);">${e(user.name)}</div></div>
            <div class="field"><label>Email</label><div class="input" style="background:var(--surface2);">${e(user.email)}</div></div>
            <div class="field"><label>Role</label><div class="input" style="background:var(--surface2);text-transform:capitalize;">${e(user.role)}</div></div>
          </div>
          <form id="pwForm" style="margin-top:8px;">
            <div class="form-row">
              <div class="field"><label>Current password</label><input class="input" id="pwCur" type="password" autocomplete="current-password"/></div>
              <div class="field"><label>New password</label><input class="input" id="pwNew" type="password" autocomplete="new-password" placeholder="At least 8 characters"/></div>
              <div class="field"><label>Confirm new password</label><input class="input" id="pwNew2" type="password" autocomplete="new-password"/></div>
            </div>
            <button class="btn btn-primary btn-sm" type="submit">Change password</button>
            <span class="muted" style="font-size:0.76rem;margin-left:10px;">Changing your password signs out all other devices.</span>
          </form>
        </div></div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">API keys</span>
        <button class="btn btn-primary btn-sm" data-newkey>+ New key</button></div>
        <div class="card-body no-pad" id="apiKeysBody">${apiKeysTable(apiKeys)}</div>
        <div class="card-body" style="padding-top:0;"><p class="muted" style="font-size:0.78rem;">Use a key for scripted scans: <code class="mono">curl -H "X-API-Key: pwp_..." -H "Content-Type: application/json" -d '{"project_id":1,"target":"host","profile":"quick","authorised":true}' ${e(location.origin)}/api/scan?wait=1</code></p></div></div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Scan engine</span></div>
        <div class="card-body">
          <p style="font-size:0.9rem;">Engine mode: <b class="mono" style="color:${health.engine === 'nmap' ? 'var(--low)' : 'var(--med)'}">${e(health.engine)}</b></p>
          <p class="muted" style="font-size:0.82rem;margin-top:6px;">
            ${health.engine === 'nmap'
              ? `Real nmap is installed; scans probe live targets using ${health.scan_type === 'syn' ? 'SYN (-sS)' : 'TCP connect (-sT)'} scans.`
              : 'nmap is not available in this environment, so PortWatch produces realistic simulated scans. Install nmap and restart to scan live targets.'}
          </p>
        </div></div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Notification channels</span>
        <button class="btn btn-primary btn-sm" data-newch>+ Add channel</button></div>
        <div class="card-body no-pad">${channelsTable(channels)}</div></div>

      <div class="card"><div class="card-header"><span class="card-eyebrow">Audit log</span>
        <span class="card-count">${user.role === 'admin' ? 'all users' : 'your activity'} · last ${audit.length}</span></div>
        <div class="card-body no-pad">${auditTable(audit)}</div></div>
    `;

    mount.querySelector('[data-newch]').onclick = openChannelModal;
    mount.querySelector('[data-logoutall]').onclick = async () => {
      const ok = await UI.confirm({ title: 'Sign out everywhere?', message: 'Every session and refresh token for your account will be invalidated, including this one.', confirmLabel: 'Sign out everywhere' });
      if (!ok) return;
      try { await API.logoutAll(); } catch (err) { UI.toast(err.message, 'error'); return; }
      API.clearSession(); location.hash = ''; location.reload();
    };
    mount.querySelector('#pwForm').onsubmit = async (ev) => {
      ev.preventDefault();
      const cur = mount.querySelector('#pwCur').value, nw = mount.querySelector('#pwNew').value, nw2 = mount.querySelector('#pwNew2').value;
      if (nw !== nw2) { UI.toast('New passwords do not match', 'error'); return; }
      try {
        const session = await API.changePassword({ current_password: cur, new_password: nw });
        API.setSession(session);
        UI.toast('Password changed. Other devices were signed out.', 'success');
        go('settings');
      } catch (err) { UI.toast(err.message, 'error'); }
    };
    mount.querySelector('[data-newkey]').onclick = openApiKeyModal;
    mount.querySelectorAll('[data-revoke]').forEach(b => b.onclick = async () => {
      const ok = await UI.confirm({ title: 'Revoke API key?', message: 'Scripts using this key will stop working immediately.', confirmLabel: 'Revoke' });
      if (!ok) return;
      try { await API.revokeApiKey(b.dataset.revoke); UI.toast('Key revoked', 'success'); go('settings'); }
      catch (err) { UI.toast(err.message, 'error'); }
    });
    mount.querySelectorAll('[data-test]').forEach(b => b.onclick = async () => {
      b.disabled = true; b.textContent = 'Sending…';
      try { const r = await API.testChannel(b.dataset.test);
        UI.toast(r.ok ? 'Test sent' : `Test failed: ${r.detail}`, r.ok ? 'success' : 'error'); }
      catch (err) { UI.toast(err.message, 'error'); }
      finally { b.disabled = false; b.textContent = 'Test'; }
    });
    mount.querySelectorAll('[data-delch]').forEach(b => b.onclick = async () => {
      const ok = await UI.confirm({ title: 'Delete channel?', message: 'You will stop receiving alerts here.', confirmLabel: 'Delete' });
      if (!ok) return;
      try { await API.deleteChannel(b.dataset.delch); UI.toast('Channel deleted', 'success'); go('settings'); }
      catch (err) { UI.toast(err.message, 'error'); }
    });
  }

  function apiKeysTable(keys) {
    const active = keys.filter(k => !k.revoked);
    if (!active.length) return emptyInline('No API keys. Create one to run scans from scripts or CI.');
    return `<table class="tbl">
      <thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Last used</th><th></th></tr></thead>
      <tbody>${active.map(k => `<tr>
        <td>${e(k.name)}</td>
        <td class="mono muted" style="font-size:0.8rem;">${e(k.hint)}</td>
        <td class="muted">${UI.fmtDate(k.created_at)}</td>
        <td class="muted">${k.last_used_at ? UI.fmtRelative(k.last_used_at) : 'never'}</td>
        <td class="td-actions"><button class="btn btn-danger btn-sm" data-revoke="${k.id}">Revoke</button></td>
      </tr>`).join('')}</tbody></table>`;
  }

  function auditTable(rows) {
    if (!rows.length) return emptyInline('No audit events yet.');
    return `<table class="tbl">
      <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td class="muted" style="white-space:nowrap;">${UI.fmtDate(r.created_at)}</td>
        <td class="mono" style="font-size:0.78rem;">${e(r.actor || '-')}</td>
        <td class="mono" style="font-size:0.78rem;">${e(r.action)}</td>
        <td class="muted" style="font-size:0.78rem;">${e(r.detail || (r.resource_type ? `${r.resource_type} #${r.resource_id}` : ''))}</td>
        <td class="mono muted" style="font-size:0.74rem;">${e(r.ip || '')}</td>
      </tr>`).join('')}</tbody></table>`;
  }

  function openApiKeyModal() {
    UI.modal({
      title: 'New API key',
      bodyHTML: `<div class="field"><label>Name</label>
          <input class="input" id="kName" placeholder="ci-pipeline, nightly-script..."/></div>
        <div id="kResult"></div>`,
      footHTML: `<button class="btn btn-ghost" data-cancel>Close</button>
                 <button class="btn btn-primary" data-save>Create key</button>`,
      onMount: (host, close) => {
        host.querySelector('#kName').focus();
        host.querySelector('[data-cancel]').onclick = () => { close(); go('settings'); };
        host.querySelector('[data-save]').onclick = async () => {
          const name = host.querySelector('#kName').value.trim();
          if (!name) { UI.toast('Name is required', 'error'); return; }
          try {
            const k = await API.createApiKey(name);
            host.querySelector('#kResult').innerHTML = `<p class="muted" style="font-size:0.8rem;margin-top:10px;">Copy this key now. It is shown once and stored hashed.</p>
              <pre class="raw-output" style="margin-top:6px;user-select:all;">${e(k.key)}</pre>`;
            host.querySelector('[data-save]').disabled = true;
          } catch (err) { UI.toast(err.message, 'error'); }
        };
      },
    });
  }

  function channelsTable(channels) {
    if (!channels.length) return emptyInline('No channels yet. Add one to get alerted when a scan grades poorly.');
    return `<table class="tbl">
      <thead><tr><th>Type</th><th>Destination</th><th>Alert when grade ≤</th><th>Status</th><th></th></tr></thead>
      <tbody>${channels.map(c => `<tr>
        <td style="text-transform:capitalize;">${e(c.kind)}</td>
        <td class="mono" style="font-size:0.8rem;">${e(c.target)}</td>
        <td>${UI.gradeBadge(c.min_grade)}</td>
        <td><span class="pill ${c.enabled ? 'pill-low' : 'pill-closed'}">${c.enabled ? 'on' : 'off'}</span></td>
        <td class="td-actions">
          <button class="btn btn-ghost btn-sm" data-test="${c.id}">Test</button>
          <button class="btn btn-danger btn-sm" data-delch="${c.id}">✕</button>
        </td></tr>`).join('')}</tbody></table>`;
  }

  // ══════════════════════ MODALS ══════════════════════
  async function openScanModal(preselectProject, presetTarget) {
    let projects, profiles;
    try { [projects, profiles] = await Promise.all([API.listProjects(), API.profiles()]); }
    catch (err) { UI.toast(err.message, 'error'); return; }
    if (!projects.length) {
      UI.toast('Create a project first', 'info'); go('projects'); return;
    }
    const profOpts = Object.entries(profiles).map(([k, v]) =>
      `<option value="${k}" ${k === 'standard' ? 'selected' : ''}>${e(v.label)}: ${e(v.description)}${v.max_seconds ? ` (max ${Math.round(v.max_seconds / 60)} min)` : ''}</option>`).join('');
    const projOpts = projects.map(p =>
      `<option value="${p.id}" ${p.id === preselectProject ? 'selected' : ''}>${e(p.name)}</option>`).join('');
    const scopeOf = (pid) => (projects.find(p => p.id === pid) || {}).allowed_targets || [];

    UI.modal({
      title: 'Run a scan',
      bodyHTML: `
        <div class="field"><label>Target</label>
          <input class="input" id="mTarget" placeholder="example.com or 192.168.1.1" autocomplete="off" spellcheck="false" value="${e(presetTarget || '')}"/>
          <div class="muted" id="mScope" style="font-size:0.74rem;margin-top:6px;"></div></div>
        <div class="form-row">
          <div class="field"><label>Project</label><select class="select" id="mProject">${projOpts}</select></div>
          <div class="field"><label>Profile</label><select class="select" id="mProfile">${profOpts}</select></div>
        </div>
        <label class="check" style="margin-top:4px;">
          <input type="checkbox" id="mCred"/> Credential & lockout checks
          <span class="muted" style="font-size:0.74rem;">(authorised targets only)</span>
        </label>
        <label class="check" style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:8px;">
          <input type="checkbox" id="mAuth"/> <b>I am authorised to scan this target.</b>
          <span class="muted" style="font-size:0.74rem;">I own it or hold explicit written permission. This consent is recorded with the scan.</span>
        </label>
        <p class="muted" style="font-size:0.76rem;margin-top:12px;">Unauthorised port scanning may be illegal. The scan is refused without this confirmation.</p>`,
      footHTML: `<button class="btn btn-ghost" data-cancel>Cancel</button>
                 <button class="btn btn-primary" data-run>Start scan</button>`,
      onMount: (host, close) => {
        const target = host.querySelector('#mTarget');
        target.focus();
        host.querySelector('[data-cancel]').onclick = close;
        const run = host.querySelector('[data-run]');
        const projSel = host.querySelector('#mProject');
        const showScope = () => {
          const scope = scopeOf(parseInt(projSel.value, 10));
          host.querySelector('#mScope').textContent = scope.length
            ? `Project scope: ${scope.join(', ')}` : 'Project has no allowlist; any target is accepted with your confirmation.';
        };
        projSel.onchange = showScope; showScope();
        const doRun = async () => {
          const payload = {
            target: target.value.trim(),
            project_id: parseInt(projSel.value, 10),
            profile: host.querySelector('#mProfile').value,
            credential_checks: host.querySelector('#mCred').checked,
            authorised: host.querySelector('#mAuth').checked,
          };
          if (!payload.target) { UI.toast('Enter a target', 'error'); return; }
          if (!payload.authorised) { UI.toast('Confirm you are authorised to scan this target', 'error'); return; }
          close();
          runScanWithProgress(payload);
        };
        run.onclick = doRun;
        target.onkeydown = (ev) => { if (ev.key === 'Enter') doRun(); };
      },
    });
  }

  function runScanWithProgress(payload) {
    const mount = document.getElementById('viewMount');
    mount.innerHTML = `<div class="card"><div class="card-body"><div class="scanning">
      <div class="pulse-ring"></div>
      <div class="scanning-text"><div class="scanning-label">Queuing scan of ${e(payload.target)}</div>
        <div class="scanning-sub">${e(payload.profile)} profile${payload.credential_checks ? ' with credential checks' : ''}…</div></div>
    </div></div></div>`;
    API.runScan(payload)
      .then(scan => {
        if (scan.status === 'completed') UI.toast(`Scan complete: grade ${scan.risk.grade}`, 'success');
        else if (scan.status === 'failed') UI.toast('Scan failed', 'error');
        go(`scan/${scan.id}`);   // scan detail polls while queued/running
      })
      .catch(err => { UI.toast(err.message, 'error'); go(`project/${payload.project_id}`); });
  }

  function openProjectModal(existing) {
    const isEdit = existing && existing.id;
    UI.modal({
      title: isEdit ? 'Edit project' : 'New project',
      bodyHTML: `
        <div class="field"><label>Name</label>
          <input class="input" id="pName" value="${isEdit ? e(existing.name) : ''}" placeholder="Client A - Web Estate"/></div>
        <div class="field"><label>Description</label>
          <textarea class="textarea" id="pDesc" placeholder="External perimeter, production hosts…">${isEdit ? e(existing.description) : ''}</textarea></div>
        <div class="field"><label>Allowed targets <span class="muted" style="font-weight:400;">(optional scope allowlist, one per line, *.example.com wildcards ok)</span></label>
          <textarea class="textarea" id="pScope" placeholder="scanme.example.com&#10;*.corp.example&#10;10.0.4.11" style="font-family:var(--mono);font-size:0.82rem;">${isEdit ? e((existing.allowed_targets || []).join('\n')) : ''}</textarea></div>`,
      footHTML: `<button class="btn btn-ghost" data-cancel>Cancel</button>
                 <button class="btn btn-primary" data-save>${isEdit ? 'Save' : 'Create'}</button>`,
      onMount: (host, close) => {
        host.querySelector('#pName').focus();
        host.querySelector('[data-cancel]').onclick = close;
        host.querySelector('[data-save]').onclick = async () => {
          const payload = { name: host.querySelector('#pName').value.trim(),
                            description: host.querySelector('#pDesc').value.trim(),
                            allowed_targets: host.querySelector('#pScope').value };
          if (!payload.name) { UI.toast('Name is required', 'error'); return; }
          try {
            if (isEdit) { await API.updateProject(existing.id, payload); UI.toast('Project updated', 'success'); close(); go(`project/${existing.id}`); }
            else { const p = await API.createProject(payload); UI.toast('Project created', 'success'); close(); go(`project/${p.id}`); }
          } catch (err) { UI.toast(err.message, 'error'); }
        };
      },
    });
  }

  async function openScheduleModal(projects) {
    let profiles;
    try { profiles = await API.profiles(); } catch { profiles = {}; }
    const profOpts = Object.entries(profiles).map(([k, v]) =>
      `<option value="${k}" ${k === 'standard' ? 'selected' : ''}>${e(v.label)}</option>`).join('');
    const projOpts = projects.map(p => `<option value="${p.id}">${e(p.name)}</option>`).join('');
    UI.modal({
      title: 'New scheduled scan',
      bodyHTML: `
        <div class="field"><label>Target</label><input class="input" id="sTarget" placeholder="example.com"/></div>
        <div class="form-row">
          <div class="field"><label>Project</label><select class="select" id="sProject">${projOpts}</select></div>
          <div class="field"><label>Profile</label><select class="select" id="sProfile">${profOpts}</select></div>
        </div>
        <div class="form-row">
          <div class="field"><label>Run every (hours)</label><input class="input" id="sInterval" type="number" value="24" min="1" max="720"/></div>
        </div>
        <label class="check"><input type="checkbox" id="sCred"/> Credential & lockout checks</label>
        <label class="check" style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:8px;">
          <input type="checkbox" id="sAuth"/> <b>I am authorised to scan this target on a schedule.</b>
        </label>`,
      footHTML: `<button class="btn btn-ghost" data-cancel>Cancel</button>
                 <button class="btn btn-primary" data-save>Create schedule</button>`,
      onMount: (host, close) => {
        host.querySelector('#sTarget').focus();
        host.querySelector('[data-cancel]').onclick = close;
        host.querySelector('[data-save]').onclick = async () => {
          const payload = {
            target: host.querySelector('#sTarget').value.trim(),
            project_id: parseInt(host.querySelector('#sProject').value, 10),
            profile: host.querySelector('#sProfile').value,
            interval_hours: parseInt(host.querySelector('#sInterval').value, 10),
            credential_checks: host.querySelector('#sCred').checked,
            authorised: host.querySelector('#sAuth').checked,
          };
          if (!payload.target) { UI.toast('Enter a target', 'error'); return; }
          if (!payload.authorised) { UI.toast('Confirm you are authorised to scan this target', 'error'); return; }
          try { await API.createSchedule(payload); UI.toast('Schedule created', 'success'); close(); go('schedules'); }
          catch (err) { UI.toast(err.message, 'error'); }
        };
      },
    });
  }

  function openChannelModal() {
    UI.modal({
      title: 'Add notification channel',
      bodyHTML: `
        <div class="field"><label>Type</label>
          <select class="select" id="cKind"><option value="email">Email</option><option value="webhook">Webhook (Slack-compatible)</option></select></div>
        <div class="field"><label>Destination</label>
          <input class="input" id="cTarget" placeholder="soc@company.com or https://hooks.slack.com/…"/></div>
        <div class="field"><label>Alert when grade is at or below</label>
          <select class="select" id="cGrade">
            <option value="A">A (any scan)</option><option value="B">B</option>
            <option value="C" selected>C</option><option value="D">D</option><option value="F">F (worst only)</option>
          </select></div>`,
      footHTML: `<button class="btn btn-ghost" data-cancel>Cancel</button>
                 <button class="btn btn-primary" data-save>Add channel</button>`,
      onMount: (host, close) => {
        host.querySelector('#cTarget').focus();
        host.querySelector('[data-cancel]').onclick = close;
        host.querySelector('[data-save]').onclick = async () => {
          const payload = { kind: host.querySelector('#cKind').value,
                            target: host.querySelector('#cTarget').value.trim(),
                            min_grade: host.querySelector('#cGrade').value };
          if (!payload.target) { UI.toast('Enter a destination', 'error'); return; }
          try { await API.createChannel(payload); UI.toast('Channel added', 'success'); close(); go('settings'); }
          catch (err) { UI.toast(err.message, 'error'); }
        };
      },
    });
  }

  // ══════════════════════ SHARED BITS ══════════════════════
  function loading(msg) {
    return `<div class="card"><div class="card-body"><div class="scanning">
      <div class="pulse-ring"></div><div class="scanning-sub">${e(msg)}</div></div></div></div>`;
  }
  function errorState(msg) {
    return `<div class="empty"><h3>Something went wrong</h3><p>${e(msg)}</p>
      <button class="btn btn-ghost" onclick="location.reload()">Reload</button></div>`;
  }
  function emptyInline(msg) { return `<p class="finding-empty" style="padding:20px;">${e(msg)}</p>`; }
  function emptyState(iconName, title, body, actionLabel, action) {
    return `<div class="card"><div class="empty">
      <div class="empty-icon">${UI.icon(iconName)}</div>
      <h3>${e(title)}</h3><p>${e(body)}</p>
      ${actionLabel ? `<button class="btn btn-primary" data-action="${action}">${e(actionLabel)}</button>` : ''}
    </div></div>`;
  }
  function scoreCls(score) {
    if (score == null) return '';
    return score >= 75 ? 'good' : score >= 60 ? 'warn' : 'crit';
  }
  function riskRank(r) { return { high: 0, medium: 1, low: 2 }[r] ?? 3; }

  return { dashboard, projects, projectDetail, scanDetail, schedules, settings, openScanModal };
})();
