/* ─────────────────────────────────────────
   PortWatch Pro - app.js
   Boots the app: renders the auth screen when logged out, the shell + routed
   view when logged in. Hash-based router keeps deep links working on refresh.
───────────────────────────────────────── */

const ROUTES = {
  dashboard: { render: (m) => Views.dashboard(m), nav: 'dashboard' },
  projects: { render: (m) => Views.projects(m), nav: 'projects' },
  findings: { render: (m) => Views.findings(m), nav: 'findings' },
  authorizations: { render: (m) => Views.authorizations(m), nav: 'authorizations' },
  schedules: { render: (m) => Views.schedules(m), nav: 'schedules' },
  settings: { render: (m) => Views.settings(m), nav: 'settings' },
};

// Navigate helper exposed globally so views can call go('path').
function go(path) {
  if (('#' + path) === location.hash) { route(); }  // re-render same route
  else location.hash = path;
}

function currentPath() {
  return (location.hash || '#dashboard').slice(1);
}

async function route() {
  const path = currentPath();
  const [head, param] = path.split('/');

  if (!API.getToken()) {
    if (head === 'reset' && param) { renderReset(param); return; }
    renderAuth();
    return;
  }

  renderShell(head);
  const mount = document.getElementById('viewMount');

  try {
    if (head === 'project' && param) return Views.projectDetail(mount, param);
    if (head === 'scan' && param) return Views.scanDetail(mount, param);
    const r = ROUTES[head] || ROUTES.dashboard;
    return r.render(mount);
  } catch (err) {
    mount.innerHTML = `<div class="empty"><h3>Failed to load</h3><p>${UI.esc(err.message)}</p></div>`;
  }
}

// ══════════════════════ APP SHELL ══════════════════════
function renderShell(activeHead) {
  const root = document.getElementById('root');
  const user = API.currentUser() || { name: '?', role: '' };
  const initials = user.name.split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();

  // Map detail routes onto their parent nav item.
  const navActive = { project: 'projects', scan: 'projects' }[activeHead] || activeHead;

  const navItems = [
    { key: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
    { key: 'projects', label: 'Projects', icon: 'projects' },
    { key: 'findings', label: 'Findings', icon: 'findings' },
    { key: 'authorizations', label: 'Authorizations', icon: 'shield' },
    { key: 'schedules', label: 'Schedules', icon: 'schedule' },
    { key: 'settings', label: 'Settings', icon: 'settings' },
  ];

  // Only rebuild the shell if it isn't already present (keeps view swaps cheap).
  if (!document.getElementById('appShell')) {
    root.innerHTML = `
      <div class="app" id="appShell">
        <a class="skip-link" href="#main">Skip to main content</a>
        <aside class="sidebar">
          <div class="brand">
            <span class="brand-icon">${UI.icon('logo')}</span>
            <span class="brand-name">PortWatch<span class="pro">PRO</span></span>
          </div>
          <button class="cmdk-trigger" id="cmdkBtn" type="button" aria-label="Open command palette (Ctrl+K)">${UI.icon('scan')}<span>Jump to...</span><kbd>Ctrl K</kbd></button>
          <div class="nav-label" aria-hidden="true">Workspace</div>
          <nav class="nav" id="nav" aria-label="Primary">
            ${navItems.map(n => `<button class="nav-item" data-nav="${n.key}" title="${n.label}" aria-label="${n.label}">${UI.icon(n.icon)}<span>${n.label}</span></button>`).join('')}
          </nav>
          <div class="sidebar-foot">
            <div class="user-chip">
              <div class="user-avatar">${UI.esc(initials)}</div>
              <div class="user-info">
                <div class="user-name">${UI.esc(user.name)}</div>
                <div class="user-role">${UI.esc(user.role)}</div>
              </div>
            </div>
            <button class="logout-btn" id="logoutBtn">Sign out</button>
            <div class="engine-badge" id="engineBadge"><span class="engine-dot"></span> checking engine...</div>
          </div>
        </aside>
        <main class="main" id="main" tabindex="-1"><div id="viewMount"></div></main>
      </div>`;

    document.querySelectorAll('[data-nav]').forEach(btn =>
      btn.onclick = () => go(btn.dataset.nav));
    document.getElementById('logoutBtn').onclick = logout;
    document.getElementById('cmdkBtn').onclick = openPalette;
    Motion.tips(document.getElementById('main'));

    // KPI count-up whenever a view renders new numbers into the mount.
    const mountEl = document.getElementById('viewMount');
    new MutationObserver(() => Motion.countUp(mountEl)).observe(mountEl, { childList: true });

    // Engine badge (nmap vs simulated)
    API.health().then(h => {
      const badge = document.getElementById('engineBadge');
      if (!badge) return;
      const live = h.engine === 'nmap';
      badge.innerHTML = `<span class="engine-dot ${live ? 'live' : ''}"></span> ${live ? 'nmap engine' : 'simulated engine'} · v${h.version}`;
    }).catch(() => {});
  }

  document.querySelectorAll('[data-nav]').forEach(btn => {
    const on = btn.dataset.nav === navActive;
    btn.classList.toggle('active', on);
    if (on) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
}

// ══════════════════════ AUTH SCREEN ══════════════════════
// Full-bleed layout: a quiet port-field canvas behind everything (a scanner lens
// appears under the mouse), a bottom-anchored headline, and a glass panel. The stage is mounted once and survives
// panel swaps (sign in / register / forgot / reset) so its sweep never restarts.
let authMode = 'login';   // login | register

const AUTH_COPY = {
  login:    { title: 'Welcome back', tag: 'Sign in to review exposures, findings and scheduled scans.', cta: 'Sign in' },
  register: { title: 'Create your account', tag: 'Start monitoring the hosts you are authorised to test.', cta: 'Create account' },
};

const ARROW = '<span class="arrow" aria-hidden="true"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg></span>';
const SHIELD = '<svg aria-hidden="true" focusable="false" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l7 3v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z"/></svg>';

function authStage() {
  return `
      <canvas class="port-field" aria-hidden="true"></canvas>
      <div class="auth-vignette" aria-hidden="true"></div>
      <header class="stage-top">
        <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
        <div class="micro stage-status" aria-hidden="true"><span class="live-dot"></span>Demo sweep <b data-sweep>0001</b>/1024<span class="stage-clock"> &nbsp;·&nbsp; <b data-clock>--:--:--</b> UTC</span></div>
      </header>
      <section class="auth-stage" aria-labelledby="stageTitle">
        <div class="micro stage-eyebrow">Attack-surface monitoring</div>
        <h1 class="stage-title" id="stageTitle" aria-label="Every open port. Seen first.">
          <span class="line" aria-hidden="true" data-scramble data-delay="350">Every open port.</span>
          <span class="line line--muted" aria-hidden="true" data-scramble data-delay="850">Seen first.</span>
        </h1>
        <p class="stage-sub">PortWatch maps the services you expose, matches their versions against known CVEs and grades the risk on a schedule, so drift never goes unnoticed.</p>
      </section>`;
}

function startClock(el) {
  if (!el) return;
  const tick = () => {
    if (!el.isConnected) { clearInterval(id); return; }
    el.textContent = new Date().toISOString().slice(11, 19);
  };
  const id = setInterval(tick, 1000);
  tick();
}

// Mount (or reuse) the full-bleed layout and put `panelHTML` in the glass panel.
function mountAuth(panelHTML) {
  const root = document.getElementById('root');
  let panel = root.querySelector('.auth-panel');
  if (!panel) {
    root.innerHTML = `<div class="auth-screen">${authStage()}<section class="auth-panel" aria-label="Account access"></section></div>`;
    panel = root.querySelector('.auth-panel');
    const sweepEl = root.querySelector('[data-sweep]');
    Motion.portField(root.querySelector('.port-field'), {
      onSweep: (n) => { sweepEl.textContent = String(n).padStart(4, '0'); },
    });
    root.querySelectorAll('[data-scramble]').forEach(el =>
      Motion.scrambleIn(el, { delay: +(el.dataset.delay || 0) }));
    startClock(root.querySelector('[data-clock]'));
  }
  panel.innerHTML = `<div class="auth-card glass">${panelHTML}</div>`;
  return panel;
}

const authLegal = `<p class="auth-legal">${SHIELD}<span>Only scan systems you own or have explicit written permission to test. Unauthorised scanning is illegal.</span></p>`;

function renderAuth() {
  const c = AUTH_COPY[authMode];
  const panel = mountAuth(`
    <div class="auth-panel-head">
      <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
      <h2 class="auth-panel-title" data-a-title>${c.title}</h2>
      <p class="auth-tag" data-a-tag>${c.tag}</p>
    </div>
    <div class="auth-toggle" role="group" aria-label="Account mode" data-active="${authMode}">
      <button type="button" data-mode="login">Sign in</button>
      <button type="button" data-mode="register">Create account</button>
    </div>
    <div id="authError" aria-live="polite"></div>
    <form id="authForm" novalidate>
      <div class="field" data-a-name>
        <label for="aName">Full name</label><input class="input" id="aName" autocomplete="name"/>
      </div>
      <div class="field"><label for="aEmail">Email</label>
        <input class="input" id="aEmail" type="email" autocomplete="email" placeholder="you@company.com"/></div>
      <div class="field"><label for="aPassword">Password</label>
        <input class="input" id="aPassword" type="password"/></div>
      <button class="btn btn-primary auth-submit" type="submit"><span data-a-cta>${c.cta}</span>${ARROW}</button>
    </form>
    <p class="auth-foot" data-a-forgot><button type="button" class="auth-link" data-forgot>Forgot your password?</button></p>
    ${authLegal}`);

  // Switch modes in place so the toggle pill slides instead of re-rendering.
  const applyMode = () => {
    const m = AUTH_COPY[authMode];
    panel.querySelector('.auth-toggle').dataset.active = authMode;
    panel.querySelectorAll('[data-mode]').forEach(b => {
      const on = b.dataset.mode === authMode;
      b.classList.toggle('active', on);
      b.setAttribute('aria-pressed', String(on));
    });
    panel.querySelector('[data-a-title]').textContent = m.title;
    panel.querySelector('[data-a-tag]').textContent = m.tag;
    panel.querySelector('[data-a-cta]').textContent = m.cta;
    panel.querySelector('[data-a-name]').classList.toggle('hidden', authMode === 'login');
    panel.querySelector('[data-a-forgot]').classList.toggle('hidden', authMode !== 'login');
    const pw = panel.querySelector('#aPassword');
    pw.autocomplete = authMode === 'login' ? 'current-password' : 'new-password';
    pw.placeholder = authMode === 'register' ? 'At least 8 characters' : '';
    panel.querySelector('#authError').innerHTML = '';
  };
  applyMode();

  panel.querySelectorAll('[data-mode]').forEach(btn =>
    btn.onclick = () => { authMode = btn.dataset.mode; applyMode(); });
  panel.querySelector('[data-forgot]').onclick = renderForgot;

  panel.querySelector('#authForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const email = panel.querySelector('#aEmail').value.trim();
    const password = panel.querySelector('#aPassword').value;
    const name = panel.querySelector('#aName').value.trim();
    const errBox = panel.querySelector('#authError');
    const submit = panel.querySelector('.auth-submit');
    errBox.innerHTML = '';
    submit.disabled = true;

    try {
      const res = authMode === 'login'
        ? await API.login({ email, password })
        : await API.register({ email, name, password });
      API.setSession(res);
      // Fresh shell after auth.
      document.getElementById('root').innerHTML = '';
      location.hash = 'dashboard';
      route();
      UI.toast(`Welcome, ${res.user.name}`, 'success');
    } catch (err) {
      errBox.innerHTML = `<div class="auth-error">${UI.esc(err.message)}</div>`;
      submit.disabled = false;
    }
  };
}

function renderForgot() {
  const panel = mountAuth(`
    <div class="auth-panel-head">
      <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
      <h2 class="auth-panel-title">Reset your password</h2>
      <p class="auth-tag">Enter your account email and we will send you a reset link.</p>
    </div>
    <div id="authError" aria-live="polite"></div>
    <form id="forgotForm">
      <div class="field"><label for="fEmail">Email</label>
        <input class="input" id="fEmail" type="email" autocomplete="email" placeholder="you@company.com"/></div>
      <button class="btn btn-primary auth-submit" type="submit"><span>Send reset link</span>${ARROW}</button>
    </form>
    <p class="auth-foot"><button type="button" class="auth-link" data-back>Back to sign in</button></p>
    ${authLegal}`);
  panel.querySelector('[data-back]').onclick = () => { authMode = 'login'; renderAuth(); };
  panel.querySelector('#forgotForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const email = panel.querySelector('#fEmail').value.trim();
    const errBox = panel.querySelector('#authError');
    try {
      const res = await API.forgotPassword(email);
      let extra = '';
      if (res.dev_reset_token) {
        // Development without SMTP: the server hands the token back so the flow is usable.
        extra = ` No mail server is configured, so here is your link: <a href="#reset/${UI.esc(res.dev_reset_token)}">open reset form</a>.`;
      }
      errBox.innerHTML = `<div class="auth-error auth-error--ok">${UI.esc(res.message)}${extra}</div>`;
    } catch (err) {
      errBox.innerHTML = `<div class="auth-error">${UI.esc(err.message)}</div>`;
    }
  };
}

function renderReset(token) {
  const panel = mountAuth(`
    <div class="auth-panel-head">
      <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
      <h2 class="auth-panel-title">Choose a new password</h2>
      <p class="auth-tag">Use at least 8 characters. You will be signed in afterwards.</p>
    </div>
    <div id="authError" aria-live="polite"></div>
    <form id="resetForm">
      <div class="field"><label for="rPass">New password</label>
        <input class="input" id="rPass" type="password" autocomplete="new-password" placeholder="At least 8 characters"/></div>
      <div class="field"><label for="rPass2">Confirm password</label>
        <input class="input" id="rPass2" type="password" autocomplete="new-password"/></div>
      <button class="btn btn-primary auth-submit" type="submit"><span>Set password</span>${ARROW}</button>
    </form>
    <p class="auth-foot"><button type="button" class="auth-link" data-back>Back to sign in</button></p>`);
  panel.querySelector('[data-back]').onclick = () => { location.hash = ''; authMode = 'login'; renderAuth(); };
  panel.querySelector('#resetForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const p1 = panel.querySelector('#rPass').value, p2 = panel.querySelector('#rPass2').value;
    const errBox = panel.querySelector('#authError');
    if (p1 !== p2) { errBox.innerHTML = '<div class="auth-error">Passwords do not match</div>'; return; }
    try {
      const res = await API.resetPassword(token, p1);
      API.setSession(res);
      document.getElementById('root').innerHTML = '';
      location.hash = 'dashboard';
      route();
      UI.toast('Password updated. You are signed in.', 'success');
    } catch (err) {
      errBox.innerHTML = `<div class="auth-error">${UI.esc(err.message)}</div>`;
    }
  };
}

async function logout() {
  try { await API.logout(); } catch { /* best effort: revoke the refresh token */ }
  API.clearSession();
  document.getElementById('root').innerHTML = '';
  location.hash = '';
  renderAuth();
}

// ══════════════════════ COMMAND PALETTE (Ctrl/Cmd + K) ══════════════════════
function paletteItems() {
  const nav = [
    ['dashboard', 'Dashboard', 'dashboard', 'Security posture overview'],
    ['projects', 'Projects', 'projects', 'Targets grouped by client or environment'],
    ['findings', 'Findings', 'findings', 'Tracked vulnerabilities and their status'],
    ['authorizations', 'Authorizations', 'shield', 'Written permission records'],
    ['schedules', 'Schedules', 'schedule', 'Recurring scans'],
    ['settings', 'Settings', 'settings', 'Account, API keys and notifications'],
  ].map(([key, label, icon, hint]) => ({ group: 'Go to', label, icon, hint, run: () => go(key) }));
  const actions = [
    { group: 'Actions', label: 'New scan', icon: 'scan', hint: 'Run a scan against an authorised target', run: () => Views.openScanModal() },
    { group: 'Actions', label: 'New project', icon: 'projects', hint: 'Create a project and set its scope', run: () => { go('projects'); setTimeout(() => Views.openProjectModal && Views.openProjectModal(), 350); } },
    { group: 'Actions', label: 'Sign out', icon: 'shield', hint: 'End this session', run: logout },
  ];
  return [...actions, ...nav];
}

function openPalette() {
  if (document.querySelector('.cmdk-backdrop') || !document.getElementById('appShell')) return;
  const prevFocus = document.activeElement;
  const host = document.createElement('div');
  host.className = 'cmdk-backdrop';
  host.innerHTML = `
    <div class="cmdk glass" role="dialog" aria-modal="true" aria-label="Command palette">
      <div class="cmdk-input-row">${UI.icon('scan')}
        <input class="cmdk-input" type="text" placeholder="Jump to a page or run an action..." aria-label="Search commands"
               role="combobox" aria-expanded="true" aria-controls="cmdkList" aria-autocomplete="list" autocomplete="off" spellcheck="false"/>
        <kbd>Esc</kbd>
      </div>
      <ul class="cmdk-list" id="cmdkList" role="listbox"></ul>
      <div class="cmdk-foot micro"><span><kbd>&uarr;</kbd><kbd>&darr;</kbd> navigate</span><span><kbd>Enter</kbd> select</span></div>
    </div>`;
  document.body.appendChild(host);
  const input = host.querySelector('.cmdk-input'), list = host.querySelector('.cmdk-list');
  const all = paletteItems();
  let shown = all, active = 0;

  const render = () => {
    let lastGroup = '';
    list.innerHTML = shown.length ? shown.map((it, n) => {
      const head = it.group !== lastGroup ? `<li class="cmdk-group micro" role="presentation">${it.group}</li>` : '';
      lastGroup = it.group;
      return `${head}<li class="cmdk-item ${n === active ? 'active' : ''}" role="option" id="cmdk-${n}" data-n="${n}" aria-selected="${n === active}">
        <span class="cmdk-ico">${UI.icon(it.icon)}</span><span class="cmdk-label">${UI.esc(it.label)}</span><span class="cmdk-hint">${UI.esc(it.hint)}</span></li>`;
    }).join('') : '<li class="cmdk-empty">No matches</li>';
    input.setAttribute('aria-activedescendant', shown.length ? `cmdk-${active}` : '');
    const el = list.querySelector('.cmdk-item.active'); if (el) el.scrollIntoView({ block: 'nearest' });
  };
  const close = () => { host.classList.add('out'); setTimeout(() => host.remove(), 160); document.removeEventListener('keydown', onKey, true); if (prevFocus && prevFocus.focus) prevFocus.focus(); };
  const choose = (n) => { const it = shown[n]; if (!it) return; close(); setTimeout(it.run, 20); };
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % Math.max(1, shown.length); render(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + shown.length) % Math.max(1, shown.length); render(); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(active); }
    else if (e.key === 'Tab') { e.preventDefault(); input.focus(); }
  };
  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    shown = !q ? all : all.filter(it => (it.label + ' ' + it.hint + ' ' + it.group).toLowerCase().includes(q));
    active = 0; render();
  });
  list.addEventListener('pointermove', (e) => { const li = e.target.closest('.cmdk-item'); if (li && +li.dataset.n !== active) { active = +li.dataset.n; render(); } });
  list.addEventListener('click', (e) => { const li = e.target.closest('.cmdk-item'); if (li) choose(+li.dataset.n); });
  host.addEventListener('pointerdown', (e) => { if (e.target === host) close(); });
  document.addEventListener('keydown', onKey, true);
  render(); input.focus();
}

// ══════════════════════ BOOT ══════════════════════
window.addEventListener('hashchange', route);
window.addEventListener('auth:expired', () => {
  document.getElementById('root').innerHTML = '';
  renderAuth();
  UI.toast('Session expired, please sign in again', 'info');
});
window.addEventListener('DOMContentLoaded', route);

window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && API.getToken()) { e.preventDefault(); openPalette(); }
});

