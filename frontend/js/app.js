/* ─────────────────────────────────────────
   PortWatch Pro - app.js
   Boots the app: renders the auth screen when logged out, the shell + routed
   view when logged in. Hash-based router keeps deep links working on refresh.
───────────────────────────────────────── */

const ROUTES = {
  dashboard: { render: (m) => Views.dashboard(m), nav: 'dashboard' },
  projects: { render: (m) => Views.projects(m), nav: 'projects' },
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
    { key: 'schedules', label: 'Schedules', icon: 'schedule' },
    { key: 'settings', label: 'Settings', icon: 'settings' },
  ];

  // Only rebuild the shell if it isn't already present (keeps view swaps cheap).
  if (!document.getElementById('appShell')) {
    root.innerHTML = `
      <div class="app" id="appShell">
        <aside class="sidebar">
          <div class="brand">
            <span class="brand-icon">${UI.icon('logo')}</span>
            <span class="brand-name">PortWatch<span class="pro">PRO</span></span>
          </div>
          <nav class="nav" id="nav">
            ${navItems.map(n => `<button class="nav-item" data-nav="${n.key}">${UI.icon(n.icon)}<span>${n.label}</span></button>`).join('')}
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
        <main class="main"><div id="viewMount"></div></main>
      </div>`;

    document.querySelectorAll('[data-nav]').forEach(btn =>
      btn.onclick = () => go(btn.dataset.nav));
    document.getElementById('logoutBtn').onclick = logout;

    // Engine badge (nmap vs simulated)
    API.health().then(h => {
      const badge = document.getElementById('engineBadge');
      if (!badge) return;
      const live = h.engine === 'nmap';
      badge.innerHTML = `<span class="engine-dot ${live ? 'live' : ''}"></span> ${live ? 'nmap engine' : 'simulated engine'} · v${h.version}`;
    }).catch(() => {});
  }

  document.querySelectorAll('[data-nav]').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.nav === navActive));
}

// ══════════════════════ AUTH SCREEN ══════════════════════
let authMode = 'login';   // login | register | forgot

function renderAuth() {
  const root = document.getElementById('root');
  root.innerHTML = `
    <div class="auth-screen">
      <div class="auth-card">
        <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
        <p class="auth-tag">Attack-surface monitoring platform</p>
        <div class="auth-toggle">
          <button data-mode="login" class="${authMode === 'login' ? 'active' : ''}">Sign in</button>
          <button data-mode="register" class="${authMode === 'register' ? 'active' : ''}">Create account</button>
        </div>
        <div id="authError"></div>
        <form id="authForm">
          <div class="field ${authMode === 'login' ? 'hidden' : ''}">
            <label>Full name</label><input class="input" id="aName" autocomplete="name"/>
          </div>
          <div class="field"><label>Email</label>
            <input class="input" id="aEmail" type="email" autocomplete="email" placeholder="you@company.com"/></div>
          <div class="field"><label>Password</label>
            <input class="input" id="aPassword" type="password" autocomplete="${authMode === 'login' ? 'current-password' : 'new-password'}" placeholder="${authMode === 'register' ? 'At least 8 characters' : ''}"/></div>
          <button class="btn btn-primary" type="submit" style="width:100%;justify-content:center;margin-top:6px;">
            ${authMode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>
        ${authMode === 'login' ? '<p class="auth-foot" style="margin-top:10px;"><a data-forgot style="cursor:pointer;color:var(--accent);">Forgot your password?</a></p>' : ''}
        <p class="auth-foot">Only scan systems you own or have explicit written permission to test.<br/>Unauthorised scanning is illegal.</p>
      </div>
    </div>`;

  document.querySelectorAll('[data-mode]').forEach(btn =>
    btn.onclick = () => { authMode = btn.dataset.mode; renderAuth(); });
  const forgot = document.querySelector('[data-forgot]');
  if (forgot) forgot.onclick = renderForgot;

  document.getElementById('authForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const email = document.getElementById('aEmail').value.trim();
    const password = document.getElementById('aPassword').value;
    const name = (document.getElementById('aName') || {}).value?.trim();
    const errBox = document.getElementById('authError');
    errBox.innerHTML = '';

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
    }
  };
}

function authCard(inner) {
  return `
    <div class="auth-screen">
      <div class="auth-card">
        <div class="auth-brand">${UI.icon('logo')}<span class="brand-name">PortWatch<span class="pro">PRO</span></span></div>
        ${inner}
      </div>
    </div>`;
}

function renderForgot() {
  const root = document.getElementById('root');
  root.innerHTML = authCard(`
    <p class="auth-tag">Reset your password</p>
    <div id="authError"></div>
    <form id="forgotForm">
      <div class="field"><label>Email</label>
        <input class="input" id="fEmail" type="email" autocomplete="email" placeholder="you@company.com"/></div>
      <button class="btn btn-primary" type="submit" style="width:100%;justify-content:center;margin-top:6px;">Send reset link</button>
    </form>
    <p class="auth-foot" style="margin-top:10px;"><a data-back style="cursor:pointer;color:var(--accent);">Back to sign in</a></p>`);
  root.querySelector('[data-back]').onclick = () => { authMode = 'login'; renderAuth(); };
  root.querySelector('#forgotForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const email = root.querySelector('#fEmail').value.trim();
    const errBox = root.querySelector('#authError');
    try {
      const res = await API.forgotPassword(email);
      let extra = '';
      if (res.dev_reset_token) {
        // Development without SMTP: the server hands the token back so the flow is usable.
        extra = ` No mail server is configured, so here is your link: <a href="#reset/${UI.esc(res.dev_reset_token)}" style="color:var(--accent);">open reset form</a>.`;
      }
      errBox.innerHTML = `<div class="auth-error" style="color:var(--low);">${UI.esc(res.message)}${extra}</div>`;
    } catch (err) {
      errBox.innerHTML = `<div class="auth-error">${UI.esc(err.message)}</div>`;
    }
  };
}

function renderReset(token) {
  const root = document.getElementById('root');
  root.innerHTML = authCard(`
    <p class="auth-tag">Choose a new password</p>
    <div id="authError"></div>
    <form id="resetForm">
      <div class="field"><label>New password</label>
        <input class="input" id="rPass" type="password" autocomplete="new-password" placeholder="At least 8 characters"/></div>
      <div class="field"><label>Confirm password</label>
        <input class="input" id="rPass2" type="password" autocomplete="new-password"/></div>
      <button class="btn btn-primary" type="submit" style="width:100%;justify-content:center;margin-top:6px;">Set password</button>
    </form>
    <p class="auth-foot" style="margin-top:10px;"><a data-back style="cursor:pointer;color:var(--accent);">Back to sign in</a></p>`);
  root.querySelector('[data-back]').onclick = () => { location.hash = ''; authMode = 'login'; renderAuth(); };
  root.querySelector('#resetForm').onsubmit = async (ev) => {
    ev.preventDefault();
    const p1 = root.querySelector('#rPass').value, p2 = root.querySelector('#rPass2').value;
    const errBox = root.querySelector('#authError');
    if (p1 !== p2) { errBox.innerHTML = '<div class="auth-error">Passwords do not match</div>'; return; }
    try {
      const res = await API.resetPassword(token, p1);
      API.setSession(res);
      root.innerHTML = '';
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

// ══════════════════════ BOOT ══════════════════════
window.addEventListener('hashchange', route);
window.addEventListener('auth:expired', () => {
  document.getElementById('root').innerHTML = '';
  renderAuth();
  UI.toast('Session expired, please sign in again', 'info');
});
window.addEventListener('DOMContentLoaded', route);
