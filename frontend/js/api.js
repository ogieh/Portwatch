/* ─────────────────────────────────────────
   PortWatch Pro - api.js
   Thin fetch wrapper. Holds the access + refresh tokens, attaches the access
   token to every request, silently refreshes it once when it expires, and
   normalizes errors into thrown Error(message) for callers.
───────────────────────────────────────── */

const API = (() => {
  const TOKEN_KEY = 'portwatch_token';
  const REFRESH_KEY = 'portwatch_refresh';
  const USER_KEY = 'portwatch_user';
  // Same-origin: the Flask app serves this SPA, so relative /api works.
  const BASE = '';

  function getToken() { return localStorage.getItem(TOKEN_KEY); }
  function getRefresh() { return localStorage.getItem(REFRESH_KEY); }
  function setSession(session) {
    localStorage.setItem(TOKEN_KEY, session.token);
    if (session.refresh_token) localStorage.setItem(REFRESH_KEY, session.refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(session.user));
  }
  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  }
  function currentUser() {
    try { return JSON.parse(localStorage.getItem(USER_KEY)); }
    catch { return null; }
  }

  // One refresh in flight at a time; concurrent 401s share it.
  let refreshing = null;
  async function tryRefresh() {
    if (refreshing) return refreshing;
    const rt = getRefresh();
    if (!rt) return false;
    refreshing = (async () => {
      try {
        const res = await fetch(`${BASE}/api/auth/refresh`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: rt }),
        });
        if (!res.ok) return false;
        setSession(await res.json());
        return true;
      } catch { return false; }
      finally { refreshing = null; }
    })();
    return refreshing;
  }

  async function request(path, { method = 'GET', body, raw = false, _retried = false } = {}) {
    const headers = {};
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    const res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401 && token) {
      // Access token died mid-app: refresh once and retry, else bounce to login.
      if (!_retried && await tryRefresh()) {
        return request(path, { method, body, raw, _retried: true });
      }
      clearSession();
      window.dispatchEvent(new CustomEvent('auth:expired'));
      throw new Error('Session expired, please sign in again');
    }

    if (raw) return res;

    let data = null;
    try { data = await res.json(); } catch { /* empty body ok */ }

    if (!res.ok) {
      const msg = (data && data.error) || `Request failed (${res.status})`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // Reports need the bearer token, which a plain <a href> cannot send, so the
  // report is fetched with auth and shown from a blob URL in a new tab.
  async function openReport(id) {
    const win = window.open('', '_blank');
    try {
      const res = await request(`/api/scans/${id}/report`, { raw: true });
      if (!res.ok) {
        let msg = `Report unavailable (${res.status})`;
        try { msg = (await res.json()).error || msg; } catch { /* keep */ }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      if (win) win.location = url; else window.open(url, '_blank');
    } catch (err) {
      if (win) win.close();
      throw err;
    }
  }

  return {
    getToken, getRefresh, setSession, clearSession, currentUser,

    // ---- auth ----
    register: (payload) => request('/api/auth/register', { method: 'POST', body: payload }),
    login: (payload) => request('/api/auth/login', { method: 'POST', body: payload }),
    me: () => request('/api/auth/me'),
    logout: () => request('/api/auth/logout', { method: 'POST', body: { refresh_token: getRefresh() } }),
    logoutAll: () => request('/api/auth/logout-all', { method: 'POST', body: {} }),
    changePassword: (payload) => request('/api/auth/password', { method: 'POST', body: payload }),
    forgotPassword: (email) => request('/api/auth/forgot', { method: 'POST', body: { email } }),
    resetPassword: (token, password) => request('/api/auth/reset', { method: 'POST', body: { token, password } }),
    listApiKeys: () => request('/api/auth/api-keys'),
    createApiKey: (name) => request('/api/auth/api-keys', { method: 'POST', body: { name } }),
    revokeApiKey: (id) => request(`/api/auth/api-keys/${id}`, { method: 'DELETE' }),

    // ---- meta ----
    health: () => request('/api/health'),
    profiles: () => request('/api/profiles'),
    audit: (limit = 100) => request(`/api/audit?limit=${limit}`),

    // ---- projects ----
    listProjects: () => request('/api/projects'),
    getProject: (id) => request(`/api/projects/${id}`),
    createProject: (payload) => request('/api/projects', { method: 'POST', body: payload }),
    updateProject: (id, payload) => request(`/api/projects/${id}`, { method: 'PATCH', body: payload }),
    deleteProject: (id) => request(`/api/projects/${id}`, { method: 'DELETE' }),

    // ---- scans ----
    runScan: (payload) => request('/api/scan', { method: 'POST', body: payload }),
    listScans: (projectId) => request(`/api/scans${projectId ? `?project_id=${projectId}` : ''}`),
    getScan: (id) => request(`/api/scans/${id}`),
    cancelScan: (id) => request(`/api/scans/${id}/cancel`, { method: 'POST', body: {} }),
    deleteScan: (id) => request(`/api/scans/${id}`, { method: 'DELETE' }),
    diff: (a, b) => request(`/api/scans/${a}/diff/${b}`),
    openReport,

    // ---- dashboard ----
    dashboard: () => request('/api/dashboard'),

    // ---- schedules ----
    listSchedules: () => request('/api/schedules'),
    createSchedule: (payload) => request('/api/schedules', { method: 'POST', body: payload }),
    updateSchedule: (id, payload) => request(`/api/schedules/${id}`, { method: 'PATCH', body: payload }),
    deleteSchedule: (id) => request(`/api/schedules/${id}`, { method: 'DELETE' }),
    runSchedule: (id) => request(`/api/schedules/${id}/run`, { method: 'POST', body: {} }),

    // ---- notifications ----
    listChannels: () => request('/api/notifications'),
    createChannel: (payload) => request('/api/notifications', { method: 'POST', body: payload }),
    updateChannel: (id, payload) => request(`/api/notifications/${id}`, { method: 'PATCH', body: payload }),
    deleteChannel: (id) => request(`/api/notifications/${id}`, { method: 'DELETE' }),
    testChannel: (id) => request(`/api/notifications/${id}/test`, { method: 'POST', body: {} }),

    // ---- recon ----
    reconFull: (target) => request('/api/recon/full', { method: 'POST', body: { target } }),
    reconSubdomains: (target) => request('/api/recon/subdomains', { method: 'POST', body: { target } }),
    reconDns: (target) => request('/api/recon/dns', { method: 'POST', body: { target } }),
    reconWhois: (target) => request('/api/recon/whois', { method: 'POST', body: { target } }),
    reconTech: (target) => request('/api/recon/technologies', { method: 'POST', body: { target } }),
    reconEmail: (target) => request('/api/recon/email-security', { method: 'POST', body: { target } }),
    reconDirs: (target) => request('/api/recon/directories', { method: 'POST', body: { target } }),
    reconWaf: (target) => request('/api/recon/waf', { method: 'POST', body: { target } }),
    reconTraceroute: (target) => request('/api/recon/traceroute', { method: 'POST', body: { target } }),
    reconExploits: (scanId) => request('/api/recon/exploits', { method: 'POST', body: { scan_id: scanId } }),
    reconExploitVersion: (version) => request('/api/recon/exploits', { method: 'POST', body: { version } }),
  };
})();
