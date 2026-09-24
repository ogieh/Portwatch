/* ─────────────────────────────────────────
   PortWatch Pro - components.js
   Reusable render helpers: escaping, icons, badges, toast, modal, formatting.
───────────────────────────────────────── */

const UI = (() => {

  function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtDate(iso) {
    if (!iso) return '-';
    const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
    if (isNaN(d)) return iso;
    return d.toLocaleString(undefined, {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  }

  function fmtRelative(iso) {
    if (!iso) return '-';
    const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
    if (isNaN(d)) return iso;
    const diff = (Date.now() - d) / 1000;
    const future = diff < 0;
    const abs = Math.abs(diff);
    if (abs < 60) return future ? 'in under a minute' : 'just now';
    let span;
    if (abs < 3600) span = `${Math.floor(abs / 60)}m`;
    else if (abs < 86400) span = `${Math.floor(abs / 3600)}h`;
    else if (abs < 604800) span = `${Math.floor(abs / 86400)}d`;
    else return fmtDate(iso);
    return future ? `in ${span}` : `${span} ago`;
  }

  // ---- SVG icons (stroke = currentColor) ----
  const ICONS = {
    dashboard: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
    projects: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    scan: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>',
    schedule: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    settings: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14 2h-4l-.5 2.5a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5A7 7 0 0 0 5 12a7 7 0 0 0 .1 1.2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2 1.2L10 22h4l.5-2.5a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.06-.4.1-.8.1-1.2z"/></svg>',
    logo: '<svg width="22" height="22" viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="8" stroke="#38BDF8" stroke-width="1.5"/><circle cx="10" cy="10" r="4" stroke="#38BDF8" stroke-width="1.5"/><circle cx="10" cy="10" r="1.5" fill="#38BDF8"/><line x1="10" y1="2" x2="10" y2="0" stroke="#38BDF8" stroke-width="1.5" stroke-linecap="round"/><line x1="10" y1="20" x2="10" y2="18" stroke="#38BDF8" stroke-width="1.5" stroke-linecap="round"/><line x1="2" y1="10" x2="0" y2="10" stroke="#38BDF8" stroke-width="1.5" stroke-linecap="round"/><line x1="20" y1="10" x2="18" y2="10" stroke="#38BDF8" stroke-width="1.5" stroke-linecap="round"/></svg>',
    empty: '<svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 13h6"/></svg>',
  };

  function icon(name) { return ICONS[name] || ''; }

  function gradeBadge(grade, large = false) {
    if (!grade) return '<span class="pill pill-info">-</span>';
    const cls = large ? 'grade-badge grade-lg' : 'grade-badge';
    return `<span class="${cls} grade-${esc(grade)}">${esc(grade)}</span>`;
  }

  function riskPill(risk) {
    return `<span class="pill pill-${esc(risk)}">${esc(risk)}</span>`;
  }

  function statePill(state) {
    return `<span class="pill pill-${esc(state)}">${esc(state)}</span>`;
  }

  // ---- Toast ----
  function toast(msg, type = 'info') {
    const host = document.getElementById('toastHost');
    const el = document.createElement('div');
    const iconChar = type === 'error' ? '✕' : type === 'success' ? '✓' : 'ℹ';
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${iconChar}</span><span>${esc(msg)}</span>`;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity 250ms ease';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 260);
    }, 3600);
  }

  // ---- Modal ----
  function modal({ title, bodyHTML, footHTML = '', large = false, onMount }) {
    const host = document.getElementById('modalHost');
    host.innerHTML = `
      <div class="modal-backdrop" data-backdrop>
        <div class="modal ${large ? 'modal-lg' : ''}">
          <div class="modal-head">
            <h3>${esc(title)}</h3>
            <button class="modal-close" data-close>&times;</button>
          </div>
          <div class="modal-body">${bodyHTML}</div>
          ${footHTML ? `<div class="modal-foot">${footHTML}</div>` : ''}
        </div>
      </div>`;
    const backdrop = host.querySelector('[data-backdrop]');
    const close = () => { host.innerHTML = ''; };
    host.querySelector('[data-close]').onclick = close;
    backdrop.onclick = (e) => { if (e.target === backdrop) close(); };
    document.addEventListener('keydown', function esckey(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esckey); }
    });
    if (onMount) onMount(host, close);
    return close;
  }

  function confirm({ title = 'Are you sure?', message, confirmLabel = 'Confirm', danger = true }) {
    return new Promise((resolve) => {
      const foot = `
        <button class="btn btn-ghost" data-cancel>Cancel</button>
        <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-ok>${esc(confirmLabel)}</button>`;
      const close = modal({
        title,
        bodyHTML: `<p style="color:var(--muted);font-size:0.9rem;">${esc(message)}</p>`,
        footHTML: foot,
        onMount: (host) => {
          host.querySelector('[data-cancel]').onclick = () => { close(); resolve(false); };
          host.querySelector('[data-ok]').onclick = () => { close(); resolve(true); };
        },
      });
    });
  }

  // ---- tiny inline SVG bar/donut renderers (no chart lib) ----
  function donut(segments, size = 120) {
    // segments: [{label, value, color}]
    const total = segments.reduce((s, x) => s + x.value, 0) || 1;
    const r = size / 2 - 10, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
    let offset = 0;
    const rings = segments.filter(s => s.value > 0).map(s => {
      const frac = s.value / total;
      const dash = `${(frac * C).toFixed(2)} ${(C - frac * C).toFixed(2)}`;
      const el = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${s.color}" stroke-width="14" stroke-dasharray="${dash}" stroke-dashoffset="${(-offset * C).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
      offset += frac;
      return el;
    }).join('');
    return `<svg class="donut" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--surface3)" stroke-width="14"/>
      ${rings}
      <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="var(--text)" font-size="22" font-weight="700" font-family="var(--mono)">${total}</text>
      <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="var(--muted)" font-size="9">projects</text>
    </svg>`;
  }

  return { esc, fmtDate, fmtRelative, icon, gradeBadge, riskPill, statePill,
           toast, modal, confirm, donut };
})();
