/* ─────────────────────────────────────────
   PortWatch Pro - motion.js
   Signature visuals, vanilla canvas, reduced-motion aware, self-cleaning:
     portField(canvas, hooks)   sign-in field: 1 cell = 1 port. A scan line
                                sweeps it; a cursor "scanner lens" magnifies
                                and reads out the ports beneath it; risky
                                services pop callouts as they are found.
     radar(canvas, blips, opts) dashboard exposure radar plotting real
                                exposures; severity = ring + shape + colour.
     scrambleIn(el, opts)       terminal-style decode for headline lines.
     countUp(root)              KPI numbers count up from zero.
     tips(root)                 shared hover tooltip for [data-tip] marks.
───────────────────────────────────────── */

const Motion = (() => {
  const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const canHover = () => matchMedia('(hover: hover) and (pointer: fine)').matches;
  const easeOutExpo = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
  const MONO = '"JetBrains Mono", ui-monospace, monospace';

  function mulberry32(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function hash(str) {
    let h = 2166136261;
    for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return (h >>> 0) / 4294967296;
  }

  // Status colours (reserved meaning). Every use is paired with a text label or shape.
  const RGB = { open: [56, 189, 248], medium: [245, 158, 11], high: [239, 68, 68], critical: [248, 113, 113], low: [34, 197, 94], info: [96, 165, 250] };
  const rgba = (k, a) => `rgba(${RGB[k][0]},${RGB[k][1]},${RGB[k][2]},${a})`;

  // Common services and how the sign-in field rates them (illustrative, it is a demo sweep).
  const SERVICES = [
    [22, 'ssh', 'open'], [80, 'http', 'open'], [443, 'https', 'open'], [53, 'dns', 'open'], [8080, 'http-alt', 'open'],
    [8443, 'https-alt', 'open'], [143, 'imap', 'open'], [110, 'pop3', 'open'], [993, 'imaps', 'open'], [587, 'submission', 'open'],
    [21, 'ftp', 'medium'], [25, 'smtp', 'medium'], [3306, 'mysql', 'medium'], [5432, 'postgresql', 'medium'], [1433, 'mssql', 'medium'],
    [23, 'telnet', 'high'], [445, 'smb', 'high'], [3389, 'rdp', 'high'], [6379, 'redis', 'high'], [27017, 'mongodb', 'high'],
    [9200, 'elasticsearch', 'high'], [11211, 'memcached', 'high'], [5900, 'vnc', 'high'],
  ];

  function setupCanvas(canvas, ctx, cap = 2) {
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    const dpr = Math.min(window.devicePixelRatio || 1, cap);
    canvas.width = Math.round(rect.width * dpr); canvas.height = Math.round(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { w: rect.width, h: rect.height };
  }

  // Runs `tick(now, dt)` every frame while the canvas is attached and the tab is visible.
  function loop(canvas, tick, onStop) {
    let raf = 0, last = 0, stopped = false;
    const frame = (now) => {
      if (!canvas.isConnected) { stop(); return; }
      const dt = last ? Math.min(0.1, (now - last) / 1000) : 0; last = now;
      tick(now, dt);
      raf = requestAnimationFrame(frame);
    };
    const onVis = () => { if (document.hidden) { cancelAnimationFrame(raf); raf = 0; } else play(); };
    function play() { if (!raf && !stopped && !reduced()) { last = 0; raf = requestAnimationFrame(frame); } }
    function stop() { stopped = true; cancelAnimationFrame(raf); raf = 0; document.removeEventListener('visibilitychange', onVis); onStop && onStop(); }
    document.addEventListener('visibilitychange', onVis);
    return { play, stop };
  }

  // ════════════ PORT FIELD + SCANNER LENS ════════════
  function portField(canvas, { onSweep, onDiscover } = {}) {
    const ctx = canvas.getContext('2d');
    const PERIOD = 8000, DECAY = 0.14, BAND = 160;
    let w = 0, h = 0, cell = 22, cols = 0, rows = 0, R = 112;
    let svc = new Int16Array(0);       // -1 closed, else index into SERVICES
    let lit = new Float32Array(0);
    let openByCol = [];                // per column: row indices of open cells
    let base = null;                   // offscreen layer with every idle closed dot (drawn once)
    let dpr = 1;
    let lastX = -BAND, lastSweepTick = 0;
    const start = performance.now();
    const lens = { x: 0, y: 0, tx: 0, ty: 0, a: 0, lastMove: -1e9 };
    const callouts = [];               // {i, t0}

    function layout() {
      const s = setupCanvas(canvas, ctx, 1.5); if (!s) return false;
      ({ w, h } = s);
      cell = w < 640 ? 17 : 22; R = w < 640 ? 78 : 112;
      cols = Math.ceil(w / cell) + 1; rows = Math.ceil(h / cell) + 1;
      const rand = mulberry32(6379);
      svc = new Int16Array(cols * rows); lit = new Float32Array(cols * rows);
      openByCol = Array.from({ length: cols }, () => []);
      for (let i = 0; i < svc.length; i++) {
        const r = rand(), pick = rand();
        svc[i] = r < 0.05 ? Math.floor(pick * SERVICES.length) : -1;
        if (svc[i] >= 0) openByCol[Math.floor(i / rows)].push(i % rows);
        if (reduced() && svc[i] >= 0) lit[i] = 0.7;
      }
      dpr = canvas.width / w;
      base = document.createElement('canvas');
      base.width = canvas.width; base.height = canvas.height;
      const b = base.getContext('2d');
      b.setTransform(dpr, 0, 0, dpr, 0, 0);
      b.fillStyle = 'rgba(226,232,240,0.07)';
      for (let i = 0; i < svc.length; i++) {
        if (svc[i] >= 0) continue;
        b.fillRect(Math.floor(i / rows) * cell - 1, (i % rows) * cell - 1, 2, 2);
      }
      if (!lens.x) { lens.x = lens.tx = w * 0.6; lens.y = lens.ty = h * 0.42; }
      return true;
    }

    const onMove = (e) => {
      if (e.pointerType && e.pointerType !== 'mouse') return;
      const r = canvas.getBoundingClientRect();
      lens.tx = e.clientX - r.left; lens.ty = e.clientY - r.top; lens.lastMove = performance.now();
    };
    window.addEventListener('pointermove', onMove, { passive: true });

    function label(text, x, y, k) {
      ctx.font = `500 10px ${MONO}`;
      const tw = ctx.measureText(text).width;
      ctx.fillStyle = 'rgba(6,8,12,0.82)';
      ctx.fillRect(x - 6, y - 11, tw + 22, 17);
      ctx.fillStyle = rgba(k, 1);
      ctx.fillRect(x - 1, y - 5, 5, 5);                    // status swatch beside the text label
      ctx.fillStyle = 'rgba(226,232,240,0.92)';
      ctx.fillText(text, x + 9, y + 1);
    }

    function draw(now, dt, scanX) {
      ctx.clearRect(0, 0, w, h);
      const decay = DECAY * dt;
      // Lens follows the cursor (lerp .12); idles into a slow drift when untouched or on touch.
      const idle = reduced() || !canHover() || now - lens.lastMove > 2500;
      if (lens.a < 0.01 && !idle) { lens.x = lens.tx; lens.y = lens.ty; }   // appear where the cursor is
      lens.x += (lens.tx - lens.x) * 0.18; lens.y += (lens.ty - lens.y) * 0.18;
      lens.a += ((idle ? 0 : 1) - lens.a) * Math.min(1, dt * 5);
      if (lens.a < 0.01) lens.a = 0;
      const R2 = R * R;
      let nearest = -1, nearestD = Infinity;
      const inLens = [];

      ctx.drawImage(base, 0, 0, w, h);
      const ly0 = Math.max(0, Math.floor((lens.y - R) / cell)), ly1 = Math.min(rows - 1, Math.ceil((lens.y + R) / cell));
      for (let c = 0; c < cols; c++) {
        const x = c * cell;
        const behind = scanX - x;
        const prox = behind >= 0 && behind < BAND ? 1 - behind / BAND : 0;
        const crossed = x <= scanX && x > lastX;
        const dx = x - lens.x;
        const inLensCol = lens.a > 0 && Math.abs(dx) < R;
        // Closed cells only need redrawing where the scan band or lens changes them; the base layer has the rest.
        const rowsToVisit = prox > 0 ? null : inLensCol ? [ly0, ly1] : 'open';
        const visit = rowsToVisit === 'open' ? openByCol[c] : null;
        const r0 = rowsToVisit && rowsToVisit !== 'open' ? rowsToVisit[0] : 0;
        const r1 = rowsToVisit && rowsToVisit !== 'open' ? rowsToVisit[1] : rows - 1;
        const n = visit ? visit.length : r1 - r0 + 1;
        for (let q = 0; q < n; q++) {
          const r = visit ? visit[q] : r0 + q;
          const i = c * rows + r, s = svc[i], y = r * cell;
          const dy = y - lens.y, d2 = dx * dx + dy * dy;
          const L = d2 < R2 ? (1 - Math.sqrt(d2) / R) * lens.a : 0;   // lens falloff 0..1
          if (s >= 0) {
            const k = SERVICES[s][2];
            if (crossed) {
              lit[i] = 1;
              if (onDiscover && (k !== 'open' || (i % 3 === 0))) onDiscover({ port: SERVICES[s][0], service: SERVICES[s][1], risk: k });
            }
            if (lit[i] > 0 && !reduced()) lit[i] = Math.max(0, lit[i] - decay);
            const Lt = Math.max(lit[i], L * 0.9);
            const size = 2.4 + Lt * 2.2 + L * 2.5;
            ctx.fillStyle = rgba(k, Math.min(1, 0.12 + Lt * 0.6 + prox * 0.12).toFixed(3));
            ctx.fillRect(x - size / 2, y - size / 2, size, size);
            if (L > 0) {
              inLens.push(i);
              if (d2 < nearestD) { nearestD = d2; nearest = i; }
            }
          } else if (prox > 0 || L > 0) {
            const size = 2 + L * 1.6;
            ctx.fillStyle = `rgba(226,232,240,${(prox * 0.26 + L * 0.3).toFixed(3)})`;   // adds on top of the base dot
            ctx.fillRect(x - size / 2, y - size / 2, size, size);
          }
        }
      }

      // Lens columns visited only the lens rows above; draw their remaining open cells.
      for (let c = 0; c < cols; c++) {
        const x = c * cell, dx = x - lens.x;
        const behind = scanX - x;
        if (!(lens.a > 0 && Math.abs(dx) < R) || (behind >= 0 && behind < BAND)) continue;
        const crossed = x <= scanX && x > lastX;
        for (const r of openByCol[c]) {
          if (r >= ly0 && r <= ly1) continue;
          const i = c * rows + r, k = SERVICES[svc[i]][2], y = r * cell;
          if (crossed) lit[i] = 1;
          if (lit[i] > 0 && !reduced()) lit[i] = Math.max(0, lit[i] - decay);
          const size = 2.4 + lit[i] * 2.2;
          ctx.fillStyle = rgba(k, Math.min(1, 0.16 + lit[i] * 0.84).toFixed(3));
          ctx.fillRect(x - size / 2, y - size / 2, size, size);
        }
      }

      // Scan line + trailing glow
      if (scanX > -BAND) {
        const g = ctx.createLinearGradient(scanX - BAND, 0, scanX, 0);
        g.addColorStop(0, 'rgba(56,189,248,0)'); g.addColorStop(1, 'rgba(56,189,248,0.04)');
        ctx.fillStyle = g; ctx.fillRect(scanX - BAND, 0, BAND, h);
        const lg = ctx.createLinearGradient(0, 0, 0, h);
        lg.addColorStop(0, 'rgba(56,189,248,0)'); lg.addColorStop(0.4, 'rgba(56,189,248,0.45)'); lg.addColorStop(1, 'rgba(56,189,248,0.05)');
        ctx.fillStyle = lg; ctx.fillRect(scanX, 0, 1, h);
      }
      lastX = scanX;

      // Lens: labels for every open port inside it, then the crosshair ring + readout.
      if (lens.a > 0) {
        ctx.font = `500 10px ${MONO}`;
        const boxes = [];
        inLens.sort((a, b) => { const ra = SERVICES[svc[a]][2] === 'open' ? 1 : 0, rb = SERVICES[svc[b]][2] === 'open' ? 1 : 0; return ra - rb; });
        for (const i of inLens) {
          const s = SERVICES[svc[i]], x = Math.floor(i / rows) * cell + 8, y = (i % rows) * cell + 3;
          const text = `${s[0]}/${s[1]}`, bw = ctx.measureText(text).width + 22;
          const box = [x - 6, y - 11, x - 6 + bw, y + 6];
          if (boxes.some(o => box[0] < o[2] && box[2] > o[0] && box[1] < o[3] && box[3] > o[1])) continue;   // skip colliding labels
          boxes.push(box);
          ctx.globalAlpha = lens.a;
          label(text, x, y, s[2]);
          ctx.globalAlpha = 1;
        }
        ctx.save();
        ctx.globalAlpha = lens.a;
        ctx.strokeStyle = 'rgba(56,189,248,0.55)'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(lens.x, lens.y, R, 0, Math.PI * 2); ctx.stroke();
        ctx.strokeStyle = 'rgba(56,189,248,0.18)';
        ctx.beginPath(); ctx.arc(lens.x, lens.y, R * 0.5, 0, Math.PI * 2); ctx.stroke();
        ctx.strokeStyle = 'rgba(56,189,248,0.8)'; ctx.lineWidth = 1.5;
        for (let q = 0; q < 4; q++) {
          const a = q * Math.PI / 2, cx = Math.cos(a), cy = Math.sin(a);
          ctx.beginPath(); ctx.moveTo(lens.x + cx * (R - 6), lens.y + cy * (R - 6)); ctx.lineTo(lens.x + cx * (R + 10), lens.y + cy * (R + 10)); ctx.stroke();
        }
        ctx.fillStyle = 'rgba(56,189,248,0.9)'; ctx.fillRect(lens.x - 1.5, lens.y - 1.5, 3, 3);
        const col = Math.round(lens.x / cell), row = Math.round(lens.y / cell);
        const cellNo = String(Math.max(1, (row * cols + col) % 65535)).padStart(5, '0');
        const read = nearest >= 0
          ? `${SERVICES[svc[nearest]][0]} · ${SERVICES[svc[nearest]][1]} · ${SERVICES[svc[nearest]][2] === 'open' ? 'open' : SERVICES[svc[nearest]][2]}`.toUpperCase()
          : `PROBING · CELL ${cellNo}`;
        ctx.font = `500 10px ${MONO}`;
        const tw = ctx.measureText(read).width;
        const rx = Math.max(8, Math.min(w - tw - 28, lens.x - tw / 2 - 10));
        const ry = w >= 860 && lens.y - R - 40 > 8 ? lens.y - R - 40 : lens.y + R + 16;
        ctx.fillStyle = 'rgba(6,8,12,0.85)'; ctx.fillRect(rx, ry, tw + 20, 20);
        ctx.strokeStyle = 'rgba(56,189,248,0.35)'; ctx.lineWidth = 1; ctx.strokeRect(rx + 0.5, ry + 0.5, tw + 19, 19);
        ctx.fillStyle = 'rgba(226,232,240,0.95)'; ctx.fillText(read, rx + 10, ry + 14);
        ctx.restore();
      }

      // Discovery callouts for risky services (leader line + label), 2.6s each.
      for (let n = callouts.length - 1; n >= 0; n--) {
        const co = callouts[n], age = (now - co.t0) / 2600;
        if (age >= 1) { callouts.splice(n, 1); continue; }
        const s = SERVICES[svc[co.i]]; if (!s) continue;
        const x = Math.floor(co.i / rows) * cell, y = (co.i % rows) * cell;
        const a = age < 0.1 ? age / 0.1 : age > 0.75 ? (1 - age) / 0.25 : 1;
        ctx.globalAlpha = a;
        ctx.strokeStyle = rgba(s[2], 0.7); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(x + 3, y - 3); ctx.lineTo(x + 18, y - 18); ctx.lineTo(x + 30, y - 18); ctx.stroke();
        ctx.strokeStyle = rgba(s[2], 0.9);
        ctx.strokeRect(x - 6.5, y - 6.5, 13, 13);
        label(`${s[0]} ${s[1].toUpperCase()} · ${s[2].toUpperCase()}`, x + 36, y - 15, s[2]);
        ctx.globalAlpha = 1;
      }
    }

    const ticker = loop(canvas, (now, dt) => {
      const t = ((now - start) % PERIOD) / PERIOD;
      const scanX = t * (w + BAND * 1.5) - BAND / 2;
      if (scanX < lastX) lastX = -BAND;
      draw(now, dt, scanX);
      if (onSweep && now - lastSweepTick > 90) {
        lastSweepTick = now;
        onSweep(Math.max(1, Math.min(1024, Math.round(Math.max(0, scanX) / w * 1024))));
      }
    }, () => { ro.disconnect(); window.removeEventListener('pointermove', onMove); });

    const ro = new ResizeObserver(() => { if (layout() && reduced()) draw(performance.now(), 0, -BAND - 1); });
    ro.observe(canvas);
    if (layout()) {
      if (reduced()) { draw(performance.now(), 0, -BAND - 1); onSweep && onSweep(1024); }
      else ticker.play();
    }
    return { stop: ticker.stop };
  }

  // ════════════ EXPOSURE RADAR ════════════
  // blips: [{severity, title, target, port, cve, scan_id}]
  const RINGS = { critical: 0.3, high: 0.55, medium: 0.76, low: 0.94 };
  const RING_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };
  const SHAPE = { critical: 'diamond', high: 'circle', medium: 'triangle', low: 'square' };

  function shapePath(ctx, shape, x, y, s) {
    ctx.beginPath();
    if (shape === 'diamond') { ctx.moveTo(x, y - s); ctx.lineTo(x + s, y); ctx.lineTo(x, y + s); ctx.lineTo(x - s, y); ctx.closePath(); }
    else if (shape === 'triangle') { ctx.moveTo(x, y - s); ctx.lineTo(x + s * 0.95, y + s * 0.75); ctx.lineTo(x - s * 0.95, y + s * 0.75); ctx.closePath(); }
    else if (shape === 'square') { ctx.rect(x - s * 0.8, y - s * 0.8, s * 1.6, s * 1.6); }
    else ctx.arc(x, y, s * 0.85, 0, Math.PI * 2);
  }

  function radar(canvas, blipsIn, { onSelect, tip } = {}) {
    const ctx = canvas.getContext('2d');
    let w = 0, h = 0, cx = 0, cy = 0, rad = 0, hover = -1;
    const seen = {};
    const blips = blipsIn.map((b, n) => {
      const key = `${b.target}:${b.port}`; seen[key] = (seen[key] || 0) + 1;
      const sev = RINGS[b.severity] ? b.severity : 'low';
      const ang = (hash(key) * Math.PI * 2 + (seen[key] - 1) * 0.22) % (Math.PI * 2);
      const prev = sev === 'critical' ? 0.1 : RINGS[{ high: 'critical', medium: 'high', low: 'medium' }[sev]];
      const rr = prev + (RINGS[sev] - prev) * (0.35 + hash(key + 'r') * 0.5);
      return { ...b, sev, ang, rr, glow: 0.8, x: 0, y: 0 };
    });
    let labelled = new Set(blips.filter(b => b.sev === 'critical').slice(0, 4));
    // De-duplicate labels that share a target:port.
    const lkeys = new Set();
    labelled = new Set([...labelled].filter(b => { const k = b.target + b.port; if (lkeys.has(k)) return false; lkeys.add(k); return true; }));

    function layout() {
      const s = setupCanvas(canvas, ctx); if (!s) return false;
      ({ w, h } = s); cx = w / 2; cy = h / 2; rad = Math.min(w, h) / 2 - 18;
      blips.forEach(b => { b.x = cx + Math.cos(b.ang) * b.rr * rad; b.y = cy + Math.sin(b.ang) * b.rr * rad; });
      return true;
    }

    function draw(now, dt, sweepA) {
      ctx.clearRect(0, 0, w, h);
      // rings + labels (recessive)
      Object.entries(RINGS).forEach(([k, r]) => {
        ctx.strokeStyle = 'rgba(226,232,240,0.09)'; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(cx, cy, r * rad, 0, Math.PI * 2); ctx.stroke();
        ctx.font = `500 9px ${MONO}`; ctx.fillStyle = 'rgba(226,232,240,0.38)';
        ctx.fillText(RING_LABEL[k], cx - r * rad + 5, cy - 5);
      });
      ctx.strokeStyle = 'rgba(226,232,240,0.06)';
      ctx.beginPath(); ctx.moveTo(cx - rad, cy); ctx.lineTo(cx + rad, cy); ctx.moveTo(cx, cy - rad); ctx.lineTo(cx, cy + rad); ctx.stroke();

      // sweep wedge
      if (sweepA !== null) {
        const steps = 28;
        for (let s = 0; s < steps; s++) {
          const a0 = sweepA - (s + 1) * 0.035, a1 = sweepA - s * 0.035;
          ctx.fillStyle = `rgba(56,189,248,${(0.16 * (1 - s / steps)).toFixed(3)})`;
          ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, rad, a0, a1); ctx.closePath(); ctx.fill();
        }
        ctx.strokeStyle = 'rgba(56,189,248,0.75)'; ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(sweepA) * rad, cy + Math.sin(sweepA) * rad); ctx.stroke();
      }

      // blips
      blips.forEach((b, n) => {
        if (sweepA !== null) {
          const diff = ((sweepA - b.ang) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);
          if (diff < 0.08) b.glow = 1;
          b.glow = Math.max(0.35, b.glow - dt * 0.35);
        }
        const k = b.sev, s = (n === hover ? 7 : 5.5) + b.glow * 1.5;
        if (n === hover) { ctx.fillStyle = rgba(k, 0.12); ctx.beginPath(); ctx.arc(b.x, b.y, s * 2.4, 0, Math.PI * 2); ctx.fill(); }
        shapePath(ctx, SHAPE[k], b.x, b.y, s);
        ctx.fillStyle = rgba(k, Math.min(1, 0.45 + b.glow * 0.55));
        ctx.fill();
        ctx.lineWidth = 2; ctx.strokeStyle = '#0D1118'; ctx.stroke();      // 2px surface ring
        if (labelled.has(b) || n === hover) {
          const text = `${b.target}:${b.port}`.slice(0, 26);
          ctx.font = `500 10px ${MONO}`;
          const tw = ctx.measureText(text).width;
          const lx = b.x + tw + 16 > w ? b.x - tw - 12 : b.x + 10;
          ctx.fillStyle = 'rgba(6,8,12,0.8)'; ctx.fillRect(lx - 4, b.y - 8, tw + 8, 15);
          ctx.fillStyle = 'rgba(226,232,240,0.9)'; ctx.fillText(text, lx, b.y + 3);
        }
      });
      ctx.fillStyle = 'rgba(56,189,248,0.9)'; ctx.beginPath(); ctx.arc(cx, cy, 2.5, 0, Math.PI * 2); ctx.fill();
    }


    function pick(e) {
      const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
      let best = -1, bd = 14 * 14;
      blips.forEach((b, n) => { const d = (b.x - x) ** 2 + (b.y - y) ** 2; if (d < bd) { bd = d; best = n; } });
      return best;
    }
    canvas.addEventListener('pointermove', (e) => {
      hover = pick(e);
      canvas.style.cursor = hover >= 0 ? 'pointer' : '';
      if (tip) {
        if (hover < 0) tip.hide();
        else { const b = blips[hover]; tip.show(e.clientX, e.clientY, `<b>${esc(b.title)}</b><span>${esc(b.target)} · port ${esc(b.port)}</span><span class="tip-sev tip-sev--${b.sev}">${b.sev}</span>${b.cve && b.cve.length ? `<span class="mono">${esc(b.cve.join(', '))}</span>` : ''}`); }
      }
      draw(performance.now(), 0, null);
    });
    canvas.addEventListener('pointerleave', () => { hover = -1; tip && tip.hide(); draw(performance.now(), 0, null); });
    canvas.addEventListener('click', (e) => { const n = pick(e); if (n >= 0 && onSelect) { tip && tip.hide(); onSelect(blips[n]); } });

    const ro = new ResizeObserver(() => { if (!canvas.isConnected) { ro.disconnect(); return; } if (layout()) draw(performance.now(), 0, null); });
    ro.observe(canvas);
    if (layout()) draw(performance.now(), 0, null);
    return { stop: () => ro.disconnect() };
  }

  // ════════════ SHARED TOOLTIP ════════════
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let tipEl = null;
  const tip = {
    show(x, y, html) {
      if (!tipEl) { tipEl = document.createElement('div'); tipEl.className = 'viz-tip'; tipEl.setAttribute('role', 'tooltip'); document.body.appendChild(tipEl); }
      tipEl.innerHTML = html; tipEl.classList.add('on');
      const r = tipEl.getBoundingClientRect();
      const left = Math.min(window.innerWidth - r.width - 12, x + 14);
      const top = y - r.height - 14 < 8 ? y + 18 : y - r.height - 14;
      tipEl.style.transform = `translate(${Math.max(8, left)}px, ${top}px)`;
    },
    hide() { if (tipEl) tipEl.classList.remove('on'); },
  };
  // Marks carry data-tip="html-escaped text with | separating lines"; first line bold.
  function tips(root) {
    root.addEventListener('pointermove', (e) => {
      const m = e.target.closest('[data-tip]');
      if (!m || !root.contains(m)) { tip.hide(); return; }
      const [first, ...rest] = m.dataset.tip.split('|');
      tip.show(e.clientX, e.clientY, `<b>${esc(first)}</b>${rest.map(r => `<span>${esc(r)}</span>`).join('')}`);
    });
    root.addEventListener('pointerleave', () => tip.hide());
  }

  // ════════════ SCRAMBLE / DECODE ════════════
  const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&*<>/=+';
  function scrambleIn(el, { delay = 0, speed = 0.5, lookahead = 3, tick = 28 } = {}) {
    const text = el.dataset.text || el.textContent;
    el.dataset.text = text;
    if (reduced()) { el.textContent = text; return; }
    el.textContent = ' ';
    setTimeout(() => {
      let pos = 0;
      const id = setInterval(() => {
        if (!el.isConnected) { clearInterval(id); return; }
        pos += speed;
        const shown = Math.floor(pos);
        let out = '';
        for (let i = 0; i < text.length; i++) {
          if (i >= shown + lookahead) break;
          out += text[i] === ' ' ? ' ' : i < shown ? text[i] : GLYPHS[(Math.random() * GLYPHS.length) | 0];
        }
        el.textContent = out || ' ';
        if (shown >= text.length) { clearInterval(id); el.textContent = text; }
      }, tick);
    }, delay);
    setTimeout(() => { if (el.isConnected) el.textContent = text; }, delay + text.length * tick * 2 + 400);
  }

  // ════════════ COUNT-UP ════════════
  function countUp(root) {
    if (reduced()) return;
    root.querySelectorAll('.kpi-value:not([data-counted]), [data-count]:not([data-counted])').forEach((el) => {
      el.dataset.counted = '1';
      const raw = el.textContent.trim();
      if (!/^\d{1,7}$/.test(raw)) return;
      const target = parseInt(raw, 10);
      if (target === 0) return;
      const dur = 700 + Math.min(300, target * 5);
      const t0 = performance.now();
      el.textContent = '0';
      const step = (now) => {
        if (!el.isConnected) return;
        const p = Math.min(1, (now - t0) / dur);
        el.textContent = String(Math.round(easeOutExpo(p) * target));
        if (p < 1) requestAnimationFrame(step); else el.textContent = raw;
      };
      requestAnimationFrame(step);
    });
  }

  return { portField, radar, scrambleIn, countUp, tips, tip, reduced, canHover };
})();
