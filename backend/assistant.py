"""
Patchy - the PortWatch cyber-assistant.

Two brains, chosen automatically:

  online   any OpenAI-compatible chat completions API. Configure via env:
             PORTWATCH_AI_API_KEY   (or OPENAI_API_KEY as fallback)
             PORTWATCH_AI_BASE_URL  default https://api.openai.com/v1
                                    point at http://127.0.0.1:11434/v1 for Ollama
             PORTWATCH_AI_MODEL     default gpt-4o-mini
           the current scan is digested into the system prompt so Patchy
           talks about YOUR results, not security in general.

  offline  a small rules-based brain that reads the stored scan directly.
           no network, no keys, honestly labelled in every reply.

We deliberately do NOT train a model here: the value is in grounding a
general model on scan context, which the system prompt does. If a
fine-tuned model exists someday, it plugs in through the same provider
call by changing PORTWATCH_AI_MODEL alone.
"""

import json
import os
import time
import urllib.error
import urllib.request

from findings import build_findings

# ── identity (change name/personality here, frontend mirrors it) ── #
ASSISTANT_NAME = "Patchy"
ASSISTANT_TAGLINE = "your scan buddy"
ASSISTANT_SPECIES = "small cyber-owl with a bandage on its head"

MAX_HISTORY = 8          # messages of conversation sent back to the model
MAX_MSG_CHARS = 800      # per-message clamp
RATE_LIMIT = 10          # chats per minute per client
RATE_WINDOW = 60

_RATE_BUCKET = {}

GLOSSARY = {
    "csp": "Content-Security-Policy - a response header that whitelists where scripts/styles may load from. Strongest practical defence against XSS.",
    "hsts": "Strict-Transport-Security - tells browsers to never talk to your domain over plain HTTP again.",
    "x-frame-options": "Header stopping other sites from framing your pages (clickjacking defence).",
    "tls": "The encryption layer under HTTPS. Modern config means TLS 1.2+ with AEAD cipher suites only.",
    "cipher": "The exact math recipe used to encrypt a TLS connection. 'Weak' ones (RC4, 3DES, EXPORT-era) can be broken or downgraded.",
    "rate limiting": "Throttling repeated requests - especially failed logins - so brute force becomes slow and loud instead of fast and silent.",
    "owasp": "The OWASP Top 10 is the industry's standard list of most critical web app security risks; we map findings onto its 2021 edition.",
    "rdp": "Remote Desktop Protocol, port 3389. Extremely convenient for admins and attackers alike - keep it behind a VPN.",
    "sqli": "SQL injection - user input reaching database queries unescaped. Our NSE probes cover a couple of classic patterns only; it is not a full SQLi audit.",
}


def _env_key():
    return os.environ.get("PORTWATCH_AI_API_KEY") or os.environ.get("OPENAI_API_KEY")


def online_available():
    return bool(_env_key())


def status_payload():
    return {
        "name": ASSISTANT_NAME,
        "tagline": ASSISTANT_TAGLINE,
        "mode": "online" if online_available() else "offline",
        "model": os.environ.get("PORTWATCH_AI_MODEL", "gpt-4o-mini"),
    }


def _rate_ok(client):
    now = time.time()
    hits = [t for t in _RATE_BUCKET.get(client, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_LIMIT:
        _RATE_BUCKET[client] = hits
        return False
    hits.append(now)
    _RATE_BUCKET[client] = hits
    return True


# ── scan digestion ─────────────────────────────────────────── #

def scan_digest(record):
    """Compact, prompt-friendly view of a stored scan. We trim script
    bodies hard - raw nmap dumps would eat the context window."""
    if not record:
        return None
    risk = record.get("risk") or {}
    ports_lines = []
    for p in (record.get("ports") or []):
        if p.get("state") != "open":
            continue
        line = f"- {p['port']}/tcp {p.get('service','')} {p.get('version','')} [{p.get('risk')} risk]"
        scripts = p.get("scripts") or {}
        for name, out in list(scripts.items())[:6]:
            snippet = (out[:160] + "...") if isinstance(out, str) and len(out) > 160 else (out or "")
            line += f"\n    {name}: {snippet}"
        ports_lines.append(line)

    cc = record.get("credential_checks")
    cc_line = None
    if isinstance(cc, dict):
        verdicts = [f.get("verdict") for f in cc.get("http_login_findings", [])]
        dbs = [(d.get("port"), d.get("vulnerable")) for d in cc.get("db_findings", [])]
        cc_line = f"login verdicts={verdicts} db_checks={dbs}"

    digest = {
        "target": record.get("target"),
        "resolved_host": record.get("resolved_host"),
        "profile": record.get("profile"),
        "scanned_at": record.get("timestamp"),
        "risk_score": risk.get("score"),
        "risk_grade": risk.get("grade"),
        "score_deductions": [f"{b['reason']} ({b['points']})" for b in risk.get("breakdown", [])],
        "open_ports": ports_lines or ["none found in scanned range"],
        "credential_checks": cc_line,
    }
    return json.dumps(digest, indent=1)[:4500]


def _findings_digest(record):
    try:
        fs = build_findings(record or {})
    except Exception:
        return []
    return [
        {"id": f["id"], "severity": f["severity"], "title": f["title"],
         "first_fix": f["remediation"][0] if f["remediation"] else ""}
        for f in fs
    ]


def system_prompt(record):
    persona = (
        f"You are {ASSISTANT_NAME}, {ASSISTANT_SPECIES}, the friendly "
        f"cyber-assistant inside PortWatch, a pentest surface scanner "
        f"({ASSISTANT_TAGLINE}). Personality: warm, a little playful, "
        f"concretely helpful - like a clever friend who happens to do security. "
        f"Use the occasional light emoji but never more than one per reply.\n"
        "Rules:\n"
        "- Ground answers in the SCAN CONTEXT when one is provided; quote its ports, scores and findings.\n"
        "- If asked something outside security or outside the scan, gently steer back.\n"
        "- Never provide instructions for attacking systems the user has not authorised; assume defensive/educational intent.\n"
        "- Be concise: short paragraphs or tight lists, max ~180 words unless asked to elaborate.\n"
        "- When unsure about scan specifics, say what you'd need rather than inventing."
    )
    if record:
        persona += "\n\nSCAN CONTEXT:\n" + scan_digest(record)
        persona += "\n\nFINDINGS SUMMARY:\n" + json.dumps(_findings_digest(record))[:1500]
    return persona


# ── online provider (OpenAI-compatible) ────────────────────── #

def _call_provider(system, history, message):
    base = os.environ.get("PORTWATCH_AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("PORTWATCH_AI_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}]
        + history[-MAX_HISTORY:]
        + [{"role": "user", "content": message}],
        "temperature": 0.4,
        "max_tokens": 600,
    }
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_env_key()}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        body = json.loads(resp.read().decode())
    return (body.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()


# ── offline brain ──────────────────────────────────────────── #

def _offline_reply(message, record):
    msg = message.lower()
    risk = (record or {}).get("risk") or {}
    tag = "\n\n(local brain - set PORTWATCH_AI_API_KEY to wake my smarter twin)"

    if not record:
        if any(w in msg for w in ("hello", "hey", "hoo")) or msg.strip() in ("hi", "yo"):
            return (f"Hoo there! I'm {ASSISTANT_NAME}, {ASSISTANT_TAGLINE}. Run a scan "
                    f"and I'll help you decode everything we find." + tag)
        return ("I need a scan first - pop a target into the bar above and give me "
                "something to peck at." + tag)

    findings = _findings_digest(record)

    if any(w in msg for w in ("hello", "hey", "hoo")) or msg.strip() in ("hi", "yo"):
        return (f"Hoo there! I'm {ASSISTANT_NAME}. I've read scan #{record.get('id')} "
                f"of {record.get('target')}: grade {risk.get('grade', '?')} "
                f"({risk.get('score', '?')}/100). Ask me about your grade, a specific "
                f"port, or what to fix first." + tag)

    if any(k in msg for k in ("grade", "score", "how bad", "overall")):
        ded = risk.get("breakdown") or []
        lines = "\n".join(f"  • {d['reason']}: {d['points']}" for d in ded[:6]) or "  • nothing deducted"
        return (f"Grade {risk.get('grade', '?')} = {risk.get('score', '?')}/100. "
                f"We start at 100 and subtract for each finding:\n{lines}\n"
                f"Bands: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below." + tag)

    if any(k in msg for k in ("fix", "first", "priority", "start", "remediat", "improve")):
        if not findings:
            return ("Nothing flagged in the tested scope - keep watching for changes "
                    "and diff scans after changes." + tag)
        lines = "\n".join(f"  {f['id']} ({f['severity']}): {f['title']} → {f['first_fix']}"
                          for f in findings[:4])
        return (f"In order, patch these first:\n{lines}\nFull step-by-steps live in "
                f"the client report." + tag)

    # port-specific question
    import re as _re
    m = _re.search(r"port?\s*(\d{1,5})", msg.replace(".", " "))
    if m:
        num = int(m.group(1))
        for p in record.get("ports") or []:
            if p.get("port") == num:
                state = p.get("state")
                scripts = ", ".join((p.get("scripts") or {}).keys()) or "no script output"
                extra = ""
                from findings import EXPOSURE_ADVICE, PLAINTEXT_PORTS
                if num in EXPOSURE_ADVICE:
                    extra = f" That's {EXPOSURE_ADVICE[num]} - it should normally not face the internet."
                if num in PLAINTEXT_PORTS:
                    extra += " It sends credentials in cleartext; retire it."
                return (f"Port {num}/{p.get('service','')}: {state}. Risk tier: {p.get('risk')}. "
                        f"Version string: {p.get('version') or 'unknown'}. Scripts seen: {scripts}.{extra}" + tag)
        return (f"Port {num} didn't appear in this scan - either closed, filtered, or "
                f"outside the profile's range. Try a Deep scan for wider coverage." + tag)

    for term, expl in GLOSSARY.items():
        if term.split()[0] in msg and len(term.split()[0]) > 2:
            return expl + tag

    if "owasp" in msg:
        cats = sorted({t["category"] for t in (record.get("compliance") or [])})
        got = (", ".join(cats) + ".") if cats else "none mapped for this scan yet."
        return (f"This scan maps onto OWASP Top 10 (2021) categories: {got} "
                f"Each finding card in the report shows its category." + tag)

    return ("I'm the offline brain, so I shine at: your grade, what to fix first, "
            "any specific port ('is 3389 open?'), OWASP mapping, or terms like "
            "CSP/HSTS/TLS. For free-form chat, wire me up with PORTWATCH_AI_API_KEY."
            + tag)


# ── entry point used by the Flask route ────────────────────── #

def chat(message, record=None, history=None, client="anon"):
    """
    Returns {"reply", "mode", "name"}.
    Never raises upward: provider failures degrade to the offline brain
    with a note, because a broken assistant is useless but a degraded
    one still helps.
    """
    message = (message or "").strip()[:MAX_MSG_CHARS]
    history = [
        {"role": "user" if h.get("role") == "user" else "assistant",
         "content": str(h.get("content", ""))[:MAX_MSG_CHARS]}
        for h in (history or [])[-MAX_HISTORY:]
        if h.get("content")
    ]

    if not _rate_ok(client):
        return {"reply": "Easy hoot! Too many questions too fast - give me a moment.",
                "mode": "ratelimited", "name": ASSISTANT_NAME}

    if online_available():
        try:
            reply = _call_provider(system_prompt(record), history, message)
            if reply:
                return {"reply": reply, "mode": "online", "name": ASSISTANT_NAME}
        except Exception as e:
            fallback_note = f"(online brain unreachable: {str(e)[:80]} - falling back local)\n\n"
            return {"reply": fallback_note + _offline_reply(message, record),
                    "mode": "offline", "name": ASSISTANT_NAME}

    return {"reply": _offline_reply(message, record),
            "mode": "offline", "name": ASSISTANT_NAME}
