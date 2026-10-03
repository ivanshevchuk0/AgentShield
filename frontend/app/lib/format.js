// Formatting helpers. Everything that reaches the DOM from the server goes through str()/num()
// so a malformed field renders as text instead of crashing a component.

export const SEVERITY = { allow: 0, monitor: 1, redact: 2, require_approval: 3, block: 4 };

export const SEV = {
  block: { label: 'BLOCKED', short: 'BLOCK', glyph: '■' },
  require_approval: { label: 'NEEDS APPROVAL', short: 'APPROVAL', glyph: '◆' },
  redact: { label: 'REDACTED', short: 'REDACT', glyph: '◐' },
  monitor: { label: 'MONITORED', short: 'MONITOR', glyph: '○' },
  allow: { label: 'ALLOWED', short: 'ALLOW', glyph: '✓' },
};

export function sevKey(action) {
  return Object.prototype.hasOwnProperty.call(SEV, action) ? action : 'none';
}

export function sevOf(action) {
  return SEV[sevKey(action)] || { label: str(action || '-').toUpperCase(), short: str(action || '-'), glyph: '·' };
}

export function strongest(actions) {
  let best = 'allow';
  for (const a of actions) if ((SEVERITY[a] ?? -1) > (SEVERITY[best] ?? -1)) best = a;
  return best;
}

export function str(v, max = 2000) {
  if (v === null || v === undefined) return '';
  let s;
  if (typeof v === 'string') s = v;
  else if (typeof v === 'number' || typeof v === 'boolean') s = String(v);
  else {
    try {
      s = JSON.stringify(v);
    } catch {
      s = String(v);
    }
  }
  return s.length > max ? s.slice(0, max) + '…' : s;
}

export function num(v, fallback = 0) {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function isNum(v) {
  return typeof v === 'number' && Number.isFinite(v);
}

export function shortHash(h, n = 12) {
  return str(h).slice(0, n) || '-';
}

export function fmtMs(v) {
  if (!isNum(v)) return '-';
  if (v < 10) return v.toFixed(2);
  if (v < 100) return v.toFixed(1);
  return String(Math.round(v));
}

export function fmtUsd(v) {
  const n = num(v, NaN);
  if (!Number.isFinite(n)) return '-';
  if (n > 0 && n < 0.01) return '$' + n.toFixed(5);
  return '$' + n.toFixed(2);
}

export function fmtInt(v) {
  const n = num(v, NaN);
  return Number.isFinite(n) ? Math.round(n).toLocaleString('en-US') : '-';
}

/** Epoch seconds from seconds, milliseconds or an ISO string; null when unknown. */
export function toSec(t) {
  if (isNum(t)) return t > 1e12 ? t / 1000 : t;
  if (typeof t === 'string' && t) {
    const p = Date.parse(t);
    if (Number.isFinite(p)) return p / 1000;
    const n = Number(t);
    if (Number.isFinite(n)) return n > 1e12 ? n / 1000 : n;
  }
  return null;
}

export function fmtClock(t) {
  const s = toSec(t);
  if (s === null) return '-';
  const d = new Date(s * 1000);
  const pad = (x, n = 2) => String(x).padStart(n, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtAgo(ms) {
  if (!isNum(ms) || ms < 0) return '-';
  if (ms < 10000) return (ms / 1000).toFixed(1) + ' s';
  if (ms < 120000) return Math.round(ms / 1000) + ' s';
  if (ms < 7200000) return Math.round(ms / 60000) + ' min';
  return Math.round(ms / 3600000) + ' h';
}

export function fmtCountdown(sec) {
  if (!isNum(sec)) return '-';
  const s = Math.max(0, Math.ceil(sec));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** OWASP tags carried by a record (primary first, then findings), de-duplicated. */
export function owaspTags(rec) {
  const out = [];
  const add = (t) => {
    const s = str(t);
    if (s && !out.includes(s)) out.push(s);
  };
  if (rec && rec.primary) add(rec.primary.owasp);
  if (rec && Array.isArray(rec.findings)) rec.findings.forEach((f) => f && add(f.owasp));
  return out;
}

export const OWASP_TITLES = {
  LLM01: 'Prompt Injection',
  LLM02: 'Sensitive Information Disclosure',
  LLM03: 'Supply Chain',
  LLM04: 'Data and Model Poisoning',
  LLM05: 'Improper Output Handling',
  LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leakage',
  LLM08: 'Vector and Embedding Weaknesses',
  LLM09: 'Misinformation',
  LLM10: 'Unbounded Consumption',
};

export const ADMIN_KINDS = new Set(['policy', 'approval', 'kill']);

/** Views produced by the normaliser; a finding with one of these as `via` matched only after decoding. */
export function isDecodedVia(via) {
  const v = str(via);
  return v !== '' && !['original', 'judge', 'policy', 'dashboard', 'flow', 'tools'].includes(v);
}

/** Total model calls from snapshot.upstream_calls (a number, {total}, or a per-model map). */
export function upstreamTotal(v) {
  if (isNum(v)) return v;
  if (v && typeof v === 'object') {
    if (isNum(v.total)) return v.total;
    let sum = 0;
    let seen = false;
    for (const x of Object.values(v)) {
      if (isNum(x)) {
        sum += x;
        seen = true;
      }
    }
    return seen ? sum : null;
  }
  return null;
}

export function httpLabel(status) {
  if (!status) return '';
  return String(status);
}
