// Evidence highlighting without markup strings: returns plain segments that components
// render as text nodes and <mark> elements.

import { str, SEVERITY } from './format.js';

const MASKED_PREFIXES = ['pii.', 'secrets.', 'canary'];

function spanOf(f) {
  return f && Number.isInteger(f.start) && Number.isInteger(f.end) && f.end > f.start ? [f.start, f.end] : null;
}

/**
 * Segments of the record's masked excerpt. `excerpt_offset` shifts finding offsets (which index
 * the original text) into the excerpt. Only the primary finding is guaranteed to come from the
 * excerpt's segment; other findings are highlighted only when the excerpt shows the masking the
 * backend applies to them in place, so a span from another message is never marked.
 * @returns {null | {segments: Array<{text: string, mark: null | {action: string, control: string}}>}}
 */
export function excerptSegments(rec) {
  if (!rec || typeof rec.excerpt !== 'string' || !rec.excerpt) return null;
  // Backend offsets index Python code points; JS strings index UTF-16 units. Work on code points.
  const ex = Array.from(rec.excerpt);
  const cut = (a, b) => ex.slice(a, b).join('');
  const off = Number.isInteger(rec.excerpt_offset) ? rec.excerpt_offset : 0;
  const cand = [];
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : null;
  const ps = spanOf(primary);
  if (ps) cand.push({ s: ps[0] - off, e: ps[1] - off, action: str(primary.action || rec.action), control: str(primary.control_id) });
  for (const f of Array.isArray(rec.findings) ? rec.findings : []) {
    const sp = spanOf(f);
    if (!sp) continue;
    const control = str(f.control_id);
    if (ps && sp[0] === ps[0] && sp[1] === ps[1] && control === str(primary.control_id)) continue;
    if (!MASKED_PREFIXES.some((p) => control.startsWith(p))) continue;
    const s = sp[0] - off;
    const e = sp[1] - off;
    if (s < 0 || e > ex.length) continue;
    if (!cut(s, e).includes('•')) continue;
    cand.push({ s, e, action: str(f.action), control });
  }
  const spans = cand
    .map((c) => ({ ...c, s: Math.max(0, c.s), e: Math.min(ex.length, c.e) }))
    .filter((c) => c.e > c.s)
    .sort((a, b) => a.s - b.s || (SEVERITY[b.action] ?? 0) - (SEVERITY[a.action] ?? 0));
  const merged = [];
  for (const c of spans) {
    const last = merged[merged.length - 1];
    if (last && c.s < last.e) {
      last.e = Math.max(last.e, c.e);
      if ((SEVERITY[c.action] ?? 0) > (SEVERITY[last.action] ?? 0)) {
        last.action = c.action;
        last.control = c.control;
      }
    } else merged.push({ ...c });
  }
  const segments = [];
  let pos = 0;
  for (const m of merged) {
    if (m.s > pos) segments.push({ text: cut(pos, m.s), mark: null });
    segments.push({ text: cut(m.s, m.e), mark: { action: m.action, control: m.control } });
    pos = m.e;
  }
  if (pos < ex.length) segments.push({ text: cut(pos), mark: null });
  return { segments, truncatedStart: off > 0 };
}

/** Findings that matched only in a decoded view (no span on the original text). */
export function decodedOnly(rec) {
  return (Array.isArray(rec && rec.findings) ? rec.findings : []).filter(
    (f) => f && !Number.isInteger(f.start) && str(f.via) && str(f.via) !== 'original');
}

/**
 * "What the model received" for text typed in this browser: redact-action spans replaced with
 * the same [LABEL] tokens the backend uses. Returns null when nothing would change.
 * Only valid for input-direction records: once the model output produced findings, the record's
 * offsets mix several text segments and cannot be applied to the prompt.
 */
export function localRedaction(text, rec) {
  if (typeof text !== 'string' || !text || !rec || !Array.isArray(rec.findings)) return null;
  if (str(rec.direction) !== 'input') return null;
  const chars = Array.from(text);   // code points, matching the backend's offsets
  const cut = (a, b) => chars.slice(a, b).join('');
  const spans = rec.findings
    .filter((f) => f && str(f.action) === 'redact' && str(f.control_id).startsWith('pii.'))
    .map((f) => ({ sp: spanOf(f), label: str(f.control_id).slice(4).toUpperCase() }))
    .filter((x) => x.sp && x.sp[1] <= chars.length)
    .sort((a, b) => a.sp[0] - b.sp[0]);
  if (!spans.length) return null;
  const parts = [];
  let pos = 0;
  for (const { sp, label } of spans) {
    if (sp[0] < pos) continue;
    if (sp[0] > pos) parts.push({ text: cut(pos, sp[0]), token: false });
    parts.push({ text: `[${label}]`, token: true });
    pos = sp[1];
  }
  if (pos < chars.length) parts.push({ text: cut(pos), token: false });
  return parts;
}
