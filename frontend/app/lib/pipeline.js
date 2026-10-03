// Pure function: decision record -> pipeline stages, in the order the engine runs them
// (backend/app/engine.py: chat(), tool_call(), try_text(), inspect()). No timings are invented:
// a stage only carries a number when the record measured one.

import { str, strongest, isNum, isDecodedVia } from './format.js';

const DETECTORS = ['pii', 'secrets', 'injection', 'signatures', 'canary'];

const STAGES = {
  auth: { label: 'Auth', match: (c) => c.startsWith('auth.') },
  kill: { label: 'Kill switch', match: (c) => c === 'tools.kill_switch' },
  limits: { label: 'Limits', match: (c) => c.startsWith('limits.') || c === 'model.not_allowed' },
  loop: { label: 'Loop guard', match: (c) => c.startsWith('loop.'), detector: 'loop' },
  pii: { label: 'PII', match: (c) => c.startsWith('pii.'), detector: 'pii' },
  secrets: { label: 'Secrets', match: (c) => c.startsWith('secrets.'), detector: 'secrets' },
  injection: { label: 'Injection', match: (c) => c.startsWith('injection.'), detector: 'prompt_injection' },
  signatures: { label: 'Signatures', match: (c) => c.startsWith('signatures.'), detector: 'signatures' },
  canary: { label: 'Canary', match: (c) => c === 'canary' || c.startsWith('canary.'), detector: 'canary' },
  judge: { label: 'LLM judge', match: (c) => c.startsWith('semantic.'), detector: 'semantic' },
  budget: { label: 'Budget', match: (c) => c.startsWith('budget.') },
  model: { label: 'Model', match: () => false },
  output: { label: 'Output scan', match: () => false },
  toolpolicy: {
    label: 'Tool policy',
    match: (c) => c.startsWith('tools.') && c !== 'tools.kill_switch' && c !== 'tools.approval',
  },
  flow: { label: 'Flow guard', match: (c) => c.startsWith('flow.'), independent: true },
  approval: { label: 'Approval', match: (c) => c === 'tools.approval' },
  exec: { label: 'Tool exec', match: () => false },
  seal: { label: 'Audit seal', match: () => false },
};

export const LAYOUTS = {
  chat: ['auth', 'kill', 'limits', 'loop', DETECTORS, 'judge', 'budget', 'model', 'output', 'seal'],
  tool: ['auth', 'loop', 'kill', 'toolpolicy', 'flow', 'approval', 'exec', DETECTORS, 'judge', 'seal'],
  try: [DETECTORS, 'judge', 'seal'],
};

const JUDGE_CALLED = new Set(['allow', 'block']);

function stageFor(kind, controlId) {
  const c = str(controlId);
  if (!c) return null;
  const order = LAYOUTS[kind].flat();
  for (const id of order) if (STAGES[id].match(c)) return id;
  // chat: governance of tool calls proposed by the model happens in the output stage
  if (kind === 'chat' && (c.startsWith('tools.') || c.startsWith('flow.'))) return 'output';
  return null;
}

/**
 * @returns {null | {kind: string, columns: Array<{group: boolean, nodes: Array<object>}>, order: string[],
 *           decisive: string|null, views: string[], note: string}}
 */
export function pipelineFor(rec) {
  if (!rec || typeof rec !== 'object') return null;
  const kind = str(rec.kind);
  const layout = LAYOUTS[kind];
  if (!layout) return null;

  const findings = Array.isArray(rec.findings) ? rec.findings.filter((f) => f && typeof f === 'object') : [];
  const disabled = new Set(Array.isArray(rec.detectors_disabled) ? rec.detectors_disabled.map((x) => str(x)) : []);
  const timings = rec.timings_ms && typeof rec.timings_ms === 'object' ? rec.timings_ms : {};
  const action = str(rec.action);
  const judge = str(rec.judge) || 'skipped';

  const hits = {};
  for (const f of findings) {
    const s = stageFor(kind, f.control_id);
    if (s) (hits[s] = hits[s] || []).push(f);
  }
  const primaryStage = rec.primary ? stageFor(kind, rec.primary.control_id) : null;
  const decisive = action === 'block' || action === 'require_approval' ? primaryStage : null;

  const order = layout.flat();
  const indexOf = (id) => layout.findIndex((item) => (Array.isArray(item) ? item.includes(id) : item === id));
  const decisiveIdx = decisive ? indexOf(decisive) : -1;

  const views = [];
  for (const f of findings) {
    if (isDecodedVia(f.via) && !views.includes(str(f.via))) views.push(str(f.via));
  }

  const modelCalled = isNum(timings.upstream);

  function node(id) {
    const def = STAGES[id];
    const idx = indexOf(id);
    const fs = hits[id] || [];
    const base = { id, label: def.label, independent: !!def.independent, findings: fs, ms: null, detail: '' };
    const notReached = decisiveIdx >= 0 && idx > decisiveIdx && id !== 'seal';

    if (id === 'seal') {
      const sealed = isNum(rec.seq);
      return { ...base, state: sealed ? 'sealed' : 'idle',
        detail: sealed ? `#${rec.seq} ${str(rec.hash).slice(0, 8)}` : 'not sealed' };
    }
    if (notReached) return { ...base, state: 'not-reached', detail: 'not reached' };
    if (def.detector && disabled.has(def.detector) && !fs.length) {
      return { ...base, state: 'off', detail: 'disabled by override' };
    }
    if (id === 'judge') {
      const ms = isNum(timings.judge) && JUDGE_CALLED.has(judge) ? timings.judge : null;
      if (fs.length) {
        const a = strongest(fs.map((f) => str(f.action)));
        const st = a === 'allow' || a === 'monitor' ? 'note' : 'hit';
        return { ...base, state: st, action: a, ms, detail: `judge: ${judge}` };
      }
      if (judge === 'skipped') return { ...base, state: 'skipped', detail: 'not needed (bypass)' };
      if (judge === 'disabled') return { ...base, state: 'off', detail: 'disabled' };
      if (JUDGE_CALLED.has(judge)) return { ...base, state: 'pass', ms, detail: `called: ${judge}` };
      return { ...base, state: 'degraded', detail: `judge ${judge}` };
    }
    if (id === 'model') {
      if (modelCalled) return { ...base, state: 'pass', ms: timings.upstream, detail: 'called' };
      return { ...base, state: 'not-called', detail: 'not called' };
    }
    if (id === 'exec') {
      if (modelCalled) return { ...base, state: 'pass', ms: timings.upstream, detail: 'executed' };
      return { ...base, state: 'not-called', detail: 'not executed' };
    }
    if (id === 'output') {
      if (!modelCalled) return { ...base, state: 'not-called', detail: 'no model output' };
      if (str(rec.direction) === 'output' || fs.length) {
        const pool = fs.length ? fs : findings;
        const a = strongest(pool.map((f) => str(f.action)));
        return { ...base, state: a === 'allow' || a === 'monitor' ? 'note' : 'hit', action: a,
          detail: 'findings in model output' };
      }
      return { ...base, state: 'pass', detail: 'clean' };
    }
    if (fs.length) {
      const a = strongest(fs.map((f) => str(f.action)));
      const st = a === 'allow' || a === 'monitor' ? 'note' : 'hit';
      return { ...base, state: st, action: a, detail: str(fs[0].control_id) + (fs.length > 1 ? ` +${fs.length - 1}` : '') };
    }
    return { ...base, state: 'pass', detail: '' };
  }

  const columns = layout.map((item) =>
    Array.isArray(item) ? { group: true, nodes: item.map(node) } : { group: false, nodes: [node(item)] });

  let note = '';
  if (kind === 'chat') note = 'Detector nodes show every finding in this record (prompt and model output).';
  else if (kind === 'tool') note = 'Detectors scan the tool result after execution; flow guard runs before it.';
  else note = 'Inspect only (/api/try): no model is called.';

  return { kind, columns, order, decisive, views, note, total: isNum(timings.total) ? timings.total : null };
}
