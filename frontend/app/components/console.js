// CONSOLE tab: operator control plane.

import { html, useEffect, useRef, useState } from '../vendor/preact-htm.js';
import { Stream } from './stream.js';
import { Drawer } from './drawer.js';
import { Approvals } from './approvals.js';
import { Agents } from './agents.js';
import { PolicyPanel } from './policy.js';
import { AuditPanel } from './audit.js';
import { Coverage, Posture } from './posture.js';
import { events, eventsVersion } from '../state.js';
import { useSig } from '../lib/hooks.js';
import { str } from '../lib/format.js';

/** Polite screen-reader summary of new blocking decisions (throttled). */
function Announcer() {
  const v = useSig(eventsVersion);
  const seen = useRef(0);
  const [msg, setMsg] = useState('');
  useEffect(() => {
    const list = events();
    if (!list.length) return;
    const top = list[0].seq;
    if (!seen.current) { seen.current = top; return; }
    const fresh = [];
    for (const r of list) { if (r.seq > seen.current) fresh.push(r); else break; }
    seen.current = top;
    const blocks = fresh.filter((r) => r.action === 'block' || r.action === 'require_approval');
    if (blocks.length) {
      const r = blocks[0];
      setMsg(`${blocks.length} new ${blocks.length === 1 ? 'decision needs' : 'decisions need'} attention. Latest: ${str(r.action)} ${str(r.primary && r.primary.control_id)} by ${str(r.agent_id) || 'unknown agent'}.`);
    }
  }, [v]);
  return html`<div class="sr-only" aria-live="polite">${msg}</div>`;
}

export function ConsoleView() {
  return html`<div class="console">
    <${Announcer} />
    <div class="c-main"><${Stream} /></div>
    <div class="c-side">
      <${Approvals} />
      <${Agents} />
    </div>
    <div class="c-grid">
      <${PolicyPanel} />
      <div class="c-col">
        <${AuditPanel} />
        <${Posture} />
      </div>
      <${Coverage} />
    </div>
    <${Drawer} />
  </div>`;
}
