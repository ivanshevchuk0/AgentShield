// Explain recorded outcomes only. A verdict is not proof that upstream was never called.
import { str, isNum } from './format.js';

export function decisionExplanation(rec) {
  if (!rec || typeof rec !== 'object') return null;
  const action = str(rec.action).toLowerCase();
  const kind = str(rec.kind);
  const inspected = kind === 'try';
  const called = isNum(rec.timings_ms && rec.timings_ms.upstream);
  const impact = {
    allow: 'Allowed by the active policy; this is not a guarantee that the content is safe.',
    block: called
      ? 'Upstream already ran; the gateway withheld the result. Blocking cannot undo upstream side effects.'
      : 'The gateway blocked this request; no model or tool execution is recorded.',
    redact: kind === 'tool'
      ? 'The tool already ran; detected sensitive spans were replaced in its result before returning it.'
      : str(rec.direction) === 'output'
        ? 'Detected sensitive spans in the model output were replaced before returning it.'
        : 'Detected sensitive spans in the input were replaced before forwarding it.',
    require_approval: called
      ? 'A proposed action needs approval; the model already ran, but this decision does not authorize tool execution.'
      : 'Execution is paused pending human approval.',
    monitor: 'Findings were recorded without enforcement; monitor mode does not block or redact them.',
  }[action] || 'Check the recorded summary and findings for this outcome.';
  const next = {
    allow: 'Review findings and enabled controls before using this result.',
    block: 'Remove the prohibited content or action and submit a new request; do not retry to bypass policy.',
    redact: 'Use the sanitized result, not the original sensitive content.',
    require_approval: 'Review the Approvals tab. An approval does not override independent flow-security checks.',
    monitor: 'Use enforce mode when you need policy findings to stop unsafe requests.',
  }[action] || 'Review the audit record.';
  const primary = rec.primary && typeof rec.primary === 'object' ? rec.primary : {};
  return {
    impact: inspected ? 'Inspection only: no model or tool was called and nothing was executed.' : impact,
    reason: str(rec.summary || primary.detail || 'No reason recorded.', 600),
    control: str(primary.control_id, 160),
    next: inspected ? 'This is a preview of the policy verdict. Submit through the gateway to enforce it.' : next,
  };
}
