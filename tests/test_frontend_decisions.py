"""Exercise the dashboard's pure explanation helper without a browser or dependencies."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


APP = Path(__file__).resolve().parents[1] / "frontend" / "app"


def test_redaction_preview_does_not_claim_inspection_called_a_model():
    source = (APP / "components" / "demo.js").read_text()
    assert "Sanitized inspection preview" in source
    assert "Output redaction preview" in source
    assert "What the model received</span>" not in source
    assert "Model reply (mock upstream)</span>" not in source


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_decision_explanations_distinguish_enforcement_from_execution():
    records = [
        {"kind": "chat", "action": "allow", "summary": "No findings"},
        {"kind": "chat", "action": "block", "summary": "Policy block"},
        {"kind": "chat", "action": "block", "direction": "output", "timings_ms": {"upstream": 0}},
        {"kind": "tool", "action": "block", "timings_ms": {"upstream": 2}},
        {"kind": "chat", "action": "redact", "direction": "input"},
        {"kind": "chat", "action": "redact", "direction": "output"},
        {"kind": "tool", "action": "redact", "direction": "input"},
        {"kind": "tool", "action": "require_approval", "approval_id": "a1"},
        {"kind": "chat", "action": "require_approval", "timings_ms": {"upstream": 1}},
        {"kind": "chat", "action": "monitor"},
        *[{"kind": "try", "action": action} for action in ("allow", "block", "redact", "require_approval")],
        {"kind": "chat", "action": "unknown", "primary": {"detail": "<script>text</script>", "control_id": "test.rule"}},
        None,
    ]
    script = """
      import { decisionExplanation } from './lib/decision.js';
      let input = '';
      for await (const chunk of process.stdin) input += chunk;
      console.log(JSON.stringify(JSON.parse(input).map(decisionExplanation)));
    """
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script], cwd=APP,
        input=json.dumps(records), text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    explanations = json.loads(result.stdout)
    assert "not a guarantee" in explanations[0]["impact"]
    assert explanations[1]["reason"] == "Policy block"
    assert "no model or tool execution is recorded" in explanations[1]["impact"]
    for index in (2, 3):
        assert "Upstream already ran" in explanations[index]["impact"]
        assert "cannot undo" in explanations[index]["impact"]
    assert "before forwarding" in explanations[4]["impact"]
    assert "model output" in explanations[5]["impact"]
    assert "tool already ran" in explanations[6]["impact"]
    assert "pending human approval" in explanations[7]["impact"]
    assert "does not override" in explanations[7]["next"]
    assert "model already ran" in explanations[8]["impact"]
    assert "without enforcement" in explanations[9]["impact"]
    for explanation in explanations[10:14]:
        assert "Inspection only" in explanation["impact"]
        assert "preview" in explanation["next"]
    assert explanations[14]["reason"] == "<script>text</script>"
    assert explanations[14]["control"] == "test.rule"
    assert explanations[15] is None


@pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')
def test_chat_result_without_a_record_is_not_an_allow_verdict():
    script = """
      globalThis.location = {hash: ''};
      globalThis.window = {addEventListener() {}};
      globalThis.setInterval = () => 0;
      globalThis.fetch = async (path) => path === '/v1/chat/completions'
        ? new Response(JSON.stringify({choices: [{message: {content: 'echo'}}]}), {status: 200})
        : new Response('{}', {status: 401});
      const {chatCall} = await import('./lib/moments.js');
      const result = await chatCall('wk_judge', 'test', 'test-session', 'test');
      console.log(JSON.stringify(result));
    """
    result = subprocess.run(['node', '--input-type=module', '-e', script], cwd=APP,
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data['record'] is None
    assert data['tone'] == 'info'
    assert data['stamp'] == 'DECISION UNAVAILABLE'


@pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')
def test_chat_record_is_available_when_admin_endpoints_are_locked():
    script = """
      globalThis.location = {hash: ''};
      globalThis.window = {addEventListener() {}};
      globalThis.setInterval = () => 0;
      const record = {seq: 77, action: 'allow', agent_id: 'judge-sandbox', findings: []};
      const paths = [];
      globalThis.fetch = async (path) => {
        paths.push(path);
        return path === '/v1/chat/completions'
          ? new Response(JSON.stringify({agentshield: {seq: 77, record}}), {status: 200})
          : new Response('{}', {status: 401});
      };
      const {chatCall} = await import('./lib/moments.js');
      const result = await chatCall('wk_judge', 'test', 'test-session', 'test');
      console.log(JSON.stringify({result, paths}));
    """
    result = subprocess.run(['node', '--input-type=module', '-e', script], cwd=APP,
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data['result']['record']['seq'] == 77
    assert data['result']['tone'] == 'allow'
    assert not any(path.startswith('/api/events') for path in data['paths'])


def test_demo_does_not_fall_back_to_previous_evidence():
    source = (APP / 'components' / 'demo.js').read_text()
    assert 'const shownRec = result && result.record ? result.record : null;' in source
    assert 'previous record' not in source
