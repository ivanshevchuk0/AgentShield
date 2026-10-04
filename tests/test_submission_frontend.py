"""Submission regressions: distinguish security review from assistant dispatch."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

APP = Path(__file__).resolve().parents[1] / 'frontend' / 'app'


def run_js(script):
    if not shutil.which('node'):
        pytest.skip('node is not installed')
    result = subprocess.run(['node', '--input-type=module', '-e', script], cwd=APP,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_security_judge_block_does_not_claim_assistant_was_called():
    nodes = run_js("""
      import {pipelineFor} from './lib/pipeline.js';
      const finding = {control_id: 'semantic.judge', action: 'block'};
      const pipeline = pipelineFor({kind: 'chat', action: 'block', judge: 'block',
        primary: finding, findings: [finding], timings_ms: {judge: 666, total: 672}});
      console.log(JSON.stringify(pipeline.columns.flatMap(column => column.nodes)));
    """)
    judge = next(node for node in nodes if node['id'] == 'judge')
    assistant = next(node for node in nodes if node['id'] == 'model')
    assert judge['label'] == 'Security judge'
    assert judge['ms'] == 666
    assert assistant['label'] == 'Assistant model'
    assert assistant['state'] == 'not-reached'
    assert assistant['ms'] is None


def test_chat_does_not_wait_for_admin_snapshot_before_dispatch():
    result = run_js("""
      globalThis.location = {hash: ''};
      globalThis.window = {addEventListener() {}};
      globalThis.setInterval = () => 0;
      const paths = [];
      globalThis.fetch = async path => {
        paths.push(path);
        return path === '/v1/chat/completions'
          ? new Response(JSON.stringify({agentshield: {record: {seq: 4, action: 'allow'}}}), {status: 200})
          : new Response('{}', {status: 401});
      };
      const {chatCall} = await import('./lib/moments.js');
      const result = await chatCall('wk_judge', 'test', 'test-session', 'test');
      console.log(JSON.stringify({paths, result}));
    """)
    assert result['paths'][0] == '/v1/chat/completions'
    assert result['result']['record']['seq'] == 4
