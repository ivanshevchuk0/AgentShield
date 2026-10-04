"""The PESEL deck uses actual gateway decisions and distinct chat-only executions."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from app import upstream

APP = Path(__file__).resolve().parents[1] / 'frontend' / 'app'


@pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')
def test_pesel_deck_has_fresh_records_and_different_checksum_results(client, monkeypatch):
    forwarded = []
    original = upstream.complete

    async def capture(model, cfg, body, **kwargs):
        forwarded.append(body['messages'][0]['content'])
        return await original(model, cfg, body, **kwargs)

    monkeypatch.setattr(upstream, 'complete', capture)
    payloads = []
    for value in ('44051401359', '44051401358', '44051401359'):
        response = client.post('/v1/chat/completions',
            headers={'Authorization': 'Bearer wk_judge', 'X-Admin-Token': ''},
            json={'model': 'mock/vulnerable-llm', 'messages': [
                {'role': 'user', 'content': f'Klient PESEL {value} pyta o limit kredytowy.'}]})
        assert response.status_code == 200
        payloads.append(response.json())
    assert '[PESEL]' in forwarded[0] and '44051401359' not in forwarded[0]
    assert '44051401358' in forwarded[1] and '[PESEL]' not in forwarded[1]
    script = """
      globalThis.location = {hash: ''};
      globalThis.window = {addEventListener() {}};
      globalThis.setInterval = () => 0;
      let input = '';
      for await (const chunk of process.stdin) input += chunk;
      const payloads = JSON.parse(input);
      const requests = [];
      globalThis.fetch = async (path, options) => {
        if (path !== '/v1/chat/completions') throw new Error('Unexpected request: ' + path);
        requests.push({path, body: JSON.parse(options.body), headers: options.headers});
        return new Response(JSON.stringify(payloads[requests.length - 1]), {status: 200});
      };
      const {buildDeck} = await import('./lib/moments.js');
      const card = buildDeck({sessions: {}, approval: {id: null}, lastRecordSeq: () => 193})
        .find(card => card.id === 'pesel');
      const results = [await card.steps[0].run(), await card.steps[1].run(), await card.steps[0].run()];
      console.log(JSON.stringify({results, requests}));
    """
    completed = subprocess.run(['node', '--input-type=module', '-e', script], cwd=APP,
        input=json.dumps(payloads), capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    data = json.loads(completed.stdout)
    valid, invalid, repeated = data['results']
    assert valid['title'] == repeated['title'] == 'PESEL checksum valid → REDACT'
    assert invalid['title'] == 'Invalid checksum → PASS'
    assert valid['tone'] == repeated['tone'] == 'redact'
    assert invalid['tone'] == 'allow'
    assert any(f['control_id'] == 'pii.pesel' for f in valid['record']['findings'])
    assert not any(f['control_id'] == 'pii.pesel' for f in invalid['record']['findings'])
    assert '[PESEL]' in valid['reply'] and '44051401359' not in valid['reply']
    assert '44051401358' in invalid['reply']
    assert len({r['record']['seq'] for r in data['results']}) == 3
    assert len({r['record']['request_id'] for r in data['results']}) == 3
    assert len({r['headers']['X-Session'] for r in data['requests']}) == 3
    assert all(r['headers']['Authorization'] == 'Bearer wk_judge' for r in data['requests'])
    assert all(r['body']['messages'][0]['role'] == 'user' for r in data['requests'])
    assert 'lookup_customer' not in json.dumps(data['requests'])
