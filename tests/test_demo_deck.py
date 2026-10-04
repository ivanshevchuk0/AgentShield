"""Exercise the actual browser demo card functions against the real gateway routes."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import shutil
import subprocess
import threading

import pytest

APP = Path(__file__).resolve().parents[1] / 'frontend' / 'app'


@pytest.mark.skipif(shutil.which('node') is None, reason='node is not installed')
def test_demo_deck_prerequisites_and_complete_execution(client):
    requests = []

    class Bridge(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def dispatch(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            requests.append(self.path)
            response = client.request(self.command, self.path, content=body or None,
                headers={k: v for k, v in self.headers.items() if k.lower() != 'host'})
            self.send_response(response.status_code)
            self.send_header('Content-Type', response.headers.get('content-type', 'application/json'))
            self.send_header('Content-Length', str(len(response.content)))
            for name in ('X-AgentShield-Record', 'X-AgentShield-Decision'):
                if name in response.headers:
                    self.send_header(name, response.headers[name])
            self.end_headers()
            self.wfile.write(response.content)

        do_GET = dispatch
        do_POST = dispatch

    server = HTTPServer(('127.0.0.1', 0), Bridge)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    script = """
      globalThis.location = {hash: ''};
      globalThis.window = {addEventListener() {}};
      globalThis.setInterval = () => 0;
      const nativeFetch = globalThis.fetch;
      const paths = [];
      globalThis.fetch = (path, options) => {
        paths.push(path);
        return nativeFetch(new URL(path, process.argv[1]), options);
      };
      const {setAdminToken} = await import('./api.js');
      setAdminToken('test-admin-token');
      const {buildDeck, nextStepIndex} = await import('./lib/moments.js');
      let lastSeq = null;
      const ctx = {sessions: {}, approval: {id: null}, lastRecordSeq: () => lastSeq};
      const deck = buildDeck(ctx);
      const card = id => deck.find(card => card.id === id);
      const early = [await card('flow').steps[2].run(), await card('flow').steps[3].run(),
        await card('transfer').steps[2].run(), await card('transfer').steps[3].run()];
      const earlyPaths = paths.slice();
      const results = [];
      for (const card of deck) {
        for (const step of card.steps) {
          const result = await step.run();
          if (result.record) lastSeq = result.record.seq;
          results.push({card: card.id, step: step.label, ...result});
        }
      }
      const next = [nextStepIndex([1,2,3], [null, 'allow']),
        nextStepIndex([1,2,3], ['allow', null, 'block']),
        nextStepIndex([1,2], ['allow','block'])];
      console.log(JSON.stringify({early, earlyPaths, results, lastSeq, next}));
    """
    try:
        result = subprocess.run(['node', '--input-type=module', '-e', script,
            f'http://127.0.0.1:{server.server_port}'], cwd=APP,
            capture_output=True, text=True, timeout=45)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data['earlyPaths'] == []  # No unrelated e-mail or unapproved payment attempts.
    assert all(r['tone'] == 'error' for r in data['early'])
    assert data['next'] == [0, 1, -1]  # Missing/failed steps remain the next keyboard action.
    rows = data['results']
    assert not [r for r in rows if r['tone'] == 'error'], rows

    def selected(card, step):
        return next(r for r in rows if r['card'] == card and r['step'] == step)

    assert selected('benign', 'Send KYC question')['tone'] == 'allow'
    assert selected('pesel', 'Valid PESEL')['tone'] == 'redact'
    assert selected('pesel', 'Bad checksum')['tone'] == 'allow'
    assert all(r['tone'] == 'block' for r in rows if r['card'] == 'inject')
    assert selected('secret', 'AWS key in prompt')['record']['primary']['control_id'] == 'secrets.aws'
    for step in ('E-mail the IBAN', 'Try a fresh session'):
        assert selected('flow', step)['record']['primary']['control_id'] == 'flow.secret_egress'
    assert selected('budget', 'Call with wk_budget_demo')['http'] == 429
    assert selected('transfer', 'Request transfer')['tone'] == 'require_approval'
    assert selected('transfer', 'Retry with approval')['tone'] == 'allow'
    replay = selected('transfer', 'Replay approval')
    assert replay['tone'] == 'require_approval'
    assert 'consumed approval was not accepted' in ' '.join(replay['lines'])
    assert selected('transfer', 'Amount over limit')['record']['primary']['control_id'] == 'tools.max_value'
    assert selected('policy', 'Break it')['http'] == 400
    assert selected('policy', 'Re-run PESEL')['tone'] == 'block'
    assert selected('audit', 'Verify chain')['chain']['ok']
    assert selected('audit', 'Tamper drill')['drill']['seq'] == data['lastSeq']
    records = [r['record'] for r in rows if r.get('record')]
    assert len({r['seq'] for r in records}) == len(records)
    assert len({r['request_id'] for r in records}) == len(records)
    snapshot = client.get('/api/snapshot').json()
    assert snapshot['policy']['profile'] == 'standard'
