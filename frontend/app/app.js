// AgentShield console: boot, hash routing (#/demo, #/console, #/console/<seq>), polling.

import { html, render } from './vendor/preact-htm.js';
import { route, startPolling } from './state.js';
import { useSig } from './lib/hooks.js';
import { StatusBar } from './components/statusbar.js';
import { DemoView } from './components/demo.js';
import { ConsoleView } from './components/console.js';

function App() {
  const r = useSig(route);
  return html`
    <button type="button" class="skip" onClick=${() => document.getElementById('main').focus()}>Skip to content</button>
    <${StatusBar} />
    <main id="main" tabIndex="-1">
      ${r.tab === 'console' ? html`<${ConsoleView} />` : html`<${DemoView} />`}
    </main>
    <footer class="foot small muted">
      Keys: 1–9 fire deck steps · R replay · / filter stream · Esc close.
      All server text is rendered as text; links in records are never clickable.
    </footer>`;
}

if (!location.hash) history.replaceState(null, '', '#/demo');
const mount = document.getElementById('app');
mount.textContent = '';
render(html`<${App} />`, mount);
startPolling();
