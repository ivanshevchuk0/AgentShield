// Sealdesk console: boot, hash routing (#/demo, #/console, #/console/<seq>), polling.

import './lib/theme.js';   // applies the saved theme before the first render
import { html, render, useEffect } from './vendor/preact-htm.js';
import { route, startPolling } from './state.js';
import { useSig } from './lib/hooks.js';
import { StatusBar } from './components/statusbar.js';
import { DemoView } from './components/demo.js';
import { ConsoleView } from './components/console.js';

function App() {
  const r = useSig(route);
  useEffect(() => { document.title = r.tab === 'console' ? 'Sealdesk · Console' : 'Sealdesk · Demo'; }, [r.tab]);
  return html`
    <button type="button" class="skip" onClick=${() => document.getElementById('main').focus()}>Skip to content</button>
    <${StatusBar} />
    <main id="main" tabIndex="-1">
      ${r.tab === 'console' ? html`<${ConsoleView} />` : html`<${DemoView} />`}
    </main>
    <footer class="foot">
      <span class="foot-keys"><kbd>1</kbd>–<kbd>9</kbd> fire deck steps <kbd>R</kbd> replay <kbd>/</kbd> filter stream <kbd>Esc</kbd> close</span>
      <span>All server text is rendered as text; links in records are never clickable.</span>
    </footer>`;
}

if (!location.hash) history.replaceState(null, '', '#/demo');
const mount = document.getElementById('app');
mount.textContent = '';
render(html`<${App} />`, mount);
startPolling();
