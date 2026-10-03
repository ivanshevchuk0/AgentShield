// Theme preference: system (follow prefers-color-scheme), light or dark. A per-viewer
// convenience kept in localStorage; every storage access is guarded.

import { signal } from '../vendor/signals-core.js';

const KEY = 'agentshield.theme';
const VALID = ['system', 'light', 'dark'];

function load() {
  try {
    const v = localStorage.getItem(KEY);
    return VALID.includes(v) ? v : 'system';
  } catch {
    return 'system';
  }
}

export const theme = signal(load());

export function applyTheme(value) {
  const root = document.documentElement;
  if (value === 'light' || value === 'dark') root.setAttribute('data-theme', value);
  else root.removeAttribute('data-theme');
}

export function setTheme(value) {
  const v = VALID.includes(value) ? value : 'system';
  theme.value = v;
  applyTheme(v);
  try {
    if (v === 'system') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, v);
  } catch { /* storage blocked: the choice lasts for this page only */ }
}

export function cycleTheme() {
  const order = { system: 'light', light: 'dark', dark: 'system' };
  setTheme(order[theme.peek()] || 'system');
}

applyTheme(theme.peek());
