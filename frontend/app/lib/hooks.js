// Bridge between @preact/signals-core and Preact hooks: a component re-renders when a signal
// it reads changes. (The full @preact/signals package needs bare-specifier imports, which an
// import map would allow, but an inline import map conflicts with the strict CSP.)

import { useState, useEffect, useRef } from '../vendor/preact-htm.js';
import { effect } from '../vendor/signals-core.js';

export function useSig(sig) {
  const [, setTick] = useState(0);
  const seen = useRef(undefined);
  const value = sig.peek();
  seen.current = value;
  useEffect(() => effect(() => {
    const next = sig.value;
    if (next !== seen.current) {
      seen.current = next;
      setTick((t) => t + 1);
    }
  }), [sig]);
  return value;
}

export function useInterval(fn, ms) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    const id = setInterval(() => ref.current(), ms);
    return () => clearInterval(id);
  }, [ms]);
}

export function prefersReducedMotion() {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}
