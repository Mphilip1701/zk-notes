import { useEffect, useRef } from 'react';

/** Calls onIdle after `ms` without keyboard/pointer activity. */
export function useIdle(ms: number, onIdle: () => void): void {
  const cb = useRef(onIdle);
  cb.current = onIdle;
  useEffect(() => {
    let timer = window.setTimeout(() => cb.current(), ms);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => cb.current(), ms);
    };
    const events = ['keydown', 'pointerdown', 'pointermove', 'wheel', 'focus'] as const;
    for (const e of events) window.addEventListener(e, reset, { passive: true });
    return () => {
      window.clearTimeout(timer);
      for (const e of events) window.removeEventListener(e, reset);
    };
  }, [ms]);
}
