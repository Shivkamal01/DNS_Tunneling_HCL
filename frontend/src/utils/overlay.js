import { useEffect, useRef } from 'react';

/**
 * Shared behaviour for the drawers and modals.
 *
 * Three things were missing from the hand-rolled overlays: the page behind the
 * panel kept scrolling, Escape handlers were registered even while a panel was
 * closed, and focus stayed on the table row underneath. These hooks keep that
 * behaviour consistent without pulling in a modal library.
 */

let lockCount = 0;
let originalOverflow = '';
let originalPaddingRight = '';

export function useBodyScrollLock(active) {
  useEffect(() => {
    if (!active) return undefined;

    if (lockCount === 0) {
      originalOverflow = document.body.style.overflow;
      originalPaddingRight = document.body.style.paddingRight;

      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.overflow = 'hidden';
      if (scrollbarWidth > 0) document.body.style.paddingRight = `${scrollbarWidth}px`;
    }

    lockCount += 1;

    return () => {
      lockCount = Math.max(0, lockCount - 1);
      if (lockCount === 0) {
        document.body.style.overflow = originalOverflow;
        document.body.style.paddingRight = originalPaddingRight;
      }
    };
  }, [active]);
}

export function useEscapeKey(active, handler) {
  const handlerRef = useRef(handler);

  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    if (!active) return undefined;

    const onKeyDown = (event) => {
      if (event.key === 'Escape') handlerRef.current?.(event);
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [active]);
}

export function useFocusReturn(active, containerRef) {
  useEffect(() => {
    if (!active) return undefined;

    const previous = document.activeElement;
    const timer = window.setTimeout(() => {
      containerRef.current?.focus?.({ preventScroll: true });
    }, 0);

    return () => {
      window.clearTimeout(timer);
      if (previous instanceof HTMLElement && document.contains(previous)) {
        previous.focus({ preventScroll: true });
      }
    };
  }, [active, containerRef]);
}

/**
 * Basic focus trap: keeps Tab cycling inside the active panel. This is not a
 * full inert-based implementation, but it stops the common case of tabbing
 * into the dashboard while a drawer is open.
 */
export function useFocusTrap(active, containerRef) {
  useEffect(() => {
    if (!active) return undefined;

    const onKeyDown = (event) => {
      if (event.key !== 'Tab' || event.defaultPrevented) return;

      const node = containerRef.current;
      if (!node) return;

      const focusable = Array.from(node.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )).filter((element) => element.offsetParent !== null);

      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const current = document.activeElement;

      if (current === node || !node.contains(current)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
        return;
      }

      if (event.shiftKey && current === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && current === last) {
        event.preventDefault();
        first.focus();
      }
    };

    const node = containerRef.current;
    node?.addEventListener('keydown', onKeyDown);
    return () => node?.removeEventListener('keydown', onKeyDown);
  }, [active, containerRef]);
}
