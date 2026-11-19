/**
 * Custom smooth scroll engine with an expressive speed-up / slow-down S-curve
 * (easeInOutQuint) so jumping from charts to packet/flow evidence feels crisp,
 * accelerated through the middle, and silky soft on arrival.
 */

export interface SmoothScrollOptions {
  /** Extra pixels to keep above the target element (accounts for sticky topbar). */
  offset?: number;
  /** Minimum animation duration in milliseconds. */
  minDuration?: number;
  /** Maximum animation duration in milliseconds. */
  maxDuration?: number;
  /** Center the element vertically inside the viewport when possible. */
  align?: "top" | "center";
  /** Callback invoked when the scroll arrives naturally (not cancelled by user). */
  onComplete?: () => void;
}

/**
 * Quintic ease-in-out S-curve:
 * - Starts gently (slow launch)
 * - Accelerates sharply through the midpoint (5x average velocity at t = 0.5)
 * - Decelerates smoothly into a feather-soft landing
 */
export function easeInOutQuint(t: number): number {
  const clamped = Math.max(0, Math.min(1, t));
  return clamped < 0.5
    ? 16 * clamped * clamped * clamped * clamped * clamped
    : 1 - Math.pow(-2 * clamped + 2, 5) / 2;
}

/**
 * Compute adaptive scroll duration from distance in pixels so short jumps feel
 * brisk and long page sweeps have enough time to showcase acceleration & braking.
 */
export function computeScrollDuration(distancePx: number, minDuration = 540, maxDuration = 960): number {
  const absDist = Math.abs(distancePx);
  if (!Number.isFinite(absDist) || absDist < 6) return 0;
  const scaled = minDuration + Math.sqrt(absDist) * 11.5;
  return Math.round(Math.max(minDuration, Math.min(maxDuration, scaled)));
}

let activeCancelScroll: (() => void) | null = null;

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function setWindowScrollInstant(y: number): void {
  if (typeof window === "undefined") return;
  try {
    window.scrollTo({ top: y, behavior: "instant" as ScrollBehavior });
  } catch {
    window.scrollTo(0, y);
  }
}

function animateContainerScroll(
  container: HTMLElement | Window,
  targetY: number,
  minDuration: number,
  maxDuration: number,
  onComplete?: () => void,
): () => void {
  const isWin = container === window;
  const startY = isWin ? window.scrollY || document.documentElement.scrollTop : (container as HTMLElement).scrollTop;
  const maxScroll = isWin
    ? Math.max(0, document.documentElement.scrollHeight - window.innerHeight)
    : Math.max(0, (container as HTMLElement).scrollHeight - (container as HTMLElement).clientHeight);
  const clampedTarget = Math.max(0, Math.min(maxScroll, Math.round(targetY)));
  const delta = clampedTarget - startY;

  if (Math.abs(delta) < 6 || prefersReducedMotion()) {
    if (isWin) {
      setWindowScrollInstant(clampedTarget);
    } else {
      (container as HTMLElement).scrollTop = clampedTarget;
    }
    onComplete?.();
    return () => {};
  }

  const duration = computeScrollDuration(delta, minDuration, maxDuration);
  const htmlEl = document.documentElement;
  const prevHtmlScrollBehavior = isWin ? htmlEl.style.scrollBehavior : "";
  if (isWin) {
    // Prevent CSS `html { scroll-behavior: smooth }` from interfering with per-frame rAF positions.
    htmlEl.style.scrollBehavior = "auto";
  }

  let rafId = 0;
  let finished = false;
  const startTime = performance.now();

  const cleanup = () => {
    if (finished) return;
    finished = true;
    if (rafId) window.cancelAnimationFrame(rafId);
    if (isWin) {
      htmlEl.style.scrollBehavior = prevHtmlScrollBehavior;
    }
    window.removeEventListener("wheel", handleInterrupt);
    window.removeEventListener("touchmove", handleInterrupt);
    window.removeEventListener("keydown", handleKeyInterrupt);
  };

  const handleInterrupt = () => {
    cleanup();
  };

  const handleKeyInterrupt = (event: KeyboardEvent) => {
    if (
      event.key === "ArrowDown" ||
      event.key === "ArrowUp" ||
      event.key === "PageDown" ||
      event.key === "PageUp" ||
      event.key === "Home" ||
      event.key === "End" ||
      event.key === " "
    ) {
      cleanup();
    }
  };

  window.addEventListener("wheel", handleInterrupt, { passive: true });
  window.addEventListener("touchmove", handleInterrupt, { passive: true });
  window.addEventListener("keydown", handleKeyInterrupt, { passive: true });

  const step = (now: number) => {
    if (finished) return;
    const elapsed = now - startTime;
    const t = Math.min(1, elapsed / duration);
    const eased = easeInOutQuint(t);
    const nextY = startY + delta * eased;

    if (isWin) {
      setWindowScrollInstant(nextY);
    } else {
      (container as HTMLElement).scrollTop = nextY;
    }

    if (t < 1) {
      rafId = window.requestAnimationFrame(step);
    } else {
      if (isWin) {
        setWindowScrollInstant(clampedTarget);
      } else {
        (container as HTMLElement).scrollTop = clampedTarget;
      }
      cleanup();
      onComplete?.();
    }
  };

  rafId = window.requestAnimationFrame(step);
  return cleanup;
}

/**
 * Smoothly scroll the window (and any vertically scrollable table wrapper)
 * to `target` with a speed-up / slow-down easeInOutQuint curve.
 */
export function animateScrollToElement(target: HTMLElement | null, options: SmoothScrollOptions = {}): () => void {
  if (!target || typeof window === "undefined") return () => {};

  if (activeCancelScroll) {
    activeCancelScroll();
    activeCancelScroll = null;
  }

  const {
    offset = 92,
    minDuration = 580,
    maxDuration = 960,
    align = "center",
    onComplete,
  } = options;

  const rect = target.getBoundingClientRect();
  const currentScrollY = window.scrollY || document.documentElement.scrollTop;
  let desiredY: number;

  if (align === "center") {
    const usableHeight = Math.max(240, window.innerHeight - offset);
    // Position target nicely in the upper-middle sweet spot (~36% of usable viewport height)
    const idealViewportY = offset + Math.min(usableHeight * 0.34, Math.max(24, (usableHeight - rect.height) * 0.42));
    desiredY = currentScrollY + rect.top - idealViewportY;
  } else {
    desiredY = currentScrollY + rect.top - offset;
  }

  // Also check if target is inside a vertically scrollable table container
  const cancels: (() => void)[] = [];
  let ancestor = target.parentElement;
  while (ancestor && ancestor !== document.body && ancestor !== document.documentElement) {
    const style = window.getComputedStyle(ancestor);
    const overflowY = style.overflowY;
    if ((overflowY === "auto" || overflowY === "scroll") && ancestor.scrollHeight > ancestor.clientHeight + 4) {
      const parentRect = ancestor.getBoundingClientRect();
      const targetOffsetInParent = rect.top - parentRect.top + ancestor.scrollTop;
      const desiredInnerTop = targetOffsetInParent - Math.max(36, (ancestor.clientHeight - rect.height) * 0.38);
      cancels.push(animateContainerScroll(ancestor, desiredInnerTop, Math.min(420, minDuration), Math.min(720, maxDuration)));
      break;
    }
    ancestor = ancestor.parentElement;
  }

  const cancelWin = animateContainerScroll(window, desiredY, minDuration, maxDuration, () => {
    if (activeCancelScroll === cancelAll) {
      activeCancelScroll = null;
    }
    onComplete?.();
  });
  cancels.push(cancelWin);

  const cancelAll = () => {
    for (const fn of cancels) fn();
    if (activeCancelScroll === cancelAll) {
      activeCancelScroll = null;
    }
  };

  activeCancelScroll = cancelAll;
  return cancelAll;
}
