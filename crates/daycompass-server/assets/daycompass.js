// Daycompass's own script: first-party, no dependencies, loaded like
// htmx from this origin under the same CSP. It only ever changes text.
//
// Live timers: an element with data-dc-elapsed="<seconds>" shows a
// running timer's elapsed time as of when the server rendered it. This
// counts on from the moment the page first saw the element, so the
// device's own clock never matters - only how much time passed on it.
// Elements htmx swaps in later are picked up on the next tick.
"use strict";
(() => {
  const base = new WeakMap();
  const pad = (n) => String(n).padStart(2, "0");
  // Same format as `routes::pages::format_clock`.
  const format = (s) => `${Math.floor(s / 3600)}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;

  const tick = () => {
    const now = Date.now();
    for (const el of document.querySelectorAll("[data-dc-elapsed]")) {
      if (!base.has(el)) {
        base.set(el, now - Number(el.dataset.dcElapsed) * 1000);
      }
      el.textContent = format(Math.max(0, Math.floor((now - base.get(el)) / 1000)));
    }
  };

  tick();
  setInterval(tick, 1000);
})();
