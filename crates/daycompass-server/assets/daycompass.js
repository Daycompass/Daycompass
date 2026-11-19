// Daycompass's own script: first-party, no dependencies, loaded like
// htmx from this origin under the same CSP. Four small jobs, each
// keyed on a data attribute the server renders:
//
// * data-dc-elapsed="<seconds>": a running timer's elapsed time as of
//   rendering. Counts on from the moment the page first saw the
//   element, so the device's own clock never matters - only how much
//   time passed on it.
// * data-dc-widen / data-dc-shift="<units per second>": the timeline's
//   running block grows, and its "now" line moves, at that rate.
// * <details id="..."> keep their open state across htmx swaps, so a
//   section opened by hand does not close after every write.
// * data-dc-sortable lists of data-dc-task items can be reordered by
//   drag and drop: the drop fills the page's form[data-dc-move] and
//   submits it, and htmx sends it like any other write. A task can
//   also be dropped into another list if both are days of the plan
//   (data-dc-day, empty for the backlog), which sends that day along.
//
// Elements htmx swaps in later are picked up on the next tick.
"use strict";
(() => {
  const seen = new WeakMap();
  const pad = (n) => String(n).padStart(2, "0");
  // Same format as `routes::pages::format_clock`.
  const format = (s) => `${Math.floor(s / 3600)}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
  // When this page first saw `el`, and what `read` gave then.
  const base = (el, now, read) => {
    if (!seen.has(el)) {
      seen.set(el, { at: now, value: read() });
    }
    return seen.get(el);
  };

  const tick = () => {
    const now = Date.now();
    for (const el of document.querySelectorAll("[data-dc-elapsed]")) {
      const b = base(el, now, () => Number(el.dataset.dcElapsed));
      el.textContent = format(Math.max(0, Math.floor(b.value + (now - b.at) / 1000)));
    }
    for (const el of document.querySelectorAll("[data-dc-widen]")) {
      const b = base(el, now, () => Number(el.getAttribute("width")));
      const room = el.ownerSVGElement.viewBox.baseVal.width - Number(el.getAttribute("x"));
      const grown = b.value + ((now - b.at) / 1000) * Number(el.dataset.dcWiden);
      el.setAttribute("width", Math.min(room, grown).toFixed(2));
    }
    for (const el of document.querySelectorAll("[data-dc-shift]")) {
      const b = base(el, now, () => Number(el.getAttribute("x1")));
      const end = el.ownerSVGElement.viewBox.baseVal.width;
      const x = Math.min(end, b.value + ((now - b.at) / 1000) * Number(el.dataset.dcShift)).toFixed(2);
      el.setAttribute("x1", x);
      el.setAttribute("x2", x);
    }
  };
  tick();
  setInterval(tick, 1000);

  const open = new Set();
  document.addEventListener("toggle", (event) => {
    const el = event.target;
    if (el instanceof HTMLDetailsElement && el.id) {
      if (el.open) open.add(el.id);
      else open.delete(el.id);
    }
  }, true);
  document.addEventListener("htmx:load", (event) => {
    for (const id of open) {
      const el = document.getElementById(id);
      if (el instanceof HTMLDetailsElement && event.target.contains(el)) el.open = true;
    }
  });

  let dragged = null;
  // The list a drop would land in, or null where it cannot land.
  const target = (event) => {
    const el = event.target instanceof Element ? event.target : null;
    const list = el?.closest("[data-dc-sortable]");
    if (!dragged || !list || el.closest("[data-dc-task]") === dragged) return null;
    const home = dragged.parentElement;
    return list === home || ("dcDay" in list.dataset && "dcDay" in home.dataset) ? list : null;
  };
  document.addEventListener("dragstart", (event) => {
    dragged = event.target instanceof Element ? event.target.closest("[data-dc-sortable] > [data-dc-task]") : null;
    if (dragged) {
      event.dataTransfer.effectAllowed = "move";
      // Firefox starts no drag without data.
      event.dataTransfer.setData("text/plain", dragged.dataset.dcTask);
    }
  });
  document.addEventListener("dragover", (event) => {
    if (target(event)) event.preventDefault();
  });
  document.addEventListener("drop", (event) => {
    const list = target(event);
    const form = document.querySelector("form[data-dc-move]");
    if (!list || !form) return;
    event.preventDefault();
    // Before the first task whose middle is below the pointer, so a
    // drop in a gap or an empty list lands where it looks like it does.
    const others = [...list.children].filter((el) => el !== dragged);
    const below = others.findIndex((el) => {
      const box = el.getBoundingClientRect();
      return event.clientY < box.top + box.height / 2;
    });
    const at = below < 0 ? others.length : below;
    form.elements.task.value = dragged.dataset.dcTask;
    form.elements.after.value = others[at - 1]?.dataset.dcTask ?? "";
    form.elements.before.value = others[at]?.dataset.dcTask ?? "";
    if (form.elements.day) form.elements.day.value = list.dataset.dcDay;
    form.requestSubmit();
  });
  document.addEventListener("dragend", () => {
    dragged = null;
  });
})();
