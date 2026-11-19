// Daycompass's own script: first-party, no dependencies, loaded like
// htmx from this origin under the same CSP. Small jobs, each keyed on
// a data attribute or element the server renders:
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
// * Keyboard: Ctrl/Cmd+K opens the command menu (dialog#dc-command),
//   ? the shortcut overview (dialog#dc-keys); both are in the app
//   layout only. Outside text fields, N goes to the new-task field
//   (input[data-dc-new]), F to Focus, J/K and the arrows select a task
//   card (data-dc-task), and Space, Ctrl/Cmd+Enter and Ctrl/Cmd+Right
//   press the selected card's button with data-dc-key timer, done or
//   later. On Focus the card shown (data-dc-current) is the selected one.
// * A button with data-dc-key="done" that succeeds plays a short chime
//   (off on the account page, kept in this browser's localStorage) and
//   pops .dc-celebrate, unless the device asks for reduced motion.
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

  // The chime on completing a task, on unless switched off.
  const SOUND = "dc-sound";
  const soundOn = () => {
    try {
      return localStorage.getItem(SOUND) !== "off";
    } catch {
      return true;
    }
  };
  const toggle = document.querySelector("input[data-dc-sound]");
  if (toggle) {
    toggle.checked = soundOn();
    toggle.addEventListener("change", () => {
      try {
        localStorage.setItem(SOUND, toggle.checked ? "on" : "off");
      } catch {
        toggle.checked = soundOn();
      }
    });
  }
  let audio = null;
  const chime = () => {
    try {
      audio ??= new AudioContext();
      audio.resume().catch(() => {});
      // Two soft notes, a fifth apart.
      [523.25, 783.99].forEach((hz, i) => {
        const start = audio.currentTime + i * 0.09;
        const note = audio.createOscillator();
        const gain = audio.createGain();
        note.frequency.value = hz;
        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.exponentialRampToValueAtTime(0.12, start + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.4);
        note.connect(gain).connect(audio.destination);
        note.start(start);
        note.stop(start + 0.45);
      });
    } catch {
      // No audio here; the check still shows.
    }
  };
  // htmx fires afterRequest again on a parent still in the page when
  // the button itself was swapped out, so this sees every completion.
  document.addEventListener("htmx:afterRequest", (event) => {
    if (!event.detail.successful || !event.detail.elt.matches?.('[data-dc-key="done"]')) return;
    if (soundOn()) chime();
    const badge = document.querySelector(".dc-celebrate");
    if (!badge || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    badge.classList.remove("dc-celebrate--on");
    void badge.offsetWidth; // restarts the animation
    badge.classList.add("dc-celebrate--on");
  });
  document.addEventListener("animationend", (event) => {
    event.target.classList?.remove("dc-celebrate--on");
  });

  const command = document.getElementById("dc-command");
  const overview = document.getElementById("dc-keys");
  if (!command || !overview) return;

  const filter = command.querySelector("input");
  const options = [...command.querySelectorAll("[role=option]")];
  let active = null;
  const activate = (el) => {
    active?.setAttribute("aria-selected", "false");
    active = el ?? null;
    active?.setAttribute("aria-selected", "true");
    active?.scrollIntoView({ block: "nearest" });
    if (active) filter.setAttribute("aria-activedescendant", active.id);
    else filter.removeAttribute("aria-activedescendant");
  };
  const shown = () => options.filter((el) => !el.hidden);
  const narrow = () => {
    const words = filter.value.trim().toLowerCase();
    for (const el of options) el.hidden = !el.textContent.toLowerCase().includes(words);
    activate(shown()[0]);
  };
  filter.addEventListener("input", narrow);
  filter.addEventListener("keydown", (event) => {
    const list = shown();
    if ((event.key === "ArrowDown" || event.key === "ArrowUp") && list.length) {
      event.preventDefault();
      const by = event.key === "ArrowDown" ? 1 : -1;
      activate(list[(list.indexOf(active) + by + list.length) % list.length]);
    } else if (event.key === "Enter" && active) {
      event.preventDefault();
      active.click();
    }
  });
  const openCommand = () => {
    document.querySelector("dialog[open]")?.close();
    filter.value = "";
    narrow();
    command.showModal();
  };

  const run = {
    new: () => {
      const field = document.querySelector("input[data-dc-new]");
      if (field) field.focus();
      else location.assign("/missions/today#new");
    },
    keys: () => overview.showModal(),
  };
  if (location.hash === "#new") document.querySelector("input[data-dc-new]")?.focus();
  document.addEventListener("click", (event) => {
    const el = event.target instanceof Element ? event.target : null;
    if (el?.closest("#dc-command [role=option]")) command.close();
    const action = el?.closest("[data-dc-run]")?.dataset.dcRun;
    if (action) run[action]?.();
    if (el?.closest("[data-dc-close]")) el.closest("dialog")?.close();
  });

  // The selected task: the focused card, or else the one Focus shows.
  const selected = () =>
    document.activeElement?.closest("[data-dc-task]") ?? document.querySelector("[data-dc-current]");
  const press = (key) => {
    const button = selected()?.querySelector(`[data-dc-key="${key}"]`);
    button?.click();
    return Boolean(button);
  };
  // Moves the selection by one card. Arrows only move one that exists,
  // so they still scroll a page where nothing is selected.
  const step = (by, start) => {
    const cards = [...document.querySelectorAll("[data-dc-task]")].filter((el) => el.getClientRects().length);
    const at = cards.indexOf(document.activeElement?.closest("[data-dc-task]"));
    if (!cards.length || (at < 0 && !start)) return false;
    const next = at < 0 ? (by > 0 ? 0 : cards.length - 1) : Math.min(Math.max(at + by, 0), cards.length - 1);
    cards[next].focus();
    return true;
  };
  document.addEventListener("keydown", (event) => {
    const mod = event.ctrlKey || event.metaKey;
    if (mod && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "k") {
      event.preventDefault();
      if (command.open) command.close();
      else openCommand();
      return;
    }
    const target = event.target instanceof Element ? event.target : null;
    if (event.defaultPrevented || event.repeat || event.altKey || target?.matches("input, textarea, select")) return;
    if (document.querySelector("dialog[open]")) return;
    let handled = false;
    if (mod) {
      if (event.key === "Enter") handled = press("done");
      else if (event.key === "ArrowRight") handled = press("later");
    } else if (event.key === "?") {
      overview.showModal();
      handled = true;
    } else if (event.key.toLowerCase() === "n") {
      run.new();
      handled = true;
    } else if (event.key.toLowerCase() === "f") {
      if (location.pathname !== "/missions/focus") location.assign("/missions/focus");
      handled = true;
    } else if (event.key === " ") {
      // A focused button or link keeps Space for itself.
      if (target === document.body || target?.matches("[data-dc-task]")) handled = press("timer");
    } else if (event.key === "j" || event.key === "ArrowDown") {
      handled = step(1, event.key === "j");
    } else if (event.key === "k" || event.key === "ArrowUp") {
      handled = step(-1, event.key === "k");
    }
    if (handled) event.preventDefault();
  });
  // A selected card stays selected when a write swaps it out and back in.
  let reselect = null;
  document.addEventListener("htmx:beforeSwap", () => {
    const el = document.activeElement;
    reselect = el?.matches("[data-dc-task]") ? el.dataset.dcTask : null;
  });
  document.addEventListener("htmx:load", () => {
    if (reselect) document.querySelector(`[data-dc-task="${CSS.escape(reselect)}"]`)?.focus();
  });
})();
