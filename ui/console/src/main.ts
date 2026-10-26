// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// The console, assembled: one app with a side navigation (D-062, Q41), each
// section a URL hash, the top bar, the strips and the gate on every page.
//
// The page keeps itself current (D-032): every few seconds it reads again
// whatever **writes no audit record**: Gate Core's state (`/v1/status`), the
// journal, provenance, the inventory as last checked and alerts. What does
// write one stays a person's click: opening a folder (`/v1/list`) and checking
// the copies (`/v1/stat`), because a screen that did those by itself would
// write someone's audit trail on its own initiative.

import { ApiError, api, type LaunchApp } from "./api.js";
import { type Data, cloud, local, sessionStart } from "./data.js";
import { ask, chip, details, el, fill, hhmm, icon, list, pill, when } from "./dom.js";
import { renderArtifacts } from "./views/artifacts.js";
import { renderCopies } from "./views/copies.js";
import { renderGate } from "./views/gate.js";
import { renderRecord } from "./views/record.js";
import { renderSources } from "./views/sources.js";
import { renderWork } from "./views/work.js";

const $ = (id: string): HTMLElement => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`the page is missing #${id}`);
  return node;
};

/** Seconds between reads while the page is open, and while it waits. */
const EVERY_MS = 10_000;
const WAITING_MS = 3_000;
let next: ReturnType<typeof setTimeout> | undefined;

/** The last answer, kept when a read fails so the page shows what it had. */
let data: Data | undefined;
/** What the last read saw: a timed read that sees the same draws nothing,
 * so focus, a text selection and a scrolled list survive the refresh. */
let seen = "";
/** When this page stopped getting answers, and why. */
let lost: { at: string; detail: string } | undefined;
let lastChange: string | undefined;
/** An app that did not open (D-027), until dismissed. */
let launchFailed: { app: LaunchApp; label: string; detail: string } | undefined;

const PAGES = ["work", "artifacts", "copies", "sources", "record"] as const;
type Page = (typeof PAGES)[number];
const page = (): Page => (PAGES as readonly string[]).includes(location.hash.slice(1)) ? (location.hash.slice(1) as Page) : "work";

function again(ms: number): void {
  clearTimeout(next);
  next = setTimeout(() => void refreshAll(true), ms);
}

/** Read everything and draw it. `auto` is a timed read. */
async function refreshAll(auto = false): Promise<void> {
  if (!auto) live("refreshing");
  try {
    const [state, view, journal, alerts, provenance, inventory] = await Promise.all([
      api.state(), api.sources(), api.journal(), api.alerts().catch(() => []), api.provenance(), api.inventory(),
    ]);
    const now = JSON.stringify([state, view, journal, alerts, provenance, inventory]);
    const changed = now !== seen || lost !== undefined;
    lost = undefined;
    data = { state, view, journal, alerts, provenance, inventory };
    if (changed || !auto) {
      seen = now;
      lastChange = new Date().toISOString();
      draw();
    } else {
      // The clock-bound parts only: the meters' and the gate's.
      live("idle");
    }
  } catch (e) {
    const detail = e instanceof ApiError ? `${e.failure.code}` : e instanceof Error ? e.message : String(e);
    lost ??= { at: new Date().toISOString(), detail };
    draw();
  }
  again(data && gated(data) ? WAITING_MS : EVERY_MS);
}

/** The person must sign in first, or Sluse has never answered (Q8, Q35). */
function gated(d: Data): "waiting" | "signing-in" | null {
  if (d.state.gate.status !== "serving") return d.journal.length === 0 ? "waiting" : null;
  const b = d.state.gate;
  const onlyCloud = cloud(d).length > 0 && local(d).length === 0;
  return onlyCloud && !b.signedIn && !b.signedOut ? "signing-in" : null;
}

function draw(): void {
  live(lost ? "lost" : "idle");
  if (!data) {
    fill($("strips"), lost ? strip("warning", "This page has stopped getting answers.", "It tries again every 10 seconds. If it stays like this, close the box from the bar above and open it again.", details(lost.detail)) : null);
    return;
  }
  const d = data;
  const gate = gated(d);
  $("cx").toggleAttribute("data-gate", !!gate);
  $("gate").hidden = !gate;
  if (gate) {
    renderGate($("gate"), d, gate, lost);
    return;
  }
  drawStrips(d);
  drawNav(d);
  const target = $("page");
  const p = page();
  for (const a of document.querySelectorAll<HTMLAnchorElement>(".sidenav__item[href]")) {
    if (a.getAttribute("href") === `#${p}`) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  const refresh = (): void => void refreshAll();
  if (p === "work") renderWork(target, d);
  if (p === "artifacts") renderArtifacts(target, d);
  if (p === "copies") renderCopies(target, d, refresh);
  if (p === "sources") renderSources(target, d);
  if (p === "record") renderRecord(target, d);
}

function live(state: "idle" | "refreshing" | "lost"): void {
  const l = $("live");
  if (state === "lost") fill(l, pill("problem", "Not answering"));
  else if (state === "refreshing") fill(l, "Refreshing");
  else if (lastChange) fill(l, el("span", { class: "cx-live__word" }, "Last change "), when(lastChange));
}

const p = (...c: (Node | string)[]): HTMLElement => el("p", {}, ...c);

// ---- Strips: what holds on every page -------------------------------------

function strip(kind: string, title: string, text: string, ...more: (Node | null)[]): HTMLElement {
  return el("div", { class: "banner banner--strip", "data-kind": kind, role: kind === "problem" ? "alert" : "status" },
    el("div", { class: "banner__body" }, el("p", { class: "banner__title" }, title), el("p", { class: "banner__text" }, text), ...more),
    el("span", {}));
}

function drawStrips(d: Data): void {
  const b = d.state.gate;
  const strips: (Node | null)[] = [];
  const c = cloud(d), l = local(d);
  const are = (xs: string[]): string => (xs.length > 1 ? "are" : "is");
  if (lost) {
    strips.push(strip("warning", `This page stopped getting answers at ${when(lost.at).textContent}.`,
      "What you see is from then. It asks again every 10 seconds. If this stays, close the box from the bar above and open it again.", details(lost.detail)));
  }
  if (b.status !== "serving") {
    strips.push(strip("warning", "Sluse on your computer is not answering.",
      "Nothing new can be let into the box until it answers. What is already here stays. This page asks again by itself.", details(`gate unreachable: ${b.detail}`)));
  } else if (c.length && b.signedOut) {
    strips.push(strip("info", "You signed out.",
      `${list(c)} ${are(c)} not read until you sign in again${l.length ? `; ${list(l)} ${are(l)} still read as your Windows account` : ""}. To sign in again, close the box from the bar above and open Sluse again.`));
  } else if (c.length && !b.signedIn) {
    strips.push(strip("info", `${list(c)} ${c.length > 1 ? "wait" : "waits"} for you to sign in.`,
      `${list(l)} ${are(l)} read now, so you can open an AI agent. If a Microsoft sign-in window has opened on your computer, finish it there.`));
  }
  if (launchFailed) {
    const f = launchFailed;
    const retry = el("button", { class: "btn btn--sm", type: "button", onclick: () => launch(f.app, f.label) }, `Open ${f.label} again`);
    const s = strip("warning", `${f.label} did not open.`, "Try again. If it still does not open, send the details to your IT department.",
      el("div", { class: "banner__actions" }, retry), details(`POST /api/launch {"app":"${f.app}"}: ${f.detail}`));
    s.lastElementChild?.replaceWith(el("button", { class: "btn btn--quiet btn--icon btn--sm banner__close", type: "button", "aria-label": "Dismiss",
      onclick: () => { launchFailed = undefined; draw(); } }, icon("close")));
    strips.push(s);
  }
  if (b.status === "serving" && b.configVersion !== d.state.configVersion) {
    strips.push(strip("warning", "Your IT department changed Sluse's settings on your computer, and this box still has the old ones.",
      "What is let in follows the new settings. If this stays, send the details to your IT department.",
      details(`settings mismatch: computer ${b.configVersion}, box ${d.state.configVersion}`)));
  }
  fill($("strips"), ...strips);
}

// ---- Navigation, its foot, and About this box ------------------------------

function drawNav(d: Data): void {
  const count = (id: string, n: number): void => fill($(id), n ? String(n) : "");
  count("n-artifacts", d.provenance.filter((x) => x.outcome === "admitted").length);
  count("n-copies", d.inventory.length);
  count("n-sources", d.view.sources.length);
  count("n-record", d.journal.length);
  const since = sessionStart(d);
  fill($("since"), since ? `This session: since the box opened at ${hhmm(since)}${new Date(since).toDateString() === new Date().toDateString() ? " today" : ""}` : "");
  const dep = d.state.deployment;
  fill($("deployment"), dep ? `${dep.name || dep.id}, revision ${dep.revision}` : "");
}

function about(): void {
  const d = data;
  if (!d) return;
  for (const m of document.querySelectorAll<HTMLDetailsElement>("details.menu[open]")) m.open = false;
  const since = sessionStart(d);
  const dep = d.state.deployment;
  fill($("about"),
    p("This page shows what Sluse let into this box, what AI agents published from it, and what was recorded. It lets nothing in and refuses nothing: every decision shown here was made by Sluse on your computer."),
    el("dl", { class: "facts" },
      el("div", {}, el("dt", {}, "Box"), el("dd", {}, chip(d.state.boxId, "Copy the box id"))),
      el("div", {}, el("dt", {}, "Session"), el("dd", {}, chip(d.state.session, "Copy the session id"))),
      since ? el("div", {}, el("dt", {}, "Opened"), el("dd", {}, when(since))) : null,
      el("div", {}, el("dt", {}, "Settings version"), el("dd", {}, dep ? `${dep.name || dep.id}, revision ${dep.revision}` : d.state.configVersion.slice(0, 12)))),
    details(`box ${d.state.boxId}\nsession ${d.state.session}${since ? `, opened ${since}` : ""}\nconfig ${dep ? `${dep.name || dep.id} revision ${dep.revision}, ` : ""}${d.state.configVersion}`),
    el("p", { class: "note", "data-kind": "info" }, "This page has no sign-in of its own. Anything running in this box can read it, as anything in the box can use the Sluse tools the AI agents use."));
  void ask("dlg-about");
}

// ---- Opening an app in the box (D-027) ------------------------------------

// The launch answers at once and the app's window takes seconds, so the
// button stays busy for a while after it, and a second click opens nothing
// more (L1, 2026-10-06).
const APP_SETTLES_MS = 5000;
function launch(app: LaunchApp, label: string, button?: HTMLButtonElement): void {
  if (button?.getAttribute("aria-busy") === "true") return;
  button?.setAttribute("aria-busy", "true");
  if (button) button.disabled = true;
  const done = (): void => { button?.removeAttribute("aria-busy"); if (button) button.disabled = false; };
  api.launch(app)
    .then(() => { if (launchFailed?.app === app) { launchFailed = undefined; draw(); } setTimeout(done, APP_SETTLES_MS); })
    .catch((e: unknown) => {
      done();
      launchFailed = { app, label, detail: e instanceof ApiError ? e.failure.code : String(e) };
      draw();
    });
}

document.addEventListener("click", (e) => {
  const t = e.target as Element;
  const b = t.closest<HTMLButtonElement>("[data-app]");
  if (b) launch(b.dataset.app as LaunchApp, b.textContent?.trim() || "The app", b);
  if (t.closest("[data-about]")) about();
  if (t.closest("[data-states]")) void ask("dlg-states");
});
$("refresh").addEventListener("click", () => void refreshAll());
addEventListener("hashchange", () => { draw(); $("main").scrollTop = 0; $("main").focus({ preventScroll: true }); });
// Menus close on an outside click and Esc.
document.addEventListener("click", (e) => {
  for (const m of document.querySelectorAll<HTMLDetailsElement>("details.menu[open]")) if (!m.contains(e.target as Node)) m.open = false;
});

void refreshAll();
