// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// The gate: the foundation's full-screen wait over the console, while Sluse
// on the computer has not answered yet, or while a box whose every source
// needs the person waits for the sign-in (Q8). Nothing to press: the Sluse
// window signs in (D-036). After 2 minutes it says what to do (Q40, fixed),
// without claiming to know why.

import { type Data, cloud } from "../data.js";
import { details, el, fill, when } from "../dom.js";

const LONG_S = 120;
const pageReady = new Date().toISOString();
let since: { state: string; at: number } | undefined;

export function renderGate(target: Element, d: Data, state: "waiting" | "signing-in", lost?: { at: string; detail: string }): void {
  if (since?.state !== state) since = { state, at: Date.now() };
  const long = (Date.now() - since.at) / 1000 >= LONG_S;
  const elapsed = Math.floor((Date.now() - since.at) / 1000);
  const waiting = state === "waiting";
  const onlyOneDrive = d.view.sources.every((s) => s.kind === "onedrive");
  const step = (status: string, text: string, time?: Node | string, sub?: string): HTMLElement =>
    el("li", { class: "step", "data-step": status }, el("span", { class: "step__text" }, text), el("span", { class: "step__time" }, time ?? ""),
      sub ? el("span", { class: "step__sub" }, sub) : null);
  const banner = (title: string, text: string): HTMLElement =>
    el("div", { class: "banner", "data-kind": "warning" }, el("div", { class: "banner__body" }, el("p", { class: "banner__title" }, title), el("p", { class: "banner__text" }, text)), el("span", {}));
  fill(target, el("div", { class: "passage-wrap" }, el("div", { class: "passage" },
    el("section", { class: "passage__lead" },
      el("span", { class: "mark", "data-size": "64", "data-alt": "" }),
      el("div", { class: "stack", style: "--stack-gap: var(--space-4)", role: "status", "aria-live": "polite" },
        el("h1", { class: "passage__title" }, waiting ? "Waiting for Sluse" : "Signing you in"),
        el("p", { class: "passage__text" }, waiting
          ? "Your box is up. Sluse on your computer has not answered yet. This page asks again every few seconds and goes on by itself."
          : "The Sluse window on your computer signs you in with your Microsoft account, so Sluse can read files as you and never more than you can open yourself."),
        waiting ? null : el("p", { class: "passage__text t-muted" }, onlyOneDrive
          ? "This box's only source is your Sluse folder in OneDrive, which needs your Microsoft account."
          : `This box's sources are ${cloud(d).join(" and ")}, and they need your Microsoft account.`)),
      el("p", { class: "bigclock" }, el("span", { class: "bigclock__label" }, "Elapsed"),
        el("span", { class: "bigclock__num" }, `${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, "0")}`)),
      lost ? null : el("div", { class: "progress", "data-indeterminate": "", role: "progressbar", "aria-label": "Under way" }, el("div", { class: "progress__fill" })),
      lost ? banner("This page has stopped getting answers.", "So it cannot tell when Sluse on your computer answers. It tries again every 10 seconds. If it stays like this, close the box from the bar above and open it again.")
        : long && waiting ? banner("Sluse has not answered for 2 minutes.", "If it stays like this, close the box with Close the box in the bar above and open it again. If that does not help, send the details to your IT department.")
          : long ? banner("You are not signed in after 2 minutes.", "Look for a Microsoft sign-in window on your computer; it can open behind this one. If there is none, the bar above the box says what happened.")
            : null,
      long || lost ? details(lost ? `GET /api/state: ${lost.detail}\nlast answer ${lost.at}`
        : `box ${d.state.boxId}, session ${d.state.session}\ngate: ${d.state.gate.status === "serving" ? "serving, signedIn: none" : `unreachable (${d.state.gate.detail})`}`) : null,
      lost ? null : el("p", { class: "passage__foot t-small t-muted" }, "Nothing to press here. This page goes on by itself.")),
    el("ol", { class: "steps ledger", "aria-label": "Where this box is" },
      step("done", "This page is ready", when(pageReady)),
      lost ? step("failed", "This page stopped getting answers", when(lost.at))
        : waiting ? step("current", "Sluse on your computer answers", "asking every 3 s") : step("done", "Sluse on your computer answers"),
      waiting || lost ? step("next", "You are signed in")
        : step("current", "You are signed in", "asking every 3 s", "If a Microsoft sign-in window has opened on your computer, finish it there.")))));
}
