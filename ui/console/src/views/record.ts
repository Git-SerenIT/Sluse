// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// Record: what this box recorded in this session, newest first, in words,
// with the reason code under the words for whoever supports Sluse. On a
// development device the computer's record stands beside it, never merged:
// they are joined by admission id, and merging would hide exactly the
// disagreement the join exists to find (invariant 7).

import { api, type AuditRecord } from "../api.js";
import { type Data, OP, outcomePill, reasonWords } from "../data.js";
import { chip, el, fill, icon, pill, when } from "../dom.js";

type Kind = "all" | "in" | "pub" | "problem" | "other";
const KINDS: [Kind, string][] = [["all", "All"], ["in", "Let in"], ["pub", "Published"], ["problem", "Refused and errors"], ["other", "Other"]];
const kindOf = (r: AuditRecord): Kind =>
  r.outcome === "refused" || r.outcome === "error" ? "problem"
    : (r.op === "read" || r.op === "fetch") ? "in" : r.op === "publish" ? "pub" : "other";

let shown: Kind = "all";
let pages = 1;
const PAGE = 50;

const pathWords = (r: AuditRecord): string =>
  r.op === "clear" ? "(every copy in the box)" : r.pathRequested.replace(/^artifacts\//, "");

function table(rs: AuditRecord[]): HTMLElement {
  return el("div", { class: "table-wrap" }, el("table", { class: "table table--dense table--fixed" },
    el("colgroup", {}, el("col", { class: "c-time" }), el("col", { class: "c-op" }), el("col", {}), el("col", { class: "c-out" }), el("col", { style: "width:22%" }), el("col", { class: "c-hash" })),
    el("thead", {}, el("tr", {}, ...["Time", "What", "File", "Outcome", "Note", "Hash"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, ...rs.map((r) => {
      const [status, word] = outcomePill(r);
      const note = reasonWords(r.reason, r.outcome);
      const code = r.reason && note !== r.reason ? r.reason : undefined;
      return el("tr", { "data-outcome": r.outcome === "refused" || r.outcome === "error" ? r.outcome : undefined },
        el("td", { class: "when" }, when(r.ts)), el("td", {}, OP[r.op] ?? r.op), el("td", { class: "mono" }, pathWords(r)),
        el("td", {}, pill(status, word)),
        el("td", {}, note && note !== code ? note : "", code ? el("span", { class: "code-line" }, "Recorded as ", el("code", {}, code)) : null),
        el("td", {}, r.hash ? chip(r.hash, "Copy the full hash", true) : el("span", { class: "t-muted", "aria-label": "no hash" }, "none")));
    }))));
}

export function renderRecord(target: Element, d: Data): void {
  const redraw = (): void => renderRecord(target, d);
  const all = [...d.journal].reverse();
  const count = (k: Kind): number => (k === "all" ? all.length : all.filter((r) => kindOf(r) === k).length);
  const rows = (shown === "all" ? all : all.filter((r) => kindOf(r) === shown)).slice(0, pages * PAGE);
  const head = el("header", { class: "pagehead" }, el("div", { class: "pagehead__text" }, el("h1", { class: "t-h2" }, "Record"),
    el("p", {}, d.state.local
      ? "Two records side by side, never merged: this computer's and this box's. They share admission ids. Both hold what reached Sluse, not what an agent did without asking it."
      : "What this box recorded in this session, newest first. It holds what reached Sluse. What an agent did without asking Sluse is not here. Sluse on your computer keeps its own record, in this computer's Event Log, which your IT department can read; it is separate, and it holds the reasons for refusals.")));
  if (!all.length) {
    fill(target, head, el("div", { class: "empty" }, el("span", { class: "empty__icon" }, icon("journal")),
      el("h2", { class: "empty__title" }, "Nothing recorded yet in this session"),
      el("p", { class: "empty__text" }, "When an AI agent asks Sluse for a file, or publishes one, the box records it here as it happens.")));
    return;
  }
  const seg = el("div", { class: "seg", role: "radiogroup", "aria-label": "Show" }, ...KINDS.map(([k, label]) =>
    el("label", {}, el("input", { type: "radio", name: "flt", value: k, checked: shown === k, onchange: () => { shown = k; pages = 1; redraw(); } }),
      label, " ", el("span", { class: "count" }, String(count(k))))));
  const total = shown === "all" ? all.length : count(shown);
  const box = el("section", { class: "stack", style: "--stack-gap: var(--space-3)" },
    d.state.local ? el("h2", { class: "t-h3" }, "This box") : null,
    rows.length ? table(rows) : el("p", { class: "empty__text" }, "No records of this kind in this session."),
    total > rows.length ? el("div", { class: "cluster" },
      el("button", { class: "btn", type: "button", onclick: () => { pages++; redraw(); } }, "Show 50 more"),
      el("span", { class: "t-small t-muted" }, `Showing the newest ${rows.length} of ${total}.`)) : null);
  const host = d.state.local ? el("section", { class: "stack", style: "--stack-gap: var(--space-3)" }, el("h2", { class: "t-h3" }, "This computer: Sluse"), el("p", { class: "t-small t-muted" }, "Reading…")) : null;
  fill(target, head, el("div", { class: "cluster" }, seg), d.state.local ? el("div", { class: "twocol" }, host, box) : box);
  if (host) {
    api.audit(50).then((t) => fill(host, el("h2", { class: "t-h3" }, "This computer: Sluse"), table([...t.records].reverse())),
      () => fill(host, el("h2", { class: "t-h3" }, "This computer: Sluse"), el("p", { class: "empty__text" }, "Not available: Sluse on your computer did not send its record. In a box it never does; this column exists on a development device only.")));
  }
}
