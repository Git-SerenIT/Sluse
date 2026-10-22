// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// Copies in the box: what an agent fetched through Sluse, kept until the
// person deletes it, every session (D-019). Checking against the sources is a
// person's click, one question per file, counted as the answers come (Q33);
// the rows keep their states until every answer is in, so the table never
// mixes two checks. A check's result survives timed reads; a file let in
// after it says Not checked.

import { ApiError, api, type InventoryRow } from "../api.js";
import { type Data, kindWords } from "../data.js";
import { ask, chip, details, el, fill, hhmm, icon, list, pill, size, when } from "../dom.js";
import { legend } from "./artifacts.js";

const WORD: Record<string, [string, string, string]> = {
  current: ["current", "Current", "The source still has these bytes."],
  stale: ["stale", "Changed", "The source has this file and it has changed since it was let in."],
  orphaned: ["orphaned", "Not at source", "The source no longer answers for this file: it was moved or deleted, or you can no longer open it."],
  unknown: ["unknown", "Not known", "Nobody could be asked. This is not a claim about the file."],
  missing: ["missing", "Copy missing", "The copy let into the box is no longer there."],
  unchecked: ["not-checked", "Not checked", "Not compared with the source yet."],
};
const pillFor = (k: string): HTMLElement => { const w = WORD[k] ?? WORD.unknown!; return pill(w[0], w[1]); };

/** The last check: each copy's answer, when it was made, or why it failed. */
let checked = new Map<string, InventoryRow>();
let checkedAt: string | undefined;
let checking: { asked: number; of: number; since: number } | undefined;
let checkFailed: string | undefined;
let cleared: { files: number; at: string } | undefined;

export function renderCopies(target: Element, d: Data, refresh: () => void): void {
  fill(document.getElementById("states")!,
    el("p", {}, "Each copy is compared with its source when you use ", el("b", {}, "Check against the sources"), ". Each question is recorded on your computer."),
    legend(Object.values(WORD)));
  const rows = d.inventory;
  const head = el("header", { class: "pagehead" },
    el("div", { class: "pagehead__text" }, el("h1", { class: "t-h2" }, "Copies in the box"),
      el("p", {}, "Copies of files an AI agent fetched through Sluse are kept in the box until you delete them. Files an agent only read get no copy from Sluse. What an agent writes from any of them is not listed here. This list covers every session of this box, not only this one.")),
    el("div", { class: "pagehead__actions" },
      el("button", { class: "btn", type: "button", "data-states": "" }, icon("info"), "What the states mean"),
      rows.length ? el("button", { class: "btn", type: "button", disabled: !!checking, "aria-busy": checking ? "true" : undefined,
        onclick: () => void check(rows, () => renderCopies(target, d, refresh)) }, icon("search"), "Check against the sources") : null,
      rows.length ? el("button", { class: "btn btn--destructive", type: "button", disabled: !!checking, onclick: () => void clear(d, refresh) }, icon("wipe"), "Delete the copies…") : null));
  if (!rows.length) {
    fill(target, head, el("div", { class: "empty" }, el("span", { class: "empty__icon" }, icon("download")),
      el("h2", { class: "empty__title" }, "No copies in the box"),
      ...(cleared ? [
        el("p", { class: "empty__text" }, `You deleted ${cleared.files} cop${cleared.files === 1 ? "y" : "ies"} at ${hhmm(cleared.at)}. The record of each admission is kept, and the deletion is in Record.`),
        el("p", { class: "empty__text" }, "Anything an AI agent made from these files, or saved elsewhere in the box, is still there. Sluse does not track those; wiping the box removes them.")]
        : [el("p", { class: "empty__text" }, "When an AI agent fetches a file, Sluse keeps a copy here with the record that let it in. Sluse keeps no copy of a file an agent only read. The agent can still save what it was shown.")])));
    return;
  }

  const stateOf = (r: InventoryRow): string => r.state === "missing" ? "missing" : checked.get(r.path)?.state ?? "unchecked";
  const after = checkedAt ? rows.filter((r) => !checked.has(r.path)).length : 0;
  const tally = new Map<string, number>();
  for (const r of rows) tally.set(stateOf(r), (tally.get(stateOf(r)) ?? 0) + 1);
  const notes = el("div", { class: "cx-banners" },
    !checkedAt && !checking && !checkFailed ? el("p", { class: "note", "data-kind": "info" },
      el("span", {}, "Not checked against the sources yet. Checking asks each source about each file, and each question is recorded on your computer.")) : null,
    checking ? el("div", { class: "panel stack", style: "--stack-gap: var(--space-2)", role: "status" },
      el("div", { class: "cluster" }, el("b", {}, `Asking the sources: ${checking.asked} of ${checking.of} files asked`)),
      el("div", { class: "progress", role: "progressbar", "aria-label": "Files asked", "aria-valuemin": 0, "aria-valuemax": checking.of, "aria-valuenow": checking.asked },
        el("div", { class: "progress__fill", style: `--value: ${(100 * checking.asked) / checking.of}%` })),
      el("p", { class: "t-small t-muted", style: "margin:0" }, "One question per file, one after another. The states below change when every answer is in.")) : null,
    checkedAt && !checking ? el("div", { class: "cluster" }, el("span", { class: "t-small" }, "Checked at ", when(checkedAt)),
      el("span", { class: "tallies" }, ...[...tally].map(([k, n]) => { const p = pillFor(k); p.classList.add("pill--count"); p.textContent = `${n} ${(WORD[k]?.[1] ?? k).toLowerCase()}`; return p; }))) : null,
    after && !checking ? el("p", { class: "note", "data-kind": "info" },
      el("span", {}, `${after === 1 ? "One file was" : `${after} files were`} let in after the check, so ${after === 1 ? "it says" : "they say"} Not checked. Check again to compare ${after === 1 ? "it" : "them"}.`)) : null,
    checkFailed ? el("div", { class: "banner", "data-kind": "warning", role: "alert" },
      el("div", { class: "banner__body" }, el("p", { class: "banner__title" }, "The check did not finish."),
        el("p", { class: "banner__text" }, "Sluse on your computer did not answer, so nothing was compared. The states below are from before. Try again in a moment; if it keeps happening, send the details to your IT department."),
        el("div", { class: "banner__actions" }, el("button", { class: "btn btn--sm", type: "button", onclick: () => void check(rows, () => renderCopies(target, d, refresh)) }, "Check again")),
        details(checkFailed)), el("span", {})) : null);

  const groups = new Map<string, InventoryRow[]>();
  for (const r of rows) groups.set(r.source, [...(groups.get(r.source) ?? []), r]);
  const tables = [...groups].map(([source, rs]) => {
    const view = d.view.sources.find((s) => s.name === source);
    return el("section", { class: "group" },
      el("div", { class: "group__head" }, el("h2", { class: "t-h3" }, source),
        el("small", {}, `${view ? `${kindWords(view)}, ` : ""}${rs.length} file${rs.length === 1 ? "" : "s"}`)),
      el("div", { class: "table-wrap" }, el("table", { class: "table table--fixed" },
        el("colgroup", {}, el("col", { class: "c-state" }), el("col", {}), el("col", { class: "c-when" }), el("col", { class: "c-size" }), el("col", { class: "c-hash" })),
        el("thead", {}, el("tr", {}, ...["State", "File", "Let in", "Size", "Hash"].map((h) => el("th", { scope: "col", class: h === "Size" ? "size" : undefined }, h)))),
        el("tbody", {}, ...rs.map((r) => {
          const k = stateOf(r);
          const c = checked.get(r.path);
          return el("tr", { "data-missing": k === "missing" },
            el("td", { class: "state" }, pillFor(k), c?.checkedAt ? el("div", { class: "t-small t-muted" }, `at ${hhmm(c.checkedAt)}`) : null),
            el("td", {}, el("div", { class: "paths" },
              k === "missing" ? el("del", { class: "mono" }, r.path) : el("span", { class: "mono" }, r.path),
              k === "missing" ? el("span", { class: "t-small" }, "The copy is no longer in the box. The record is kept.") : null,
              !r.sidecar && k !== "missing" ? el("span", { class: "t-small", title: "A re-read through Sluse will say it has no provenance." }, "No provenance file beside this copy") : null,
              k === "orphaned" ? el("span", { class: "t-small" }, WORD.orphaned![2]) : null)),
            el("td", { class: "when" }, when(r.admittedAt)),
            el("td", { class: "size" }, size(r.bytes)),
            el("td", {}, chip(r.hash, "Copy the full hash", true)));
        })))));
  });
  fill(target, head, el("div", { class: "stack", style: "--stack-gap: var(--space-6)" }, notes, ...tables));
}

/** Ask each source about each copy, in turn, and count the answers (Q33). */
async function check(rows: InventoryRow[], redraw: () => void): Promise<void> {
  if (checking) return;
  const asking = rows.filter((r) => r.localPresent);
  checking = { asked: 0, of: asking.length, since: Date.now() };
  checkFailed = undefined;
  redraw();
  const answers = new Map<string, InventoryRow>();
  try {
    for (const r of asking) {
      answers.set(r.path, await api.check(r.path));
      checking.asked++;
      redraw();
    }
    checked = answers;
    checkedAt = new Date().toISOString();
  } catch (e) {
    checkFailed = `POST /api/inventory/check: ${e instanceof ApiError ? e.failure.code : String(e)} at ${new Date().toISOString()}`;
  }
  checking = undefined;
  redraw();
}

/** Delete every copy, after the confirm that says what goes and what stays. */
async function clear(d: Data, refresh: () => void): Promise<void> {
  const present = d.inventory.filter((r) => r.localPresent);
  const bytes = present.reduce((n, r) => n + (r.bytes ?? 0), 0);
  fill(document.getElementById("clear-what")!,
    `${present.length} cop${present.length === 1 ? "y" : "ies"}, ${size(bytes)}, from ${list([...new Set(present.map((r) => r.source))])}`);
  if (await ask("dlg-clear") !== "ok") return;
  const message = document.getElementById("message")!;
  try {
    const done = await api.clear();
    if (done.failed.length) {
      fill(document.getElementById("dlg-message-t")!, `${done.failed.length} cop${done.failed.length === 1 ? "y" : "ies"} could not be deleted`);
      fill(message, el("p", {}, `Deleted ${done.files} of ${done.files + done.failed.length} copies. Some are still in the box, in use by a program in the box or with a provenance file that could not be removed.`),
        el("p", {}, "Close the program using it and try again. If it stays, send the details to your IT department."), details(done.failed.join("\n")));
      void ask("dlg-message");
    } else {
      cleared = { files: done.files, at: new Date().toISOString() };
    }
    checked = new Map();
    checkedAt = undefined;
  } catch (e) {
    fill(document.getElementById("dlg-message-t")!, "The copies were not deleted");
    fill(message, el("p", {}, "The box could not finish deleting them. What is listed now is what is still in the box. Try again; if it happens again, send the details to your IT department."),
      details(`POST /api/inventory/clear: ${e instanceof ApiError ? e.failure.code : String(e)}`));
    void ask("dlg-message");
  }
  refresh();
}

