// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// Your artifacts: every publish from this box, this session first, then
// earlier sessions, dated (Q37). One group per publish, named as its folder
// in Sluse Artifacts; each file lists the sources the agent declared (D-055).
// Sluse checked each declared source was let in; it does not know how the
// agent used them. Never "verified".

import type { LineageItem, Provenance } from "../api.js";
import { type Data, folderOf, sessionStart } from "../data.js";
import { chip, day, details, el, fill, hhmm, icon, pill, size, when } from "../dom.js";

const STATE: Record<string, [string, string, string]> = {
  read: ["read", "Read", "Its text was shown to the agent. Sluse kept no copy of it."],
  unread: ["unread", "Let in, not shown", "Sluse let it in, but its text could not be shown to the agent."],
  fetched: ["fetched", "Fetched", "A copy was fetched into the box."],
  encrypted: ["encrypted", "Encrypted", "Arrived encrypted by its label. Sluse gave the box no key to open it."],
};

/** The legend, for "What the states mean". */
export function legend(rows: [string, string, string][]): HTMLElement {
  return el("dl", { class: "legend" }, ...rows.flatMap(([status, word, text]) => [el("dt", {}, pill(status, word)), el("dd", {}, text)]));
}

function source(s: LineageItem): HTMLElement {
  const st = STATE[s.state ?? "read"] ?? STATE.read!;
  return el("li", { class: "lineage__item" }, chip(s.path, "Copy the path"), pill(st[0], st[1]),
    el("dl", { class: "lineage__ids" },
      s.admissionId ? el("div", {}, el("dt", {}, "Admission"), el("dd", {}, chip(s.admissionId, "Copy the admission id"))) : null,
      el("div", {}, el("dt", {}, "Hash"), el("dd", {}, chip(s.hash, "Copy the full hash", true)))));
}

function card(p: Provenance): HTMLElement {
  const name = p.artifact ?? p.path;
  const body = p.sources === undefined
    ? [el("p", { class: "prov__empty" }, "No declaration on record: published before Sluse asked agents for their sources.")]
    : p.sources.length === 0
      ? [el("p", { class: "prov__label" }, "Sources the agent declared: none"), el("p", { class: "prov__empty" }, "The agent declared no sources for this file.")]
      : [el("p", { class: "prov__label" }, `Sources the agent declared: ${p.sources.length}`), el("ul", { class: "lineage" }, ...p.sources.map(source))];
  return el("article", { class: "prov", "data-outcome": "admitted" },
    el("div", { class: "prov__tree" },
      el("header", { class: "prov__head" }, el("span", { class: "prov__node" }, icon("artifact")), el("h4", { class: "prov__name" }, name),
        pill("published", "Published"),
        p.reason?.startsWith("rendered by") ? el("p", { class: "prov__where" }, "Rendered by Sluse from the agent's Markdown.") : null),
      ...body),
    el("dl", { class: "facts prov__facts" },
      el("div", {}, el("dt", {}, "Published"), el("dd", {}, when(p.at))),
      el("div", {}, el("dt", {}, "Size"), el("dd", {}, size(p.bytes))),
      p.hash ? el("div", {}, el("dt", {}, "Hash"), el("dd", {}, chip(p.hash, "Copy the full hash", true))) : null));
}

const WHY: Record<string, string> = {
  SOURCE_NOT_ADMITTED: "The agent declared a source this box never let in. A declaration can only name files Sluse let in.",
  HASH_MISMATCH: "The file changed while it was being published, so what arrived did not match what the agent sent. Ask the agent to publish it again.",
};

function refused(p: Provenance): HTMLElement {
  const code = p.reason ?? "";
  return el("article", { class: "prov", "data-outcome": p.outcome },
    el("div", { class: "prov__tree" },
      el("header", { class: "prov__head" }, el("span", { class: "prov__node" }, icon("artifact")),
        el("h4", { class: "prov__name" }, p.artifact ?? p.path.replace(/^artifacts\//, ""), " ", el("small", {}, "(attempted)")),
        pill(p.outcome === "refused" ? "refused" : "error", p.outcome === "refused" ? "Refused" : "Error")),
      el("p", { class: "prov__empty" }, "Nothing was published, so nothing reached Sluse Artifacts.")),
    el("p", { class: "prov__reason" }, icon("refused"),
      el("span", {}, WHY[code] ?? "Sluse did not publish it. Ask the agent to try again. If it happens again, send the details to your IT department.")),
    el("dl", { class: "facts prov__facts" }, el("div", {}, el("dt", {}, "Attempted"), el("dd", {}, when(p.at)))),
    details(`publish ${p.outcome}: ${code || "no code"}\nrequested: ${p.path}\nsession ${p.sessionId}, ${p.at}`));
}

/** One publish: one folder in Sluse Artifacts, one group of cards. */
function publish(folder: string, ps: Provenance[]): HTMLElement {
  const first = ps[ps.length - 1]!;
  return el("section", { class: "dlv" },
    el("div", { class: "dlv__head" },
      el("h3", { class: "dlv__title" }, icon("folder"), chip(folder, "Copy the folder name")),
      el("span", { class: "t-small t-muted" }, `${ps.length} file${ps.length === 1 ? "" : "s"}, published at ${hhmm(first.at)}`),
      el("span", { class: "spacer" }),
      first.publishId ? el("span", { class: "t-small t-muted" }, "Publish id") : null,
      first.publishId ? chip(first.publishId, "Copy the publish id") : null,
      el("p", { class: "dlv__sub" }, "In Sluse Artifacts on your computer. Open it with ", el("b", {}, "Sluse Artifacts"), " in the bar above the box.")),
    el("div", { class: "dlv__cards" }, ...ps.map(card)));
}

/** A session's publishes, refused ones first in their own group. */
function publishes(ps: Provenance[]): HTMLElement[] {
  const out: HTMLElement[] = [];
  const bad = ps.filter((p) => p.outcome !== "admitted");
  if (bad.length) {
    out.push(el("section", { class: "dlv" },
      el("div", { class: "dlv__head" }, el("h3", { class: "dlv__title t-h3" }, icon("refused"), "Not published"),
        el("p", { class: "dlv__sub" }, "Sluse refused these. Nothing reached Sluse Artifacts. Ask the agent to try again; it was told why.")),
      el("div", { class: "dlv__cards" }, ...bad.map(refused))));
  }
  const groups = new Map<string, Provenance[]>();
  for (const p of ps.filter((p) => p.outcome === "admitted")) {
    const f = folderOf(p.path, p.artifact) ?? p.publishId ?? p.at;
    groups.set(f, [...(groups.get(f) ?? []), p]);
  }
  for (const [f, g] of groups) out.push(publish(f, g));
  return out;
}

const weekday = (iso: string): string => new Date(iso).toLocaleDateString("en-GB", { weekday: "long" });

export function renderArtifacts(target: Element, d: Data): void {
  fill(document.getElementById("states")!,
    el("p", {}, "Each source the agent declared is shown with what became of it in the box."),
    legend(Object.values(STATE)));
  const sessions = new Map<string, Provenance[]>();
  for (const p of d.provenance) sessions.set(p.sessionId, [...(sessions.get(p.sessionId) ?? []), p]);
  const mine = sessions.get(d.state.session) ?? [];
  sessions.delete(d.state.session);
  const start = sessionStart(d);
  const head = el("header", { class: "pagehead" },
    el("div", { class: "pagehead__text" }, el("h1", { class: "t-h2" }, "Your artifacts"),
      el("p", {}, "What AI agents published from this box, this session first, then earlier sessions. One group for each publish, as its folder in Sluse Artifacts. Each file lists the sources the agent declared for it. Sluse checked that each declared source was let into this box; it does not know how the agent used them, or whether it used others.")),
    el("div", { class: "pagehead__actions" }, el("button", { class: "btn", type: "button", "data-states": "" }, icon("info"), "What the states mean")));
  if (!d.provenance.length) {
    fill(target, head, el("div", { class: "empty" }, el("span", { class: "empty__icon" }, icon("artifact")),
      el("h2", { class: "empty__title" }, "Nothing published from this box yet"),
      el("p", { class: "empty__text" }, "When an AI agent publishes a result, it appears here with the sources the agent declared for it, and lands in Sluse Artifacts on your computer. Every session of this box is listed here, this one first.")));
    return;
  }
  const sessHead = (title: string, span: string, id: string, h: "h2" | "h3"): HTMLElement =>
    el("header", { class: "sess__head" }, el(h, { class: "t-h3" }, title), el("span", { class: "sess__when" }, span),
      el("span", { class: "sess__id" }, "Session ", chip(id, "Copy the session id")));
  const thisOne = el("section", { class: "sess" },
    sessHead("This session", start ? `Since the box opened at ${hhmm(start)}, ${day(start)}` : "Since the box opened", d.state.session, "h2"),
    ...(mine.length ? [el("div", { class: "stack", style: "--stack-gap: var(--space-8)" }, ...publishes(mine))]
      : [el("p", { class: "sess__none" }, "Nothing published yet in this session.")]));
  const earlier = [...sessions].map(([id, ps]) => {
    const first = ps[ps.length - 1]!.at, lastAt = ps[0]!.at;
    const span = hhmm(first) === hhmm(lastAt) ? `${weekday(first)}, published at ${hhmm(first)}` : `${weekday(first)}, published from ${hhmm(first)} to ${hhmm(lastAt)}`;
    return el("section", { class: "sess" }, sessHead(day(first), span, id, "h3"), ...publishes(ps));
  });
  fill(target, head, el("div", { class: "stack", style: "--stack-gap: var(--space-12)" }, thisOne,
    earlier.length ? el("section", { class: "sess-earlier" },
      el("div", { class: "sess-earlier__head" }, el("h2", { class: "t-h3" }, "Earlier sessions"),
        el("p", {}, "Published from this box before it was last opened, newest first. Each folder is still in Sluse Artifacts on your computer.")),
      ...earlier) : null));
}
