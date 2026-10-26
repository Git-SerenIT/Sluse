// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// Work: the console's first page (D-034 point 9, Q41, Q72), for the person
// working, not the person auditing. The chamber is its one picture: the
// sources converge on the gate in the lock's wall, where Sluse lets files in
// and counts them per source (Q36), and the box lies past it. Every number
// here is counted from the box's own journal, except the meters, which are
// Sluse's own counts in the alert's window, so meter and alert agree.

import type { AuditRecord } from "../api.js";
import { type Data, folderOf, kindIcon, kindWords, letIn, sessionStart, sourceNames, sourceOf, within } from "../data.js";
import { ago, chip, el, fill, hhmm, icon, list, size, words } from "../dom.js";

export function renderWork(target: Element, d: Data): void {
  const vol = d.view.volume;
  const win = words(vol.windowSeconds);
  const ins = letIn(d);
  const files = new Map<string, AuditRecord>();
  for (const r of ins) files.set(r.hash ?? r.pathRequested, r);
  const read = ins.filter((r) => r.op === "read").length;
  const fetched = ins.filter((r) => r.op === "fetch").length;
  const pubs = d.journal.filter((r) => r.op === "publish" && r.outcome === "admitted");
  const folders = new Set(pubs.map((r) => folderOf(r.pathRequested, r.artifact)));
  const from = [...new Set(ins.map((r) => sourceOf(r.pathRequested)))];
  const last = ins.at(-1);
  const refused = d.journal.filter((r) => r.op === "publish" && (r.outcome === "refused" || r.outcome === "error"));
  const earlier = d.inventory.filter((c) => !ins.some((r) => r.admissionId && r.admissionId === c.admissionId)).length;
  const start = sessionStart(d);
  const nothing = ins.length === 0 && pubs.length === 0;
  const limit = `${vol.admissions} files${vol.bytes ? `, or ${size(vol.bytes)},` : ""} from one source in ${win}`;

  const banners = el("div", { class: "cx-banners" },
    ...d.alerts.filter((a) => !a.closedAt).map((a) =>
      el("div", { class: "banner", "data-kind": "info", role: "status" },
        el("div", { class: "banner__body" },
          el("p", { class: "banner__title" }, `${a.count} files from ${a.source} in ${words(a.windowSeconds)}`),
          el("p", { class: "banner__text" }, `That is past your IT department's volume alert of ${limit}. Sluse does not stop the work. It is recorded in this computer's Event Log, which your IT department can read. Since ${hhmm(a.openedAt)}.`)),
        el("span", {}))),
    refused.length ? el("p", { class: "note", "data-kind": "warning" },
      el("span", {}, `${refused.length === 1 ? "One publish was" : `${refused.length} publishes were`} not published, the last at ${hhmm(refused.at(-1)!.ts)}. Nothing reached Sluse Artifacts. `,
        el("a", { class: "btn--link", href: "#artifacts" }, "See it in Your artifacts"))) : null);

  const howto = nothing && earlier === 0 ? el("section", { class: "stack", style: "--stack-gap: var(--space-3)" },
    el("h2", { class: "t-h3" }, "How work gets in and out"),
    el("ol", { class: "howto" },
      el("li", {}, el("b", {}, "Open an AI agent"), el("span", {}, "Claude, Claude Code, Codex or Mistral Vibe, with Open in the bar at the top of this page.")),
      el("li", {}, el("b", {}, "Ask it for files"), el("span", {}, "It asks Sluse. Sluse lets in what you may open yourself, from the sources your IT department chose, and records each one.")),
      el("li", {}, el("b", {}, "Find the results"), el("span", {}, "What the agent publishes lands in Sluse Artifacts on your computer, with the sources it declared.")))) : null;

  // The chamber.
  const serving = d.state.gate.status === "serving";
  const counts = d.state.gate.status === "serving" ? d.state.gate.volume.filter((c) => c.files > 0) : [];
  const fromHere = (name: string): number => new Set(ins.filter((r) => sourceOf(r.pathRequested) === name).map((r) => r.hash ?? r.pathRequested)).size;
  const sources = el("ul", { class: "chamber__sources" }, ...d.view.sources.map((s) => {
    const n = fromHere(s.name);
    return el("li", { class: "chamber__src", "data-active": n > 0 }, icon(kindIcon(s.kind)), el("b", {}, s.name), el("small", {}, kindWords(s)),
      el("span", { class: "chamber__count" }, `${n} let in`));
  }));
  const meters = counts.map((c) => {
    const over = c.files >= vol.admissions;
    return el("div", { class: "meter", role: "meter", "aria-label": `${c.source}: files let in during the last ${win}`, "aria-valuemin": 0, "aria-valuemax": vol.admissions, "aria-valuenow": c.files, "data-over": over },
      el("div", { class: "meter__label" }, el("span", {}, c.source), el("span", {}, el("strong", {}, String(c.files)), over ? ` of ${vol.admissions}: past the volume alert` : ` of ${vol.admissions}`)),
      el("div", { class: "meter__track" }, el("div", { class: "meter__fill", style: `--value: ${Math.min(100, (100 * c.files) / vol.admissions)}%` })));
  });
  const window_ = el("div", { class: "chamber__window" },
    el("span", { class: "t-small t-muted" }, `Sluse's count for each source, in the last ${win}`),
    ...meters,
    el("p", { class: "chamber__foot" }, serving
      ? `${counts.length ? "The other sources" : "The sources"} let nothing in during the last ${win}.`
      : "Not known: these counts come from Sluse on your computer, which is not answering."));
  const lock = el("div", { class: "chamber__lock" },
    el("span", { class: "chamber__gate", title: "Sluse lets files in here" }, icon("admit")),
    el("div", { class: "chamber__col" },
      el("span", { class: "t-label" }, "Sluse"),
      el("p", { class: "chamber__lede" }, el("strong", {}, "Lets in what you may open"),
        "A file from your sources comes in only when an AI agent asks Sluse for it, you may open it yourself, and it is in a folder your IT department chose. Each one is recorded."),
      window_,
      el("p", { class: "chamber__foot" }, `Past ${limit}, Sluse raises your IT department's volume alert. It is recorded in this computer's Event Log, which your IT department can read. Sluse does not stop the work.`)));
  const box = el("div", { class: "chamber__col chamber__box" },
    el("span", { class: "t-label" }, "Your box"),
    el("div", { class: "stat" },
      el("span", {}, el("span", { class: "stat__num" }, String(files.size)), " ", el("span", { class: "stat__unit" }, `file${files.size === 1 ? "" : "s"} let in`)),
      el("span", { class: "stat__label" }, from.length ? `from ${list(from)}` : start ? `Nothing yet since the box opened at ${hhmm(start)}` : "Nothing yet in this session")),
    ins.length ? el("ul", { class: "chamber__facts" },
      el("li", {}, icon("eye"), el("span", {}, el("b", {}, String(read)), " read: their text was shown to the agent. Sluse kept no copy of them.")),
      el("li", {}, icon("download"), el("span", {}, el("b", {}, String(fetched)), " fetched as copies into the box")),
      el("li", {}, icon("artifact"), el("span", {}, ...(pubs.length
        ? [el("b", {}, String(pubs.length)), ` file${pubs.length === 1 ? "" : "s"} published, in ${folders.size} folder${folders.size === 1 ? "" : "s"} in Sluse Artifacts`]
        : ["Nothing published yet"])))) : null,
    last ? el("p", { class: "t-small", style: "margin:0" }, "Last let in: ", el("span", { class: "mono" }, within(last.pathRequested)), ` from ${sourceOf(last.pathRequested)}, ${ago(last.ts)}.`) : null,
    nothing && earlier ? el("ul", { class: "chamber__facts" },
      el("li", {}, icon("download"), el("span", {}, el("b", {}, String(earlier)), ` cop${earlier === 1 ? "y" : "ies"} from earlier sessions ${earlier === 1 ? "is" : "are"} still in the box. `, el("a", { class: "btn--link", href: "#copies" }, "See them")))) : null);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "chamber__streams");
  svg.setAttribute("aria-hidden", "true");
  const chamber = el("section", { class: "chamber", "aria-label": "How files reach your box" }, svg,
    el("div", { class: "chamber__col chamber__srccol" }, el("span", { class: "t-label" }, "Your sources"), sources), lock, box);

  // Let in recently, and this session's artifacts.
  const recent = el("section", { class: "card" }, el("div", { class: "card__head" }, el("h2", { class: "card__title" }, "Let in recently")),
    ins.length ? el("ul", { class: "ov-list" }, ...ins.slice(-5).reverse().map((r) =>
      el("li", { class: "ov-item" }, icon(r.op === "read" ? "eye" : "download"),
        el("span", { class: "ov-item__name" }, within(r.pathRequested)),
        el("span", { class: "ov-item__meta" }, `${sourceOf(r.pathRequested)}, ${r.op === "read" ? "read" : "fetched as a copy"}${r.reason === "OFFICE_ENCRYPTED" ? "; arrived encrypted" : r.reason === "NOT_UTF8_TEXT" ? "; its text could not be shown" : ""}`),
        el("span", { class: "ov-item__when" }, ago(r.ts))))) : null,
    ins.length ? el("div", { class: "card__foot" }, el("a", { class: "btn btn--sm", href: "#record" }, `See all ${ins.length} in Record`)) : null,
    ins.length ? null : el("div", { class: "empty" }, el("span", { class: "empty__icon" }, icon("admit")),
      el("h3", { class: "empty__title" }, "Nothing let in yet"),
      el("p", { class: "empty__text" }, `Ask an AI agent to read or fetch files from ${list(sourceNames(d))}. Sluse lets in only what you may open yourself, from the sources your IT department chose.`),
      el("div", { class: "empty__action" }, el("button", { class: "btn btn--primary", type: "button", "data-app": "claude-desktop" }, "Open Claude"))));

  const byFolder = new Map<string, AuditRecord[]>();
  for (const r of pubs) {
    const f = folderOf(r.pathRequested, r.artifact) ?? r.publishId ?? r.ts;
    byFolder.set(f, [...(byFolder.get(f) ?? []), r]);
  }
  const earlierPubs = d.provenance.some((x) => x.sessionId !== d.state.session && x.outcome === "admitted");
  const published = el("section", { class: "card" }, el("div", { class: "card__head" }, el("h2", { class: "card__title" }, "Your artifacts")),
    byFolder.size ? el("div", {},
      ...[...byFolder].reverse().map(([folder, rs]) => el("div", { class: "delivery" },
        el("div", { class: "delivery__head" }, icon("folder"), chip(folder, "Copy the folder name"), el("span", { class: "delivery__when" }, ago(rs[0]!.ts))),
        el("ul", { class: "delivery__files" }, ...rs.map((r) => el("li", {}, r.artifact ?? within(r.pathRequested)))),
        el("div", { class: "delivery__foot" }, el("a", { class: "btn--link", href: "#artifacts" }, "Show the sources declared")))),
      el("p", { class: "note", "data-kind": "info", style: "margin-top: var(--space-3)" },
        el("span", {}, "Each folder is in Sluse Artifacts on your computer. Open it with ", el("b", {}, "Sluse Artifacts"), " in the bar above the box."))) : null,
    byFolder.size || earlierPubs ? el("div", { class: "card__foot" }, el("a", { class: "btn btn--sm", href: "#artifacts" }, "See this and earlier sessions in Your artifacts")) : null,
    byFolder.size ? null : el("div", { class: "empty" }, el("span", { class: "empty__icon" }, icon("artifact")),
      el("h3", { class: "empty__title" }, "Nothing published yet"),
      el("p", { class: "empty__text" }, earlierPubs
        ? "Nothing published in this session. Earlier sessions' publishes are listed in Your artifacts, by session, and are in Sluse Artifacts on your computer."
        : "When an AI agent publishes a result, it appears here and lands in Sluse Artifacts on your computer, with the sources the agent declared.")));

  fill(target,
    el("header", { class: "pagehead" }, el("div", { class: "pagehead__text" },
      el("h1", { class: "t-h2" }, "Work"),
      el("p", {}, "What Sluse let into your box and what AI agents published from it, in this session."))),
    banners, howto, chamber, el("div", { class: "ov-grid" }, recent, published));
  requestAnimationFrame(() => streams(chamber, svg));
}

/** The streams from each source to the gate; heavier where files came in. */
function streams(ch: HTMLElement, svg: SVGSVGElement): void {
  if (!ch.isConnected || !ch.offsetWidth) return;
  const r = ch.getBoundingClientRect();
  const lock = ch.querySelector(".chamber__lock")!.getBoundingClientRect();
  const gy = parseFloat(getComputedStyle(ch).getPropertyValue("--gate-y")) || 76;
  const gx = lock.left - r.left;
  let out = "";
  for (const s of ch.querySelectorAll<HTMLElement>(".chamber__src")) {
    const b = s.getBoundingClientRect();
    const x1 = b.right - r.left, y1 = b.top + b.height / 2 - r.top, dx = (gx - x1) / 2;
    out += `<path d="M${x1} ${y1} C${x1 + dx} ${y1} ${gx - dx} ${gy} ${gx - 18} ${gy}"${s.hasAttribute("data-active") ? " data-active" : ""}/>`;
  }
  svg.setAttribute("viewBox", `0 0 ${ch.offsetWidth} ${ch.offsetHeight}`);
  svg.innerHTML = out;
}
addEventListener("resize", () => {
  const ch = document.querySelector<HTMLElement>(".chamber");
  const svg = ch?.querySelector<SVGSVGElement>(".chamber__streams");
  if (ch && svg) streams(ch, svg);
});
