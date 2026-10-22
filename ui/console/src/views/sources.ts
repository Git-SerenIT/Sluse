// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// Sources: what the agents in this box can see, folder by folder. Opening a
// folder asks Sluse (`/v1/list`), and that is recorded on the computer, so it
// is always a click: "List again" re-lists on purpose, and a timed read never
// moves the person's place (D-032). Nothing here lets a file in; there is no
// Open button. In a box every listed row is in scope (D-033); on a
// development device the out-of-scope ones are listed too, marked.

import { ApiError, api, type ListResponse } from "../api.js";
import { type Data, kindIcon, kindWords } from "../data.js";
import { details, el, fill, icon, pill, size, when } from "../dom.js";

/** Where the person is, and what the last listing said. */
let at = "";
let listing: ListResponse | undefined;
let listedAt: string | undefined;
let failure: { code: string; raw: string } | undefined;
let opening: string | undefined;

async function open(path: string, redraw: () => void): Promise<void> {
  at = path;
  if (!path) { listing = undefined; failure = undefined; redraw(); return; }
  opening = path;
  redraw();
  try {
    listing = await api.list(path);
    failure = undefined;
  } catch (e) {
    listing = undefined;
    failure = e instanceof ApiError ? { code: e.failure.code, raw: JSON.stringify(e.failure) } : { code: "INTERNAL", raw: String(e) };
  }
  listedAt = new Date().toISOString();
  opening = undefined;
  redraw();
}

function what(s: Data["view"]["sources"][number]): string {
  if (s.kind === "onedrive") return "Your Sluse folder";
  if (!s.scopes.length) return "The whole folder";
  return `${s.scopes.length} folder${s.scopes.length === 1 ? "" : "s"}: ${s.scopes.join(", ")}`;
}

function problem(title: string, text: string, raw?: string, action?: Node): HTMLElement {
  return el("div", { class: "empty", role: "status" }, el("span", { class: "empty__icon" }, icon("folder")),
    el("h2", { class: "empty__title" }, title), el("p", { class: "empty__text" }, text),
    action ? el("div", { class: "empty__action" }, action) : null, raw ? details(raw) : null);
}

export function renderSources(target: Element, d: Data): void {
  const redraw = (): void => renderSources(target, d);
  const source = at.split("/")[0] ?? "";
  const crumbs = at ? at.split("/") : [];
  const head = [
    el("header", { class: "pagehead" }, el("div", { class: "pagehead__text" }, el("h1", { class: "t-h2" }, "Sources"),
      el("p", {}, "What the AI agents in this box can see, folder by folder. Opening a folder here asks Sluse, and that is recorded on your computer, as it is when an agent asks."))),
    el("p", { class: "note", "data-kind": "info" }, el("span", {}, "There is no Open button here. A file from these sources reaches the box only when an AI agent asks Sluse for it.")),
    d.state.local ? el("div", { class: "banner", "data-kind": "warning" }, el("div", { class: "banner__body" },
      el("p", { class: "banner__title" }, "Development device"),
      el("p", { class: "banner__text" }, "On this device Sluse also lists what the agents cannot see, marked Out of scope. In a box, those entries are not listed at all.")), el("span", {})) : null,
  ];
  const bar = el("div", { class: "cluster" },
    el("ol", { class: "crumbs", "aria-label": "Where you are" },
      el("li", {}, el("button", { type: "button", "aria-current": at ? undefined : "location", onclick: () => void open("", redraw) }, "sources")),
      ...crumbs.map((c, i) => el("li", {}, el("button", { type: "button", class: "mono", "aria-current": i === crumbs.length - 1 ? "location" : undefined,
        onclick: () => void open(crumbs.slice(0, i + 1).join("/"), redraw) }, c)))),
    el("span", { class: "spacer" }),
    opening ? el("span", { class: "t-small", role: "status" }, `Opening ${opening.split("/").at(-1)}`)
      : listedAt && at ? el("span", { class: "t-small t-muted" }, "Listed at ", when(listedAt)) : null,
    at ? el("button", { class: "btn btn--sm", type: "button", onclick: () => void open(at, redraw) }, icon("refresh"), "List again") : null);

  let body: HTMLElement;
  if (!at) {
    body = el("div", { class: "table-wrap" }, el("table", { class: "table table--fixed" },
      el("thead", {}, el("tr", {}, ...["Source", "Kind", "What the agents can see", "Sensitivity"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...d.view.sources.map((s) => el("tr", {},
        el("td", {}, el("button", { class: "linkrow", type: "button", onclick: () => void open(s.name, redraw) }, icon(kindIcon(s.kind)), el("span", { class: "mono" }, s.name))),
        el("td", {}, kindWords(s).split(",")[0] ?? ""), el("td", {}, what(s)),
        el("td", {}, s.sensitivityName.charAt(0).toUpperCase() + s.sensitivityName.slice(1)))))));
  } else if (failure) {
    const back = el("button", { class: "btn", type: "button", onclick: () => void open(source, redraw) }, `Back to ${source}`);
    body = ({
      SOURCE_UNAVAILABLE: () => problem("The source did not answer", `${source} did not answer Sluse. Try again in a moment with List again. If it keeps happening, send the details to your IT department.`, failure!.raw),
      SIGN_IN_REQUIRED: () => problem("Sluse needs you to sign in again", `${source} cannot be listed until you do. To sign in, close the box from the bar above and open Sluse again.`, failure!.raw),
      BROKER_UNREACHABLE: () => problem("Sluse on your computer is not answering", "Nothing can be listed until it answers. This page asks again by itself; use List again when the bar above says it is back.", failure!.raw),
      NOT_FOUND: () => at === source && d.view.sources.find((s) => s.name === source)?.kind === "onedrive"
        ? problem("Your Sluse folder in OneDrive is not there yet", "It appears here once OneDrive has synced it. If you have not made it yet, the Sluse window on your computer offers to.")
        : problem("This folder is no longer there", "It was moved or deleted at the source after the list above it was made.", failure!.raw, at === source ? undefined : back),
    }[failure.code] ?? (() => problem("Sluse did not list this folder", "The agents in this box cannot open it through Sluse. The reason is in this computer's Event Log, which your IT department can read; send them the details if you need to know.", failure!.raw)))();
  } else if (!listing) {
    body = el("div", { class: "progress listing__bar", "data-indeterminate": "" }, el("div", { class: "progress__fill" }));
  } else if (!listing.entries.some((e) => e.inScope || d.state.local)) {
    body = problem("Nothing to see in this folder", `Nothing in ${at} is visible to the AI agents in this box.`);
  } else {
    const entries = listing.entries.filter((e) => e.inScope || d.state.local)
      .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === "directory" ? -1 : 1));
    body = el("div", { class: "table-wrap" }, el("table", { class: "table table--fixed" },
      el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Name"), el("th", { scope: "col" }, "Modified"), el("th", { scope: "col", class: "size" }, "Size"),
        d.state.local ? el("th", { scope: "col" }, "Scope") : null)),
      el("tbody", {}, ...entries.map((e) => el("tr", { "data-out": !e.inScope },
        el("td", {}, e.kind === "directory" && e.inScope
          ? el("button", { class: "linkrow", type: "button", onclick: () => void open(`${at}/${e.name}`, redraw) }, icon("folder"), el("span", { class: "mono" }, e.name))
          : el("span", { class: "name-cell" }, icon(e.kind === "directory" ? "folder" : "file"), el("span", { class: "mono" }, e.name))),
        el("td", { class: "when" }, e.modified ? when(e.modified) : ""),
        el("td", { class: "size" }, size(e.size)),
        d.state.local ? el("td", {}, e.inScope ? pill("in-scope", "In scope") : pill("out-of-scope", "Out of scope")) : null)))));
  }
  fill(target, ...head, el("section", { class: "listing stack", style: "--stack-gap: var(--space-3)", "aria-label": "Listing" }, bar,
    opening ? el("div", { class: "progress listing__bar", "data-indeterminate": "" }, el("div", { class: "progress__fill" })) : null, body));
}
