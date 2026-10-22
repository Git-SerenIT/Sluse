// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

// A few functions instead of a framework.
//
// The console renders a handful of lists that change when a person clicks
// something. `document.createElement` does that, and a framework in here would
// be a build step, a dependency tree and a second mental model for the sake of
// re-rendering a table. The look is the foundation's components (D-062).

type Child = Node | string | null | undefined | false;

/** An element with attributes and children. `on…` attributes are listeners. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | number | EventListener | undefined> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === "function") node.addEventListener(k.replace(/^on/, ""), v);
    else if (v === false || v == null) continue;
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c == null || c === false) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

/** Replace an element's contents. */
export function fill(target: Element, ...children: Child[]): void {
  target.replaceChildren(
    ...children.filter((c): c is Node | string => c != null && c !== false)
      .map((c) => (typeof c === "string" ? document.createTextNode(c) : c)),
  );
}

/** An icon from look/icons.js, which hydrates it once it is in the page. */
export const icon = (name: string): HTMLElement => el("i", { "data-icon": name });

export const pill = (status: string, text: string): HTMLElement => el("span", { class: "pill", "data-status": status }, text);

/**
 * A value a person copies exactly: a path, an id, a hash. Long ones show
 * their first twelve characters and copy whole; the full value is the title.
 */
export function chip(value: string, label: string, short = false): HTMLElement {
  const copy = el("button", { class: "chip-mono__copy", type: "button", "aria-label": label }, icon("copy"));
  copy.addEventListener("click", () => {
    void navigator.clipboard?.writeText(value).then(() => {
      copy.setAttribute("data-copied", "");
      setTimeout(() => copy.removeAttribute("data-copied"), 1500);
    });
  });
  return el("span", { class: short ? "chip-mono chip-mono--truncate" : "chip-mono", title: short ? value : undefined },
    el("code", {}, short ? value.slice(0, 12) : value), copy);
}

/** Details for IT, collapsed, with Copy details: the raw text, never the headline. */
export function details(text: string): HTMLElement {
  const copy = el("button", { class: "btn btn--sm btn--quiet", type: "button" }, icon("copy"), "Copy details");
  copy.addEventListener("click", () => void navigator.clipboard?.writeText(text));
  return el("details", { class: "disclosure" }, el("summary", {}, "Details"),
    el("div", { class: "disclosure__body" },
      el("div", { class: "techdetails" },
        el("div", { class: "techdetails__bar" }, el("span", { class: "t-label" }, "For your IT department"), copy),
        el("pre", {}, text))));
}

const two = (n: number): string => String(n).padStart(2, "0");

/**
 * A timestamp as local time, `14:32:07` with colons whatever the locale (the
 * Danish default printed `14.32.07`), and the date only when it is not today.
 * The full ISO value on hover.
 */
export function when(iso: string): HTMLElement {
  const d = new Date(iso);
  const time = `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
  const today = d.toDateString() === new Date().toDateString();
  const text = today ? time : `${d.getDate()} ${d.toLocaleString("en", { month: "short" })} ${time}`;
  return el("time", { datetime: iso, title: iso }, text);
}

/** `14:32`. */
export const hhmm = (iso: string): string => {
  const d = new Date(iso);
  return `${two(d.getHours())}:${two(d.getMinutes())}`;
};

/** `19 October 2026`. */
export const day = (iso: string): string =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/** How long ago, in words: "12 seconds ago", "3 minutes ago". */
export function ago(iso: string): string {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${plural(s, "second")} ago`;
  if (s < 3600) return `${plural(Math.round(s / 60), "minute")} ago`;
  return `${plural(Math.round(s / 3600), "hour")} ago`;
}

/** A window kept in seconds, said in natural words (Q52): "60 seconds", "10 minutes". */
export function words(seconds: number): string {
  if (seconds >= 3600 && seconds % 3600 === 0) return plural(seconds / 3600, "hour");
  if (seconds >= 120 && seconds % 60 === 0) return plural(seconds / 60, "minute");
  return plural(seconds, "second");
}

/** Bytes, in the units a person reads. */
export function size(bytes: number | undefined): string {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

/** Open one of the page's dialogs; resolves with the button's value. */
export function ask(id: string): Promise<string> {
  const d = document.getElementById(id) as HTMLDialogElement;
  d.returnValue = "";
  d.showModal();
  return new Promise((done) => d.addEventListener("close", () => done(d.returnValue), { once: true }));
}

/** A list joined in words: "a, b and c". */
export const list = (xs: string[]): string =>
  xs.length > 1 ? `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}` : xs[0] ?? "";
