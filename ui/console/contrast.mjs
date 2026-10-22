// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Assert the console's colours are readable. `npm run contrast`.
//
// This exists because the first palette shipped with secondary text at 3.6:1 on
// the light background and 4.3:1 on the dark one, and an out-of-scope entry at
// **1.88:1** — a row a person was meant to read, rendered invisible by an
// `opacity` that looked reasonable in the stylesheet. Contrast is arithmetic;
// it should not be left to whether someone happened to look at the screen.
//
// Values are read from look/tokens.css, the one file the shell, Sluse Admin
// and the console share (D-062), in both themes, so the check cannot drift
// from what ships. The tints are color-mix() there and mixed the same way here.

import { readFileSync } from "node:fs";

const css = readFileSync(new URL("./look/tokens.css", import.meta.url), "utf8");
const style = readFileSync(new URL("./style.css", import.meta.url), "utf8");

/** Every `--name: #hex` in the first block `selector {` opens. */
const block = (selector) => {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`tokens.css has no ${selector} block`);
  const body = css.slice(start, css.indexOf("}", start));
  return Object.fromEntries([...body.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})/g)].map((m) => [m[1], m[2]]));
};
const themes = { Light: block('[data-theme="light"]'), Dark: block('[data-theme="dark"]') };

/** color-mix(in srgb, a p%, b): what tokens.css computes for a tint. */
const mix = (a, p, b) => "#" + [1, 3, 5].map((i) => {
  const v = Math.round(parseInt(a.slice(i, i + 2), 16) * p + parseInt(b.slice(i, i + 2), 16) * (1 - p));
  return v.toString(16).padStart(2, "0");
}).join("");
for (const t of Object.values(themes)) {
  t["tint-hover"] = mix(t.ink, 0.05, t["surface-2"]);
  t["tint-wash"] = mix(t.ink, 0.04, t.surface);
  t["tint-press"] = mix(t.ink, 0.10, t["surface-2"]);
  t["tint-track"] = mix(t.ink, 0.16, t.surface);
  t["ink-hover"] = mix(t.ink, 0.86, t.surface); // a primary button, hovered
}

const luminance = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};

const ratio = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

// [what it is, foreground, background, minimum]
// 4.5 is AA for body text. 3.0 is AA for non-text UI: a control's edge, the
// gate's fill against its track. --line is a divider only, never measured as
// an edge (README, Foundation).
const pairs = [
  ["text on the page", "ink", "surface", 4.5],
  ["text on a panel", "ink", "surface-2", 4.5],
  ["secondary text on the page", "ink-muted", "surface", 4.5],
  ["secondary text on a panel", "ink-muted", "surface-2", 4.5],
  ["secondary text on a hovered row", "ink-muted", "tint-hover", 4.5],
  ["text on a pressed row", "ink", "tint-press", 4.5],
  ["text on a hovered button", "ink", "tint-wash", 4.5],
  ["a primary button's label", "surface", "ink", 4.5],
  ["a primary button's label, hovered", "surface", "ink-hover", 4.5],
  ["a control's edge", "ink-muted", "surface", 3.0],
  ["a control's edge on a panel", "ink-muted", "surface-2", 3.0],
  ["the gate's fill on its track", "ink", "tint-track", 3.0],
];

let failed = 0;
console.log(`${"pair".padEnd(40)} ${"ratio".padStart(6)}  need  result`);
for (const [name, t] of Object.entries(themes)) {
  console.log(`\n${name}`);
  for (const [what, fg, bg, min] of pairs) {
    if (!t[fg] || !t[bg]) {
      console.log(`${what.padEnd(40)} ${"—".padStart(6)}        MISSING --${t[fg] ? bg : fg}`);
      failed++;
      continue;
    }
    const r = ratio(t[fg], t[bg]);
    const ok = r >= min;
    if (!ok) failed++;
    console.log(`${what.padEnd(40)} ${r.toFixed(2).padStart(6)}  ${String(min).padStart(4)}  ${ok ? "pass" : "FAIL"}`);
  }
}

// `opacity` on a row of text is how the first palette hid an out-of-scope entry
// at 1.88:1. Greying is done with a colour, which can be measured.
const opacityOnText = /\.entry-out\s*\{[^}]*opacity/.test(style);
if (opacityOnText) {
  console.log("\nFAIL: .entry-out uses opacity. Grey with a colour so it can be measured.");
  failed++;
}

console.log(failed === 0 ? "\nAll pairs readable." : `\n${failed} problem(s).`);
process.exit(failed === 0 ? 0 : 1);
