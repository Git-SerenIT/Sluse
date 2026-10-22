// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
/* Sluse icon set: the product's copy of the mock-ups' foundation
   (docs/design/mockups/foundation/icons.js, D-062). The logo cuts are in
   logo/ beside it, copied from docs/design/sluse-logo-kit/svg/.

   One ink, line icons on a 24px grid, 1.75 stroke, round ends: drawn to sit
   beside the mark's outlined breakers without imitating the mark. Fill is
   used only where a shape needs a solid part (a dot, the half of "stale").

   Use
     <i data-icon="admitted"></i>            replaced by an inline <svg>
     <i data-icon="copy" data-size="16"></i> 16px instead of the 20px default
     SluseIcons.svg("refused")               the markup as a string, for JS
   Every icon is decorative (aria-hidden): the word next to it carries the
   meaning. An icon-only button needs its own aria-label.

   Works from file:// because the sprite is injected inline: an external
   icons.svg#id reference is blocked on file:// by Chromium, and one file
   is one fewer to ship. */
(function () {
  "use strict";

  // Paths are drawn with stroke="currentColor" fill="none" from the .icon
  // class. Solid parts carry fill="currentColor" stroke="none" themselves.
  var DOT = function (x, y) { return '<circle cx="' + x + '" cy="' + y + '" r="1.15" fill="currentColor" stroke="none"/>'; };
  var RING = '<circle cx="12" cy="12" r="9"/>';

  var ICONS = {
    /* ---- Status: the shape is the meaning, the word says it ----------- */
    // Settled, as asked: a ring with a tick.
    "admitted": RING + '<path d="M8 12.4l2.7 2.7L16.2 9.6"/>',
    // Refused: the ring crossed. "No entry", not a red X.
    "refused": RING + '<path d="M5.7 5.7l12.6 12.6"/>',
    // Released: out of the box, upward.
    "released": '<path d="M4 13.5V19a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5.5"/><path d="M12 15V4"/><path d="M7.5 8.5L12 4l4.5 4.5"/>',
    // Admission: an arrow passing a gap in a wall. The sluse, as a verb.
    "admit": '<path d="M12 3v5.5M12 15.5V21"/><path d="M3 12h16.5"/><path d="M15.5 8l4 4-4 4"/>',
    "pending": RING + '<path d="M12 7v5l3.2 2"/>',
    "current": RING + '<path d="M8 10h8M8 14h8"/>',
    // Stale: half of it has moved on.
    "stale": RING + '<path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/>',
    "orphaned": '<path d="M10.2 13.8l-1.9 1.9a3.4 3.4 0 0 1-4.8-4.8l1.9-1.9"/><path d="M13.8 10.2l1.9-1.9a3.4 3.4 0 0 1 4.8 4.8l-1.9 1.9"/><path d="M8.5 3.5v2.2M3.5 8.5h2.2M15.5 20.5v-2.2M20.5 15.5h-2.2"/>',
    "missing": '<circle cx="12" cy="12" r="9" stroke-dasharray="2.6 3.05"/>',
    "unknown": RING + '<path d="M9.6 9.6a2.5 2.5 0 1 1 3.6 2.25c-.75.35-1.2.95-1.2 1.75v.4"/>' + DOT(12, 16.9),
    "not-checked": '<circle cx="12" cy="12" r="9" stroke-dasharray="2.6 3.05"/><path d="M8.5 12h7"/>',
    "info": RING + '<path d="M12 11v5.5"/>' + DOT(12, 7.9),
    // Warning: a triangle. Something to read before going on.
    "warning": '<path d="M12 3.8L21.2 19.5H2.8z"/><path d="M12 10v4.4"/>' + DOT(12, 16.9),
    // Problem: an octagon. Something stopped.
    "problem": '<path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z"/><path d="M12 7.5v5.5"/>' + DOT(12, 16.3),
    "check": '<path d="M5 12.6l4.4 4.4L19 7.4"/>',
    "dash": '<path d="M6 12h12"/>',
    "changed": RING + '<path d="M8 13.5l2.5-3 2.5 2 3-3.5"/>',
    "spinner": '<circle cx="12" cy="12" r="8.5" opacity=".28"/><path d="M12 3.5a8.5 8.5 0 0 1 8.5 8.5"/>',
    // Sealed: a closed envelope. Encrypted content arrived and stays closed:
    // the control working (D-055 point 4), not a fault. Not a lock: the set
    // has none, on purpose.
    "sealed": '<rect x="3" y="5.5" width="18" height="13" rx="1.6"/><path d="M3.6 6.6L12 13l8.4-6.4"/>',

    /* ---- Objects -------------------------------------------------------- */
    "file": '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>',
    "artifact": '<path d="M13 21H6V3h8l4 4v6"/><path d="M14 3v4h4"/><path d="M15 18h6M18 15l3 3-3 3"/>',
    "folder": '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/>',
    "folder-open": '<path d="M3 18.5V6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h7.5A1.5 1.5 0 0 1 20 9v1.5"/><path d="M3 18.5l2.6-7A1.5 1.5 0 0 1 7 10.5h13.2a1 1 0 0 1 .95 1.3L19 18.9a1.5 1.5 0 0 1-1.4 1.1H4.5A1.5 1.5 0 0 1 3 18.5z"/>',
    // Sources by kind
    "library": '<path d="M3.5 4h4v16h-4zM9.5 4h4v16h-4z"/><path d="M15 5.3l3.5-.9 3 14.9-3.5.9z"/>',
    "server": '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/>' + DOT(8, 7.5) + DOT(8, 16.5),
    "cloud": '<path d="M7.2 18.5h10.3a4 4 0 0 0 .55-7.96A6 6 0 0 0 6.6 9.6a4.5 4.5 0 0 0 .6 8.9z"/>',
    "inbox": '<path d="M3 13.5L5.6 5h12.8L21 13.5V19a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M3 13.5h5l1.5 2.5h5l1.5-2.5h5"/>',
    "source": '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v12c0 1.45 3.1 2.6 7 2.6s7-1.15 7-2.6V6"/><path d="M5 12c0 1.45 3.1 2.6 7 2.6s7-1.15 7-2.6"/>',
    // The box, as the user sees it: a screen they work in.
    "box": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8.5 21h7M12 17v4"/>',
    "person": '<circle cx="12" cy="8" r="3.6"/><path d="M5 20.2c.8-3.6 3.6-5.6 7-5.6s6.2 2 7 5.6"/>',
    "group": '<circle cx="9" cy="8.5" r="3.2"/><path d="M3 19.5c.7-3.2 3.1-5 6-5s5.3 1.8 6 5"/><path d="M15.2 5.6a3.2 3.2 0 0 1 0 6.1M17.6 14.8c1.7.6 2.9 2.2 3.4 4.7"/>',
    "journal": '<path d="M6 3h12v18H6z"/><path d="M9 8h6M9 12h6M9 16h3.5"/>',
    "lineage": '<circle cx="6" cy="5.5" r="2"/><circle cx="6" cy="18.5" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7.5v9M8 5.5c5 0 8 1.5 8.2 4.6"/>',
    "hash": '<path d="M9.5 4L7.5 20M16.5 4l-2 16M4.5 9h15.5M4 15h15.5"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9.5l3 2.5-3 2.5M12.5 15h4.5"/>',
    "apps": '<rect x="4" y="4" width="6.5" height="6.5" rx="1.3"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.3"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.3"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.3"/>',
    "globe": RING + '<path d="M3 12h18"/><path d="M12 3c2.4 2.5 3.6 5.5 3.6 9s-1.2 6.5-3.6 9c-2.4-2.5-3.6-5.5-3.6-9S9.6 5.5 12 3z"/>',
    "clipboard": '<rect x="5.5" y="4.5" width="13" height="16.5" rx="1.8"/><path d="M9 3h6v3.2H9z"/>',
    "meter": '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/>',

    /* ---- Actions -------------------------------------------------------- */
    "copy": '<rect x="8.5" y="8.5" width="12" height="12" rx="1.8"/><path d="M15.5 8.5V5.3a1.8 1.8 0 0 0-1.8-1.8H5.3a1.8 1.8 0 0 0-1.8 1.8v8.4a1.8 1.8 0 0 0 1.8 1.8h3.2"/>',
    "close": '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
    "chevron-down": '<path d="M6 9.5l6 6 6-6"/>',
    "chevron-up": '<path d="M6 14.5l6-6 6 6"/>',
    "chevron-right": '<path d="M9.5 6l6 6-6 6"/>',
    "chevron-left": '<path d="M14.5 6l-6 6 6 6"/>',
    "arrow-right": '<path d="M4.5 12h15M13.5 6l6 6-6 6"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "more": DOT(5.5, 12).replace('1.15', '1.5') + DOT(12, 12).replace('1.15', '1.5') + DOT(18.5, 12).replace('1.15', '1.5'),
    "search": '<circle cx="10.8" cy="10.8" r="6.3"/><path d="M15.5 15.5l5 5"/>',
    "refresh": '<path d="M20 12a8 8 0 1 1-2.35-5.65"/><path d="M20 4v4.6h-4.6"/>',
    "reset": '<path d="M4 12a8 8 0 1 0 2.35-5.65"/><path d="M4 4v4.6h4.6"/>',
    "wipe": '<path d="M4 7h16M9.5 7V4h5v3M6.2 7l.9 13h9.8l.9-13"/><path d="M10 11v5.5M14 11v5.5"/>',
    "power": '<path d="M12 3v8.5"/><path d="M7 6.2a8 8 0 1 0 10 0"/>',
    "external": '<path d="M14 4h6v6M20 4l-8.5 8.5"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    "sign-in": '<path d="M14 4h5v16h-5"/><path d="M10 8l4 4-4 4M14 12H4"/>',
    "sign-out": '<path d="M10 4H5v16h5"/><path d="M15 8l4 4-4 4M19 12H9.5"/>',
    "download": '<path d="M12 4v11M7.5 10.5L12 15l4.5-4.5"/><path d="M4 19.5h16"/>',
    "upload": '<path d="M12 16V5M7.5 9.5L12 5l4.5 4.5"/><path d="M4 19.5h16"/>',
    "eye": '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
    "settings": '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    "theme": '<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5a8.5 8.5 0 0 0 0 17z" fill="currentColor" stroke="none"/>',
    // The theme switch's two states (Q3). "theme" (half filled) stays for
    // Follow Windows: the theme comes from elsewhere.
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.55 1.55M17.15 17.15l1.55 1.55M5.3 18.7l1.55-1.55M17.15 6.85l1.55-1.55"/>',
    "moon": '<path d="M19.5 14.6A8 8 0 0 1 9.4 4.5a8 8 0 1 0 10.1 10.1z"/>',
    "launch": '<path d="M6 4l13 8-13 8z"/>',
    "drag": DOT(9, 6) + DOT(15, 6) + DOT(9, 12) + DOT(15, 12) + DOT(9, 18) + DOT(15, 18)
  };

  var SPRITE_ID = "sluse-icon-sprite";

  function sprite() {
    if (document.getElementById(SPRITE_ID)) return;
    var s = '<svg xmlns="http://www.w3.org/2000/svg" id="' + SPRITE_ID + '" aria-hidden="true" style="position:absolute;width:0;height:0;overflow:hidden">';
    for (var k in ICONS) s += '<symbol id="i-' + k + '" viewBox="0 0 24 24">' + ICONS[k] + "</symbol>";
    s += "</svg>";
    document.body.insertAdjacentHTML("afterbegin", s);
  }

  function svg(name, extraClass, size) {
    if (!ICONS[name]) { console.warn("SluseIcons: no icon named", name); name = "unknown"; }
    var cls = "icon icon--" + name + (extraClass ? " " + extraClass : "");
    var style = size ? "width:" + size + "px;height:" + size + "px;" : "";
    // A spinner joins one shared turn rather than starting its own: a page
    // that redraws a row every second (Sluse Admin's sign-in steps) made a
    // new one each time, which began at 0° again and looked stuck. 900 ms is
    // components.css's sl-spin.
    if (name === "spinner") style += "animation-delay:-" + Math.round(performance.now() % 900) + "ms;";
    var dim = (size ? ' width="' + size + '" height="' + size + '"' : "") + (style ? ' style="' + style + '"' : "");
    return '<svg class="' + cls + '"' + dim + ' aria-hidden="true" focusable="false"><use href="#i-' + name + '"/></svg>';
  }

  /* ---- Automatic icons -------------------------------------------------
     These components get their icon from an attribute, so a state change in
     a mock-up (or in the product) can never leave a stale icon behind:
       .pill[data-status], .status[data-status]   status vocabulary below
       .step[data-step]                           done | current | next | failed | skipped
       .banner[data-kind], .note[data-kind], .toast[data-kind]   info | warning | problem | done
       .stepper__item[data-flag]                  done | warning | problem
     Write data-icon="none" on the element to keep it word-only. */
  var STATUS_ICON = {
    "admitted": "admitted", "released": "released", "published": "released", "current": "current",
    "done": "check", "granted": "check", "ready": "check", "allowed": "check", "in-scope": "check", "on": "check",
    "signed-in": "person",
    "refused": "refused", "denied": "refused", "out-of-scope": "refused", "stale": "stale", "orphaned": "orphaned",
    "changed": "changed", "warning": "warning", "encrypted": "sealed", "let-in": "admitted",
    "signed-out": "dash", "signing-in": "spinner",
    "problem": "problem", "error": "problem", "failed": "problem",
    "pending": "pending", "waiting": "pending", "checking": "spinner", "working": "spinner",
    "not-checked": "not-checked", "off": "dash",
    "missing": "missing", "unknown": "unknown", "none": "dash",
    "read": "eye", "unread": "dash", "fetched": "download", "info": "info", "plain": null
  };
  var STEP_ICON = { "done": "admitted", "current": "spinner", "next": "not-checked", "failed": "problem", "skipped": "dash" };
  var KIND_ICON = { "info": "info", "warning": "warning", "problem": "problem", "done": "admitted" };
  var FLAG_ICON = { "done": "check", "warning": "warning", "problem": "problem" };

  var AUTO = [
    { sel: ".pill[data-status], .status[data-status]", attr: "data-status", map: STATUS_ICON, where: "start" },
    { sel: ".step[data-step]", attr: "data-step", map: STEP_ICON, where: "start" },
    { sel: ".banner[data-kind], .note[data-kind], .toast[data-kind]", attr: "data-kind", map: KIND_ICON, where: "start" },
    { sel: ".stepper__item[data-flag] > .stepper__btn", attr: "data-flag", map: FLAG_ICON, where: "end", from: "parent" }
  ];

  function autoOne(el, rule) {
    if (el.getAttribute("data-icon") === "none") return;
    var host = rule.from === "parent" ? el.parentElement : el;
    var key = host.getAttribute(rule.attr);
    var name = rule.map[key];
    var existing = null;
    for (var i = 0; i < el.children.length; i++) if (el.children[i].hasAttribute && el.children[i].hasAttribute("data-auto-icon")) existing = el.children[i];
    if (!name) { if (existing) existing.remove(); return; }
    if (existing && existing.getAttribute("data-auto-icon") === name) return;
    var tmp = document.createElement("span");
    tmp.innerHTML = svg(name);
    var node = tmp.firstChild;
    node.setAttribute("data-auto-icon", name);
    if (existing) existing.replaceWith(node);
    else if (rule.where === "end") el.appendChild(node);
    else el.insertBefore(node, el.firstChild);
  }

  function auto(root) {
    root = root || document;
    AUTO.forEach(function (rule) {
      var list = root.querySelectorAll(rule.sel);
      for (var i = 0; i < list.length; i++) autoOne(list[i], rule);
      if (root.matches && root.matches(rule.sel)) autoOne(root, rule);
    });
  }

  function watch() {
    if (!window.MutationObserver) return;
    new MutationObserver(function (records) {
      records.forEach(function (r) {
        if (r.type === "attributes") {
          var target = r.target;
          if (r.attributeName === "data-flag") target = target.querySelector(".stepper__btn") || target;
          auto(target);
        } else {
          r.addedNodes.forEach(function (n) { if (n.nodeType === 1 && !n.hasAttribute("data-auto-icon") && n.tagName !== "IMG") { hydrateIcons(n); auto(n); brand(n); wrapAll(n); } });
          // The target's own children changed (textContent written into a
          // note, a pill, a banner): put its icon back and re-wrap its text.
          var t = r.target;
          if (t.nodeType === 1 && t.matches) {
            AUTO.forEach(function (rule) { if (t.matches(rule.sel)) autoOne(t, rule); });
            if (t.matches(TEXT_ROWS)) wrapText(t);
          }
        }
      });
    }).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-status", "data-step", "data-kind", "data-flag"] });
  }

  // The <svg> keeps the <i>'s other attributes: id, title, hidden, style,
  // and every data-* (data-when-*, data-unless-* above all), so a mock's
  // visibility rules survive the swap.
  var SKIP = { "class": 1, "data-icon": 1, "data-size": 1, "aria-hidden": 1, "focusable": 1 };
  function hydrateIcons(root) {
    var nodes = (root.matches && root.matches("i[data-icon]")) ? [root] : root.querySelectorAll("i[data-icon]");
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var tmp = document.createElement("span");
      tmp.innerHTML = svg(n.getAttribute("data-icon"), n.className, n.getAttribute("data-size"));
      var out = tmp.firstChild;
      for (var a = 0; a < n.attributes.length; a++) {
        var at = n.attributes[a];
        if (SKIP[at.name]) continue;
        if (at.name === "style") out.setAttribute("style", (out.getAttribute("style") || "") + ";" + at.value);
        else out.setAttribute(at.name, at.value);
      }
      n.replaceWith(out);
    }
  }

  /* ---- Text in icon rows --------------------------------------------------
     .note, .status and .field__msg are flex rows: icon, then text. Mixed
     inline content (text, a mono path, a link) would become flex columns,
     so it is wrapped in one span.sl-text. Runs at load and on every change,
     so a page may write textContent into one: the icon comes back (watch)
     and the text is wrapped. Block children (div, p, ul…) are left alone. */
  var TEXT_ROWS = ".note, .status, .field__msg";
  var BLOCK = /^(DIV|P|UL|OL|TABLE|DETAILS|SECTION|FORM|DL|H[1-6])$/;
  function isIconNode(k) {
    return k.nodeType === 1 && (k.hasAttribute("data-auto-icon") || (k.tagName === "I" && k.hasAttribute("data-icon")) ||
      (k.tagName.toLowerCase() === "svg" && k.classList.contains("icon")));
  }
  function wrapText(el) {
    var kids = Array.prototype.slice.call(el.childNodes).filter(function (k) { return !isIconNode(k) && !(k.nodeType === 3 && !k.textContent.trim()); });
    if (kids.length < 2) return;
    if (kids.some(function (k) { return k.nodeType === 1 && BLOCK.test(k.tagName); })) return;
    var span = document.createElement("span");
    span.className = "sl-text";
    kids[0].parentNode.insertBefore(span, kids[0]);
    kids.forEach(function (k) { span.appendChild(k); });
  }
  function wrapAll(root) {
    if (root.matches && root.matches(TEXT_ROWS)) wrapText(root);
    var list = root.querySelectorAll ? root.querySelectorAll(TEXT_ROWS) : [];
    for (var i = 0; i < list.length; i++) wrapText(list[i]);
  }

  /* ---- Brand: the logo kit, the right cut for each size -----------------
       <span class="app-icon" data-size="32"></span>   tiled icon, cut chosen by size
       <span class="mark" data-size="96"></span>       tileless; cream on navy, navy on cream
     The rule (Q10, jok, 2026-10-19, option B): the full mark from 36px,
     the small cut at 24 and 32, the 16px cut at 16. The guide still says
     48 and is to change to 36. A cut is never scaled up, so a size between
     cuts below 32 takes the next larger cut, scaled down. Windows' 36 and
     40 (taskbar and Start at 125% and 150%) take the full mark.
     33 to 35px is the one gap left: the small cut may not be scaled up and
     the full mark starts at 36. Windows asks for none of those sizes;
     cutFor returns null there and nothing is drawn, never an illegal cut. The tileless mark is the full drawing, so it too starts
     at 36. */
  var here = (document.currentScript && document.currentScript.src) || location.href;
  var KIT = new URL("logo/", here).href;
  function cutFor(px) {
    if (px <= 16) return "sluse-app-icon-16.svg";
    if (px <= 32) return "sluse-app-icon-small.svg";
    if (px < 36) return null;
    return "sluse-app-icon.svg";
  }
  function noCut(el, px, what) {
    el.setAttribute("data-ready", "");
    console.warn("Sluse: no " + what + " is allowed at " + px + "px (Q10). Use 16, 24, 32, or 36 and up.");
  }
  function brand(root) {
    root = root || document;
    var icons = root.querySelectorAll(".app-icon[data-size]:not([data-ready])");
    if (root.matches && root.matches(".app-icon[data-size]:not([data-ready]), .mark[data-size]:not([data-ready])")) { var p = root.parentNode || document; brand(p); return; }
    for (var i = 0; i < icons.length; i++) {
      var el = icons[i], px = parseFloat(el.getAttribute("data-size"));
      if (!cutFor(px)) { noCut(el, px, "cut of the app icon"); continue; }
      if ([16, 24, 32].indexOf(px) < 0 && px < 36) console.info("Sluse: " + px + "px takes the next larger cut, scaled down.");
      el.style.width = el.style.height = px + "px";
      el.innerHTML = '<img src="' + KIT + cutFor(px) + '" width="' + px + '" height="' + px + '" alt="' + (el.getAttribute("data-alt") || "") + '">';
      el.setAttribute("data-ready", "");
    }
    var marks = root.querySelectorAll(".mark[data-size]:not([data-ready])");
    for (var j = 0; j < marks.length; j++) {
      var m = marks[j], mpx = parseFloat(m.getAttribute("data-size"));
      if (mpx < 36) { noCut(m, mpx, "tileless mark (the full drawing, 36px and up)"); continue; }
      m.style.width = m.style.height = mpx + "px";
      var alt = m.getAttribute("data-alt") || "";
      m.innerHTML = '<img class="mark__on-navy" src="' + KIT + 'sluse-mark-cream.svg" alt="' + alt + '">' +
                    '<img class="mark__on-cream" src="' + KIT + 'sluse-mark-navy.svg" alt="' + alt + '">';
      m.setAttribute("data-ready", "");
    }
    if (!document.querySelector('link[rel~="icon"]')) {
      var l = document.createElement("link"); l.rel = "icon"; l.type = "image/svg+xml"; l.href = KIT + "sluse-app-icon-16.svg";
      document.head.appendChild(l);
    }
  }

  function init() { sprite(); hydrateIcons(document); auto(document); brand(document); wrapAll(document); watch(); }

  window.SluseIcons = { names: Object.keys(ICONS), svg: svg, hydrate: function (r) { hydrateIcons(r || document); auto(r || document); brand(r || document); wrapAll(r || document); }, auto: auto, wrapText: wrapAll, paths: ICONS, statusIcon: STATUS_ICON };
  window.SluseBrand = { kit: KIT, cutFor: cutFor, render: brand };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
