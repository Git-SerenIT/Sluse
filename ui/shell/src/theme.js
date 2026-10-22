// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// The theme switch (Q3, D-062): Follow Windows, Light or Dark, kept on this
// computer; and the bar's menus, which close on an outside click or Esc.
// A classic script in <head>, so the theme is set before the first paint.
// Markup: docs/design/mockups/shell/running.html, the bar's last item.
// The theme in use, Follow Windows resolved, is window.sluseTheme(); each
// change to it is a 'sluse-theme' event on document, which main.js carries
// into the box at once (Q70).
(function () {
  'use strict';
  // Sluse Admin keeps its own choice (<html data-theme-key>), apart from
  // the box window's on the same computer.
  const KEY = document.documentElement.dataset.themeKey || 'sluse.theme';
  const WORD = { light: 'Light', dark: 'Dark' };
  const dark = matchMedia('(prefers-color-scheme: dark)');
  let theme = 'system';
  try { theme = localStorage.getItem(KEY) || 'system'; } catch { /* no storage: follow Windows */ }

  const effective = () => (theme === 'system' ? (dark.matches ? 'dark' : 'light') : theme);

  let told = null;
  // Said once per change of the theme in use, not per click: Follow Windows
  // on a dark Windows and Dark are the same theme to the box.
  function tell() {
    const eff = effective();
    if (eff !== told) document.dispatchEvent(new CustomEvent('sluse-theme', { detail: (told = eff) }));
  }

  function apply(t) {
    theme = t === 'light' || t === 'dark' ? t : 'system';
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem(KEY, theme); } catch { /* the choice lasts this window only */ }
    sync();
  }

  function sync() {
    const eff = effective();
    for (const sw of document.querySelectorAll('[data-theme-switch]')) {
      for (const b of sw.querySelectorAll('[data-theme-choice]')) b.setAttribute('aria-pressed', String(b.dataset.themeChoice === theme));
      for (const n of sw.querySelectorAll('[data-theme-now]')) n.textContent = WORD[eff];
      // toggleAttribute: the icons are <svg> once icons.js has run, and SVG has no .hidden.
      for (const n of sw.querySelectorAll('[data-theme-icon]')) n.toggleAttribute('hidden', n.dataset.themeIcon !== eff);
      for (const n of sw.querySelectorAll('[data-theme-follow]')) n.toggleAttribute('hidden', theme !== 'system');
      for (const n of sw.querySelectorAll('[data-theme-windows]')) n.textContent = `Windows is ${dark.matches ? 'dark' : 'light'} now.`;
      // Under 1280px only the icon shows (style.css); the title says it in words.
      sw.querySelector('summary').title = `Theme: ${WORD[eff]}${theme === 'system' ? ', following Windows' : ''}`;
    }
    tell();
  }

  window.sluseTheme = effective;
  apply(theme);
  dark.addEventListener('change', sync);
  document.addEventListener('DOMContentLoaded', sync);

  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-theme-choice]');
    if (b) {
      apply(b.dataset.themeChoice);
      const sw = b.closest('details');
      sw.open = false;
      sw.querySelector('summary').focus();
    }
    for (const m of document.querySelectorAll('details.menu[open]')) if (!m.contains(e.target)) m.open = false;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const m = document.activeElement?.closest('details.menu[open]');
    if (m) { m.open = false; m.querySelector('summary').focus(); }
  });
})();
