// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// The shell's window: ask the service for the box, then show it (D-025).
// The VNC secret goes from the service to noVNC without being shown or
// typed (D-027 point 4). The screens are the mock-ups' (D-062):
// docs/design/mockups/shell/{wait,running,errors}.html.

import RFB from './novnc/core/rfb.js';
import { cause } from './causes.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
// The clipboard plugin's own commands, called directly rather than through
// its injected JS, which is one less thing to be present.
const clip = {
  readText: () => invoke('plugin:clipboard-manager|read_text'),
  writeText: (text) => invoke('plugin:clipboard-manager|write_text', { text }),
};

const $ = (id) => document.getElementById(id);
const clockText = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
const inWords = (s) => (s >= 120 ? `${Math.round(s / 60)} minutes` : `${s} second${s === 1 ? '' : 's'}`);
const secondsSince = (t) => Math.floor((Date.now() - t) / 1000);
const state = () => document.body.dataset.state;
const IT = 'Send the details to your IT department.';
const it = 'send the details to your IT department.';
// This window's own log, `%LOCALAPPDATA%\Sluse\logs\shell.log` (D-066): each
// step, the viewer, the console's answers and the sign-ins, with the time.
const slog = (...words) => invoke('shell_log', { line: `${new Date().toISOString()} ${words.join(' ')}` }).catch(() => {});
slog('window: started');
// Quit, with why: the line is written before the window goes.
const quit = (why) => slog('quit:', why).then(() => invoke('quit'));

/** A button, as the components draw it. */
function button(label, { icon, cls = '', run } = {}) {
  const b = Object.assign(document.createElement('button'), { type: 'button', className: `btn ${cls}`.trim() });
  if (icon) {
    const i = document.createElement('i');
    i.dataset.icon = icon;
    b.append(i);
  }
  b.append(label);
  if (run) b.onclick = run;
  return b;
}

// What IT needs to find this box (Q24), from the service and this computer;
// asked at each open. `facts.user` is who the box is signed in as.
let facts = {};
const getFacts = () => invoke('facts').then((f) => { facts = f; }, () => {});

/** Copy details: what, when, the words, then the identity line and where to look. */
function details(code, message, steps) {
  return `Sluse: ${code} at ${new Date().toISOString()}\n${message}\n\n` +
    `Sluse ${facts.version ?? 'version not known'} on ${facts.device || 'this computer'}, ` +
    `Windows user ${facts.windows_user || 'not known'}, box ${facts.vm || 'not made yet'}\n` +
    (steps ? `Steps: ${steps}\n` : '') +
    'For IT: the Sluse events in the Event Log around that time; C:\\ProgramData\\Sluse\\phases.json' +
    (facts.dir ? `; ${facts.dir}\\console.log` : '');
}

async function copyText(b, text) {
  const label = b.querySelector('span') ?? b;
  try {
    await clip.writeText(text);
    label.textContent = 'Copied';
    setTimeout(() => { label.textContent = 'Copy details'; }, 2000);
  } catch { /* the clipboard refused; the text is on screen to select */ }
}

// ---- The attempt: its steps, as the ledger shows them --------------------
// The service sends its plan with its first progress (Q19); the shell's own
// steps (the sign-in, connecting, the console) come as progress too. The
// ledger names each step by its phase, never estimates time, and carries on
// from a reset into its open.
const NAME = {
  'sign-in': 'Signing you in to Microsoft', check: 'Checking this computer',
  download: "Downloading your box's system", convert: "Preparing your box's disk",
  install: "Installing your box's system", make: 'Making your box', start: 'Starting your box',
  gate: 'Connecting Sluse to your files', wait: "Waiting for your box's screen",
  connect: 'Connecting to your box', console: "Waiting for your box's console",
  reset: "Resetting the box's system", wipe: 'Wiping the box', close: 'Closing your box', open: 'Opening your box',
};
const BUILD = ['download', 'convert', 'install', 'make'];
const OPENING = ['sign-in', 'check', 'start', 'gate', 'wait', 'connect', 'console'];
const SLOW = "The first time on this computer, Sluse prepares your box's system first.";
// Q26: closing the window during a build finishes it and leaves the box closed.
const SAFE = {
  open: "You can close this window: Sluse finishes preparing your box's system without it and leaves your box closed. Windows tells you when it is ready.",
  reset: 'You can close this window: the reset finishes without it and leaves your box closed until you open Sluse again.',
  wipe: 'You can close this window: the wipe finishes without it and leaves your box closed until you open Sluse again.',
};

// `kind`: open, reset, wipe or close. `done`: finished steps; `cur`: the
// step under way; `plan`: the service's steps for this request.
let att = null;
let clock = null;
let signinWindow = false;

function begin(kind) {
  att = { kind, since: Date.now(), done: [], cur: null, plan: [] };
  signinWindow = false;
  renderLedger();
}

function nameFor(phase) {
  return att.plan.find((p) => p.phase === phase)?.step ?? NAME[phase] ?? phase;
}

function renderLedger(failedSub) {
  const rows = att.done.map((d) => ['done', d.name, clockText(d.secs), d.sub]);
  const c = att.cur;
  if (c) rows.push([failedSub !== undefined ? 'failed' : 'current', c.name, clockText(secondsSince(c.since)), failedSub ?? c.sub]);
  // Before the service's plan, the ledger says only that the box is opening.
  else if (failedSub === undefined) rows.push(['current', NAME[att.kind === 'close' ? 'close' : 'open'], clockText(secondsSince(att.since))]);
  else rows.push(['failed', NAME[att.kind === 'close' ? 'close' : att.kind === 'open' ? 'open' : att.kind], '0:00', failedSub]);
  if (failedSub === undefined) {
    const seen = new Set([...att.done.map((d) => d.phase), c?.phase]);
    for (const p of att.plan) if (!seen.has(p.phase)) rows.push(['next', p.step]);
  }
  $('ledger').replaceChildren(...rows.map(([step, text, time, sub]) => {
    const li = Object.assign(document.createElement('li'), { className: 'step' });
    li.dataset.step = step;
    li.append(Object.assign(document.createElement('span'), { className: 'step__text', textContent: text }));
    li.append(Object.assign(document.createElement('span'), { className: 'step__time', textContent: time ?? '' }));
    if (sub) li.append(Object.assign(document.createElement('span'), { className: 'step__sub', textContent: sub }));
    return li;
  }));
}

/** The steps for Copy details: `done check 0:01, start 0:12 failed`. */
function stepsLine(failed) {
  const s = att.done.map((d) => `${d.phase ?? d.name} ${clockText(d.secs)}`);
  if (att.cur) s.push(`${att.cur.phase ?? att.cur.name} ${clockText(secondsSince(att.cur.since))}${failed ? ' failed' : ''}`);
  return s.length ? `done ${s.join(', ')}` : null;
}

// One progress event: `{ step, phase?, pct?, lastS?, limitS?, plan? }`, from
// the service or the shell's own steps; `{ step }` from an older service,
// whose steps are shown as they come (D-034 point 3).
function progress(p) {
  if (state() !== 'waiting' && state() !== 'closing') show('waiting');
  if (!att) begin('open');
  if (p.plan?.length) att.plan = p.plan;
  const phase = p.phase ?? null;
  if (phase !== (att.cur?.phase ?? null) || (!phase && p.step !== att.cur?.step)) {
    slog('step:', phase ?? '-', p.step, p.tries ? `(try ${p.tries})` : '');
    if (att.cur) att.done.push({ phase: att.cur.phase, name: att.cur.name, secs: secondsSince(att.cur.since) });
    att.cur = { phase, name: phase ? nameFor(phase) : p.step, since: Date.now(), pct: null, pctSince: Date.now() };
  }
  const c = att.cur;
  c.step = p.step;
  c.lastS = p.lastS ?? c.lastS ?? null;
  c.limitS = p.limitS ?? c.limitS ?? null;
  if ((p.pct ?? null) !== c.pct) { c.pct = p.pct ?? null; c.pctSince = Date.now(); }
  c.sub = phase === 'sign-in' ? (signinWindow ? 'Waiting for you in the sign-in window' : 'A Microsoft window opens only if Microsoft needs you.')
    : phase === 'console' ? "The box's screen is up. Sluse shows it once the console answers."
      : p.tries ? `Try ${p.tries} of ${RETRIES}`
        : p.step !== c.name ? (c.pct != null ? `${p.step}, ${c.pct}%` : p.step) : '';
  renderLedger();
  renderWait();
  edges();
}

function renderWait() {
  const c = att?.cur;
  if (!c) return;
  const phase = c.phase;
  $('title').textContent = phase === 'sign-in' && signinWindow ? c.step : c.pct != null ? `${c.step}, ${c.pct}%…` : `${c.step}…`;
  $('lead').hidden = !(phase === 'sign-in' && signinWindow);
  $('lead').textContent = 'Sluse opened a window called Sign in to Sluse. Sign in there so Sluse can read files as you.';
  $('signin-row').hidden = !(phase === 'sign-in' && signinWindow);
  const say = (id, text) => { $(id).textContent = text ?? ''; $(id).hidden = !text; };
  say('m-last', c.lastS != null ? `Last time on this computer: ${clockText(c.lastS)}.`
    : BUILD.includes(phase) && att.kind === 'open' ? SLOW : null);
  say('m-limit', phase === 'close' && c.limitS != null
    ? `If it has not shut down after ${inWords(c.limitS)}, Sluse turns it off. Your files stay either way.`
    : phase === 'sign-in' ? (signinWindow ? 'Sluse waits up to 10 minutes for you.' : 'Sluse waits up to 30 seconds for Microsoft.')
      : c.limitS != null ? `If this step takes more than ${inWords(c.limitS)}, Sluse stops and says why.` : null);
  say('m-safe', BUILD.includes(phase) ? SAFE[att.kind] : null);
  // A real bar only where there is a percentage.
  const bar = $('bar');
  if (c.pct != null) {
    bar.removeAttribute('data-indeterminate');
    bar.style.setProperty('--value', `${c.pct}%`);
    bar.setAttribute('aria-valuenow', c.pct);
  } else {
    bar.setAttribute('data-indeterminate', '');
    bar.removeAttribute('aria-valuenow');
  }
  tick();
}

// Kept here, not by the service: it moves even when the service is between
// messages, which is what tells a wait from a hang. Looking stuck has three
// cases (Q28): later than last time, a percentage that has not moved for 5
// minutes, past the step's limit.
const FROZEN_S = 300;
let stuckText = '';
function tick() {
  if (!att) return;
  $('clock').textContent = clockText(secondsSince(att.since));
  const now = $('ledger').querySelector('[data-step="current"] .step__time');
  const c = att.cur;
  if (now) now.textContent = clockText(secondsSince(c?.since ?? att.since));
  if (!c) { $('stuck').hidden = true; return; }
  const s = secondsSince(c.since);
  // ponytail: the 30 s of slack is a guess; tune it from the L1 timings.
  const kind = c.limitS != null && s > c.limitS ? 'over'
    : c.pct != null && secondsSince(c.pctSince) >= FROZEN_S ? 'frozen'
      : c.lastS != null && s > Math.max(2 * c.lastS, c.lastS + 30) ? 'late' : null;
  $('stuck').hidden = !kind;
  if (!kind) return;
  $('stuck').dataset.kind = kind === 'over' ? 'warning' : 'info';
  const since = new Date(c.pctSince).toTimeString().slice(0, 5);
  const [title, text] = {
    over: ['This has taken longer than Sluse waits for it.', `It stops by itself and says why. If it does not, ${it}`],
    frozen: ['This step has not moved for 5 minutes.', `It has stayed at ${c.pct}% since ${since}. Sluse goes on waiting. If it does not move on, ${it}`],
    late: ['This is taking longer than last time.', `${c.lastS != null ? `Last time this step took ${clockText(c.lastS)}. ` : ''}If it does not move on, ${it}`],
  }[kind];
  $('stuck-title').textContent = title;
  $('stuck-text').textContent = text;
  stuckText = details('waiting',
    `waiting in ${c.phase ?? 'none'} for ${clockText(s)}${kind === 'frozen' ? ` at ${c.pct}%, unchanged for ${clockText(secondsSince(c.pctSince))}` : ''}` +
    ` (last time ${c.lastS != null ? clockText(c.lastS) : 'none'}, limit ${c.limitS != null ? `${c.limitS} s` : 'none'})\nstep: ${c.step}`,
    stepsLine(false));
}

// The first waits say what a box is, until one has opened (D-034 point 10).
let intro = false;
try { intro = !localStorage.getItem('sluse.opened'); } catch { intro = true; }

function show(next, title) {
  if (next !== state()) slog('screen:', next);
  document.body.dataset.state = next;
  if (title !== undefined) $('title').textContent = title;
  clearInterval(clock);
  clock = null;
  if (next === 'waiting' || next === 'closing') {
    clock = setInterval(tick, 1000);
    tick();
  }
  $('intro').hidden = !(next === 'waiting' && intro);
  edges();
}

// ---- Windows' edges (Q11): taskbar, tray, notifications ------------------
// What runs for this person, said where Windows shows it: the taskbar
// button's bar during a build, the tray icon while a box or a build runs,
// and four notifications, each withdrawn once untrue (Q86). The window's
// second X closes the box while it is on screen (Q29) and quits into the
// tray during a build (Q26).
const building = () => (state() === 'waiting' && BUILD.includes(att?.cur?.phase)) || quitting;
const who = () => (facts.entra && facts.user && signState.cause === 'ok' ? facts.user : facts.windows_user || 'you');
let quitting = false;
// Said again only when it changed: progress comes every second or so.
const said = {};
const tell = (cmd, args) => {
  const json = JSON.stringify(args);
  if (said[cmd] === json) return;
  said[cmd] = json;
  invoke(cmd, args).catch(() => {});
};
function edges() {
  const s = state();
  tell('window_state', { state: s === 'running' ? 'running' : building() ? 'building' : 'other' });
  const c = att?.cur;
  tell('taskbar', { state: building()
    ? (c?.pct != null ? { status: 'normal', progress: c.pct } : { status: 'indeterminate' })
    : s === 'error' && BUILD.includes(c?.phase) ? { status: 'error', progress: c.pct ?? 50 } : { status: 'none' } });
  let tray = null;
  if (building()) {
    const what = `Preparing your box's system${c?.pct != null ? `, ${c.pct}%` : ''}`;
    tray = { tip: `${what}. Open Sluse to see each step.`, lines: [what, 'Open Sluse to see each step.'], canClose: false };
  } else if (s === 'running') {
    const [line, tip] = box?.update ? ['An update for it is ready. Resetting the box\'s system applies it, and your files stay.', 'Your box is running. An update for it is ready. Resetting the box\'s system applies it, and your files stay.']
      : box?.problem ? ['An update for it could not be prepared. Your box works as before.', 'An update for your box could not be prepared. Your box works as before. Sluse tries again by itself and when the computer restarts.']
        : [`Sluse reads files for it as ${who()}.`, `Your box is running. Sluse reads files for it as ${who()}.`];
    tray = { tip, lines: ['Your box is running', line], canClose: true };
  }
  tell('tray', { state: tray && { ...tray, inputs: !$('inputs').hidden } });
}
const notify = (tag, title, text, buttons) => invoke('notify', { tag, title, text, buttons }).catch(() => {});
const OPEN = ['Open Sluse', 'open'];
const CLOSE = ['Close the box', 'close'];
// A notification that is no longer true is withdrawn: the build is ready
// only until Sluse opens again.
invoke('withdraw', { tags: ['built'] }).catch(() => {});
listen('tray-close', () => askClose());
// The second X during a build: the window has gone to the tray (Q26).
listen('quit-build', () => { quitting = true; edges(); });

const wait = (title) => show('waiting', title);

// ---- Errors, by code and cause (D-034 point 4) --------------------------
// A pill that names what did not happen, a headline, one sentence, the
// action that fits, the attempt's ledger with the failed step, and the
// service's words under Details. Reset and Wipe are offered only where a
// reset can help.
const RETRY_BOX = "Try again. If it keeps happening, resetting the box's system usually helps, and your files stay.";
const NOT_ANSWERING = ['Sluse is not answering on this computer', 'Restart the computer. If Sluse still does not open, send the details to your IT department.'];

function explainFailure(f, kind) {
  const m = f.message ?? '';
  const e = { head: 'Your box did not open', body: 'Try again. If it keeps happening, send the details to your IT department.', primary: 'retry' };
  switch (f.code) {
    case 'busy':
      e.head = 'Sluse is busy';
      e.body = m.startsWith("Another user's box") ? "Another user's box is open on this computer, and only one box runs at a time. Try again when they have closed it."
        : m.startsWith('This box is already being reset') ? 'This box is already being reset or wiped. Try again when that has finished.' : m;
      e.sub = m.startsWith("Another user's box") ? "Another user's box is running" : 'Sluse was busy';
      break;
    case 'noBox':
      Object.assign(e, { head: 'You have no box on this computer yet', body: `Try again to make one. ${SLOW}`, sub: 'No box to reset' });
      break;
    case 'preflight':
      if (/Restart the computer to finish installing/.test(m)) {
        Object.assign(e, { head: 'Restart the computer to finish installing Sluse', primary: 'none', secondary: true, sub: 'Hyper-V needs a restart',
          body: 'Sluse needs Hyper-V, and Hyper-V needs a restart before your box can run. Restart the computer, then open Sluse again.' });
      } else if (/no Sluse configuration/.test(m)) {
        Object.assign(e, { head: 'This computer is not set up for Sluse yet', body: `It has no Sluse configuration. ${IT}`, sub: 'No Sluse configuration' });
      } else {
        Object.assign(e, { head: 'This computer is not ready for Sluse', body: `Sluse checks this computer before it opens your box, and a check failed. ${IT}` });
      }
      break;
    case 'gate':
      Object.assign(e, { head: 'Sluse could not connect your box to your files',
        body: 'This is a setup problem on this computer, not in your box, so resetting the box would not help. Try again, or send the details to your IT department.' });
      break;
    case 'box': {
      const why = cause(m);
      if (kind === 'reset') Object.assign(e, { head: "Your box's system was not reset", body: `Your files stay. Try again to open your box. If it keeps happening, ${it}` });
      else if (kind === 'wipe') Object.assign(e, { head: 'Your box was not wiped', body: `Some or all of what was in your box may still be there. Try again to open your box and wipe it. If it keeps happening, ${it}` });
      else if (why) Object.assign(e, { head: why.head, body: why.body, sub: why.sub, primary: why.reset ? 'reset' : 'retry' });
      else Object.assign(e, { head: f.headline ?? 'Your box did not start', body: RETRY_BOX, recover: true, pill: f.headline ? 'Connection lost' : undefined });
      break;
    }
    case 'notAllowed':
      Object.assign(e, /set up by hand/.test(m)
        ? { head: 'Sluse cannot reset this box', body: `This box was set up by hand, not by Sluse, so Sluse cannot reset or wipe it. ${IT}`, sub: 'Set up by hand' }
        : { head: "You cannot reset another user's box", body: 'Only an administrator on this computer can reset or wipe it.' });
      break;
    case 'badRequest':
      Object.assign(e, { head: 'Sluse did not understand the request', body: `This is a fault in Sluse, not something you did. ${IT}` });
      break;
    case 'service':
      if (/owner is not SYSTEM/.test(m)) {
        Object.assign(e, { head: "Something else answered in Sluse's place", primary: 'none', secondary: true, sub: 'The answer did not come from Sluse',
          body: 'The program that answered on this computer is not Sluse, so Sluse did not open your box. Send the details to your IT department before you restart the computer.',
          extra: 'Before it opens your box, Sluse checks that the program answering on this computer is its own, and this check failed.' });
      } else {
        [e.head, e.body] = NOT_ANSWERING;
        e.sub = 'Sluse did not answer';
      }
      break;
    case 'screen':
      Object.assign(e, { head: 'Sluse did not show this box', body: `The box's screen was not where Sluse expects it, so Sluse did not show it. ${IT}`,
        primary: 'none', secondary: true, sub: 'Not shown: unexpected address', extra: 'Sluse shows a box only at the address it set up for it on this computer.' });
      break;
    case 'console':
      Object.assign(e, { head: "Your box's console did not start", primary: 'close', sub: 'The console did not answer',
        body: 'Your box is running, but its console did not answer in time, so Sluse did not show it. Close the box and open Sluse again. If it happens again, send the details to your IT department.' });
      break;
    case 'signIn':
      Object.assign(e, { head: 'Sluse could not sign you in',
        body: 'Your box is open, but Sluse cannot read files for it until you are signed in. Close the box and open Sluse again to sign in.' });
      break;
    case 'closeFailed':
      Object.assign(e, { head: 'Your box did not close', body: 'Try closing it again. Restarting the computer also closes it, and your files stay.', primary: 'close' });
      break;
    default:
  }
  if (kind === 'close') e.primary = 'close';
  e.pill ??= { reset: 'Not reset', wipe: 'Not wiped', close: 'Did not close' }[kind] ?? 'Did not open';
  return e;
}

const asFailure = (e) => (e && typeof e === 'object' && 'code' in e) ? e : { code: 'unknown', message: String(e) };

let lastRaw = '';
function failed(error, kind = att?.kind ?? 'open') {
  const f = asFailure(error);
  slog('failed:', kind, f.code ?? '-', f.message ?? '');
  // After Quit during a build the service leaves the box closed and says
  // so; a build that finished is the one thing worth telling (Q26).
  if (quitting) {
    if (/window quit/.test(f.message ?? '')) notify('built', 'Your box\'s system is ready', 'Sluse has finished preparing it. Open Sluse to start your box.', [OPEN]);
    quit('the box was left closed after a Quit');
    return;
  }
  if (!att) begin(kind);
  const e = explainFailure(f, kind);
  show(kind === 'close' ? 'close-failed' : 'error', e.head);
  $('err-pill').textContent = e.pill;
  $('err-pill').hidden = false;
  $('lead').textContent = e.body;
  $('lead').hidden = false;
  $('extra').textContent = e.extra ?? '';
  $('extra').hidden = !e.extra;
  $('signin-row').hidden = true;
  lastRaw = details(f.code, f.message, stepsLine(true));
  $('raw').textContent = lastRaw;
  $('details').open = false;
  renderLedger(e.sub ?? '');
  const acts = [];
  // Close on an error page runs at once (Q76): the box was never shown, or
  // the person already chose to close it.
  if (e.primary === 'retry') acts.push(button('Try again', { icon: 'refresh', cls: 'btn--primary', run: () => open() }));
  if (e.primary === 'close') acts.push(button('Close the box', { icon: 'power', cls: 'btn--primary', run: closeBox }));
  if (e.primary === 'reset') acts.push(button("Reset the box's system…", { icon: 'reset', cls: 'btn--primary', run: askReset }), button('Try again', { icon: 'refresh', run: () => open() }));
  if (e.secondary) acts.push(button('Try again', { icon: 'refresh', run: () => open() }));
  if (e.recover) acts.push(button("Reset the box's system…", { icon: 'reset', run: askReset }), button('Wipe the box…', { icon: 'wipe', cls: 'btn--destructive', run: () => askWipe() }));
  $('actions').replaceChildren(...acts);
  $('actions').hidden = !acts.length;
  acts[0]?.focus();
}

listen('progress', (e) => progress(typeof e.payload === 'string' ? { step: e.payload } : e.payload));
// Microsoft needs the person: the main window says so and can bring the
// sign-in window forward (Q18).
listen('signin-window', (e) => {
  signinWindow = !!e.payload;
  if (att?.cur?.phase === 'sign-in') progress({ step: att.cur.step, phase: 'sign-in' });
});
$('show-signin').onclick = () => invoke('show_sign_in');

// ---- The viewer -----------------------------------------------------------
// The box may still be applying this open's secret when the port first
// answers, so a refused or dropped connection is retried for a while.
const RETRIES = 20;

// The viewer now showing, and whether it was stopped on purpose, so that a
// reset's disconnect is not taken for a box that stopped answering.
let viewer = null;
let stopped = false;
let box = null;
// This open's wait for the box's console (Q9): the picture shows once it has
// answered, and `opening` tells this open's answer from an earlier one's.
let consoleUp = Promise.resolve();
let opening = 0;
let reconnectClock = null;
// Tries since the screen last answered: a drop after a good connection gets
// its full 20 again.
let tries = 0;

function stopViewer() {
  stopped = true;
  if (viewer) viewer.disconnect();
  viewer = null;
  clearTimeout(signInTimer);
  endReconnect();
}

function endReconnect() {
  clearInterval(reconnectClock);
  $('reconnecting').hidden = true;
  $('still').hidden = true;
}

function connect() {
  stopped = false;
  slog('viewer: connecting to', box.vnc);
  const rfb = new RFB($('screen'), box.vnc, {
    credentials: { username: box.username, password: box.password },
  });
  viewer = rfb;
  // The box renders at the size of the space under the bar (Q34); scaling
  // stays on only for a box that cannot follow, so nothing is cut off.
  rfb.resizeSession = true;
  rfb.scaleViewport = true;
  rfb.focusOnClick = true;

  rfb.addEventListener('credentialsrequired', () =>
    rfb.sendCredentials({ username: box.username, password: box.password }));
  // RSA-AES asks to approve the box's key. ponytail: not pinned yet; the
  // enrolment in slice 2 can carry the fingerprint.
  rfb.addEventListener('serververification', () => rfb.approveServer());
  rfb.addEventListener('connect', () => (slog('viewer: connected'), consoleUp.then(() => {
    if (viewer !== rfb) return;
    tries = 0;
    endReconnect();
    if (state() !== 'running') {
      // Q77: only after a first build or a reset, and only when the window
      // is not in front.
      const long = att && (att.kind !== 'open' || att.done.some((d) => BUILD.includes(d.phase)));
      show('running');
      if (long && !document.hasFocus()) notify('open', 'Your box is open', `Sluse reads files for it as ${who()} until you close it.`, [OPEN, CLOSE]);
      // "Box" has been seen working now; the first wait's line about it can go.
      try { localStorage.setItem('sluse.opened', '1'); } catch { /* storage refused */ }
      intro = false;
    }
    rfb.focus();
  }, () => { /* the console did not answer: open() says so */ })));
  rfb.addEventListener('disconnect', (e) => {
    slog('viewer: disconnected', e.detail.clean ? 'clean' : 'not clean', stopped ? '(stopped)' : '');
    if (stopped || viewer !== rfb) return;
    if (tries < RETRIES) {
      tries += 1;
      if (state() === 'running') {
        // The last frame stays, greyed, with the tries counted over it.
        try { $('still').src = rfb.toDataURL(); $('still').hidden = false; } catch { /* no frame yet */ }
        $('reconnecting').hidden = false;
        if (!reconnectClock) {
          const from = Date.now();
          reconnectClock = setInterval(() => { $('rclock').textContent = clockText(secondsSince(from)); }, 1000);
          $('rclock').textContent = '0:00';
        }
        $('rtry').textContent = `Try ${tries} of ${RETRIES}`;
      } else {
        progress({ step: 'Connecting to your box', phase: 'connect', tries });
      }
      setTimeout(() => { if (viewer === rfb) connect(); }, 1000);
    } else {
      stopViewer();
      failed({ code: 'box', message: e.detail.clean ? 'the box closed the connection' : "no answer from the box's screen",
        headline: e.detail.clean ? 'The box closed the connection' : 'Your box is not answering' });
    }
  });
  // Clipboard text, both ways, and nothing else (D-025 point 3). Out of the
  // box only where the config allows it (D-038 point 7): that stops copy
  // and paste out, not retyping or a photo of the screen. Each transfer is
  // recorded (D-076); into the box only on the paste keystroke, below.
  if (box.copy_out !== false) {
    let last = null;
    rfb.addEventListener('clipboard', (e) => {
      const text = e.detail.text;
      clip.writeText(text).catch(() => {});
      // The same text announced again is not a second transfer.
      if (text && text !== last) record('out', text);
      last = text;
    });
  }
}

// ---- Clipboard into the box, on the paste keystroke (D-076) -------------
// Only Ctrl+V, Ctrl+Shift+V and Shift+Insert send the host's clipboard in,
// so what the person copied for something else stays out of the box. The
// keystroke is held while the text goes, then sent, in that order on the one
// connection. Its release reaches noVNC, which drops a key it never saw go
// down. ponytail: a paste from a menu in the box pastes the last text sent;
// add a menu item in the bar if people miss it.
function record(direction, text) {
  invoke('clipboard', { direction, text }).catch(() => { /* no box, or the service's to log */ });
}
const PASTE = { KeyV: (e) => e.ctrlKey && !e.altKey && !e.metaKey, Insert: (e) => e.shiftKey && !e.ctrlKey && !e.altKey };
window.addEventListener('keydown', async (e) => {
  const rfb = viewer;
  // Only a keystroke on its way to the box's screen; the bar's fields paste as usual.
  if (!rfb || !PASTE[e.code]?.(e) || !$('screen').contains(e.target)) return;
  e.preventDefault();
  e.stopPropagation();
  try {
    const text = await clip.readText();
    if (text && viewer === rfb) {
      rfb.clipboardPasteFrom(text);
      record('in', text);
    }
  } catch { /* nothing on the clipboard, or not text */ }
  if (viewer !== rfb) return;
  if (e.code === 'Insert') rfb.sendKey(0xff63, 'Insert');
  else rfb.sendKey(e.shiftKey ? 0x56 : 0x76, 'KeyV');
}, true);

// ---- Who Sluse reads as, and the sign-in (D-036, Q7, Q8, Q22) ----------
// The open asks the person at most once; from the moment the box is open,
// and every minute after, only a silent sign-in is tried. A sign-out in the
// box holds until the next open.
const SIGN_IN_EVERY_MS = 60_000;
let signInTimer = null;
// A sign-in outcome, as the notice and the who popover say it. `mixed`: a
// box with file shares or Sluse Inputs beside the cloud, which go on
// reading (Q8).
const SI = {
  retrying: { title: 'Sluse is not signed in.', text: 'Your box is open, but Sluse cannot read files for it until it is. Sluse tries again every minute.',
    mixed: 'Your box is open. Sluse goes on reading from {local}, but SharePoint and OneDrive wait until it is signed in. Sluse tries again every minute.' },
  'needs-you': { title: 'Microsoft needs you to sign in again.', close: true,
    text: 'Your box is open, but Sluse cannot read files for it until you do. Close the box and open Sluse again to sign in.',
    mixed: 'Your box is open. Sluse goes on reading from {local}, but SharePoint and OneDrive wait until you have signed in. Close the box and open Sluse again to sign in.' },
  'closed-window': { title: 'You closed the sign-in window.', close: true,
    text: 'Your box is open, but Sluse cannot read files for it until you are signed in. Close the box and open Sluse again to sign in.',
    mixed: 'Your box is open. Sluse goes on reading from {local}, but SharePoint and OneDrive wait until you are signed in. Close the box and open Sluse again to sign in.' },
  timeout: { title: "Microsoft's sign-in did not answer.", text: 'Your box is open, but Sluse cannot read files for it until you are signed in. Sluse tries again every minute.',
    mixed: 'Your box is open. Sluse goes on reading from {local}, but SharePoint and OneDrive wait until you are signed in. Sluse tries again every minute.' },
  'entra-error': { title: 'Microsoft did not let Sluse sign you in.', text: `Your box is open, but Sluse cannot read files for it. ${IT}`,
    mixed: `Your box is open. Sluse goes on reading from {local}, but cannot read from SharePoint or OneDrive. ${IT}` },
  'service-lost': { title: "Sluse lost contact with this computer's part of Sluse.", pill: 'unknown', pillText: 'Not known', popTitle: 'Sign-in unknown',
    text: 'Your box is open, but Sluse cannot tell whether it can read files for it. Sluse tries again every minute.' },
  'signed-out': { title: 'You signed out.', kind: 'info', close: true, noDetails: true, pill: 'signed-out', pillText: 'Signed out', popTitle: 'You signed out',
    text: 'Sluse reads no files for it until you sign in again. To sign in, close the box and open Sluse again.',
    mixed: 'Sluse goes on reading from {local}, but not from SharePoint or OneDrive until you sign in again. To sign in, close the box and open Sluse again.' },
};
let signState = { cause: 'ok' };

function signInCause(f) {
  if (f.code === 'signedOut') return 'signed-out';
  if (f.code !== 'signIn') return 'service-lost';
  const m = f.message;
  return /needs you/.test(m) ? 'needs-you' : /window was closed|not finished/.test(m) ? 'closed-window'
    : /did not answer/.test(m) ? 'timeout' : /AADSTS/.test(m) ? 'entra-error' : 'retrying';
}

const identity = () => (!facts.entra ? 'windows' : box?.shares || box?.inputs ? 'mixed' : 'entra');
const local = () => `file shares${box?.inputs ? ' and Sluse Inputs' : ''}`;
const siText = (s) => (identity() === 'mixed' && s.mixed ? s.mixed.replace('{local}', local()) : s.text);
const siKind = (s) => s.kind ?? (identity() === 'mixed' && s.mixed ? 'warning' : 'problem');

// `mayAsk` on the first ask after an open (D-066): an open's sign-in that
// grew too old during a build left the box unbound, and Microsoft's page
// is shown then; every later ask is silent.
async function keepSignedIn(mayAsk = false) {
  clearTimeout(signInTimer);
  if (!viewer) return;
  try {
    const user = await invoke('keep_signed_in', { mayAsk });
    if (user) facts.user = user;
    signState = { cause: 'ok' };
    slog('sign-in:', user ? `signed in as ${user}` : 'already signed in', mayAsk ? '(may ask)' : '');
  } catch (e) {
    const f = asFailure(e);
    signState = { cause: signInCause(f), raw: details(f.code, f.message, null) };
    slog('sign-in: not signed in:', f.code ?? '-', f.message ?? '');
  }
  renderWho();
  renderNotices();
  edges();
  // Nothing to try after a sign-out in the box until the next open.
  if (signState.cause !== 'signed-out') signInTimer = setTimeout(keepSignedIn, SIGN_IN_EVERY_MS);
}

function pill(status, text) {
  const p = Object.assign(document.createElement('span'), { className: 'pill', textContent: text });
  p.dataset.status = status;
  return p;
}

function fact(term, value, mono) {
  const d = document.createElement('div');
  d.append(Object.assign(document.createElement('dt'), { textContent: term }));
  const dd = document.createElement('dd');
  if (mono) dd.className = 'mono';
  dd.append(value);
  d.append(dd);
  return d;
}

const SCOPE = 'Through Sluse, your box can read a file only if you may open it yourself, from the sources your IT department chose.';
function renderWho() {
  const idn = identity();
  const val = $('who-value');
  const p = (text, cls) => Object.assign(document.createElement('p'), { textContent: text, className: cls ?? '' });
  const dl = (...rows) => {
    const l = Object.assign(document.createElement('dl'), { className: 'facts' });
    l.append(...rows);
    return l;
  };
  const shares = () => fact(`File shares${box?.inputs ? ' and Sluse Inputs' : ''}, as your Windows account`, facts.windows_user ?? '', true);
  val.classList.toggle('mono', idn === 'windows');
  if (idn === 'windows') {
    val.textContent = facts.windows_user ?? '';
    $('who-title').textContent = 'Sluse reads files as your Windows account';
    $('who-body').replaceChildren(dl(fact('Windows account on this computer', facts.windows_user ?? '', true)),
      p("Sluse reads files as your Windows account on this computer. This box's sources need no Microsoft sign-in."),
      p(`${SCOPE} Closing the box stops it.`, 't-muted'));
  } else if (signState.cause === 'ok' && facts.user) {
    val.textContent = facts.user;
    $('who-title').textContent = 'Sluse reads files as you';
    const checked = new Date().toTimeString().slice(0, 5);
    $('who-body').replaceChildren(dl(fact('Signed in to Microsoft as', facts.user), ...(idn === 'mixed' ? [shares()] : []),
      fact('Last checked', `${checked}. Sluse checks every minute.`)),
    p(`${SCOPE} Closing the box signs Sluse out. So does Sign out, until you open Sluse again.`, 't-muted'),
    btnRow(button('Sign out…', { icon: 'sign-out', cls: 'btn--sm', run: askSignOut })));
  } else {
    const s = SI[signState.cause] ?? SI.retrying;
    const mark = () => pill(s.pill ?? 'signed-out', s.pillText ?? 'Not signed in');
    val.classList.remove('mono');
    const acct = Object.assign(document.createElement('span'), { className: 'mono who__acct', textContent: facts.windows_user ?? '' });
    acct.append(Object.assign(document.createElement('span'), { className: 'visually-hidden', textContent: ', ' }));
    val.replaceChildren(...(idn === 'mixed' ? [acct, mark()] : [mark()]));
    $('who-title').textContent = s.popTitle ?? 'Sluse is not signed in';
    const body = [];
    if (idn === 'mixed') body.push(dl(shares(), fact('Microsoft, for SharePoint and OneDrive', mark())));
    body.push(p(siText(s)));
    if (!s.noDetails && signState.raw) body.push(btnRow(button('Details', { icon: 'info', cls: 'btn--sm', run: signInDetails })));
    $('who-body').replaceChildren(...body);
  }
}

function btnRow(...buttons) {
  const row = Object.assign(document.createElement('div'), { className: 'btn-row' });
  row.append(...buttons);
  return row;
}

// The one Sign out (D-064): here in the bar, where nothing in the box can
// draw over it. It holds until the next open (Q7).
async function askSignOut() {
  $('who').open = false;
  $('signout-ask-d').textContent = identity() === 'mixed'
    ? `AI agents in your box stop reading from SharePoint and OneDrive as ${facts.user}. ${local()[0].toUpperCase()}${local().slice(1)} are still read as your Windows account. What is already in the box stays, and so does the record.`
    : `AI agents in your box stop reading files as ${facts.user}. What is already in the box stays, and so does the record.`;
  if (await ask('signout-ask') !== 'ok') return;
  try {
    await invoke('sign_out');
    clearTimeout(signInTimer);
    signState = { cause: 'signed-out' };
  } catch (e) {
    const f = asFailure(e);
    message('Sluse did not sign you out', `Try again. If it keeps happening, ${it}`, details(f.code, f.message, null));
  }
  renderWho();
  renderNotices();
  edges();
}

const signInDetails = () => message('Sign-in details', 'If this notice stays, send these details to your IT department.', signState.raw, { icon: null });

// ---- Notices: ordered by weight, folded behind a count ------------------
// The heaviest first; one strip shows, the rest behind "N more notices". A
// dismissed notice stays dismissed for this window (Q31).
const dismissed = new Set();
let unfold = false;
let shown = {};

function strip(id, kind, title, text, actions) {
  const b = Object.assign(document.createElement('div'), { className: 'banner banner--strip' });
  b.dataset.kind = kind;
  b.setAttribute('role', kind === 'problem' ? 'alert' : 'status');
  const body = Object.assign(document.createElement('div'), { className: 'banner__body' });
  body.append(Object.assign(document.createElement('span'), { className: 'banner__title', textContent: title }));
  if (text) body.append(Object.assign(document.createElement('span'), { className: 'banner__text', textContent: text }));
  const acts = Object.assign(document.createElement('div'), { className: 'banner__actions' });
  acts.append(...(actions ?? []));
  body.append(acts);
  const x = button('', { icon: 'close', cls: 'btn--quiet btn--icon btn--sm banner__close', run: () => { dismissed.add(id); renderNotices(); } });
  x.setAttribute('aria-label', 'Dismiss');
  b.append(body, x);
  return b;
}

const sm = (label, icon, cls, run) => button(label, { icon, cls: `btn--sm ${cls}`, run });

function renderNotices() {
  const out = [];
  const add = (id, sev, el) => { if (!dismissed.has(id)) out.push({ sev, el }); };
  if (signState.cause !== 'ok' && identity() !== 'windows') {
    const s = SI[signState.cause] ?? SI.retrying;
    const k = siKind(s);
    add('signin', { problem: 0, warning: 0.5, info: 3 }[k], strip('signin', k, s.title, siText(s), [
      ...(s.close ? [sm('Close the box', 'power', '', askClose)] : []),
      ...(!s.noDetails ? [sm('Details', 'info', '', signInDetails)] : []),
    ]));
  }
  const changes = shown.config ?? [];
  if (changes.length) {
    const names = { sources: 'what Sluse may read', egress: 'the sites your box may reach', settings: "Sluse's settings for this box" };
    const said = changes.map((c) => names[c]).filter(Boolean);
    const list = said.length > 1 ? `${said.slice(0, -1).join(', ')} and ${said.at(-1)}` : said[0] ?? '';
    const src = changes.includes('sources');
    add('config', src ? 1 : 4, strip('config', src ? 'warning' : 'info', `Your IT department changed ${list}.`,
      src ? 'Files already in your box stay there.' : '', src ? [sm('Wipe the box…', 'wipe', 'btn--destructive', () => askWipe(true))] : []));
  }
  if (box?.problem) add('build', 2, strip('build', 'info', 'An update for your box could not be prepared.', 'Your box works as before. Sluse tries again by itself and when the computer restarts.'));
  if (facts.keyboard_fallback != null) {
    add('keyboard', 3, strip('keyboard', 'info', `Your box does not know your keyboard layout${facts.keyboard_fallback ? `, ${facts.keyboard_fallback}` : ''}.`,
      'It uses US English, so some keys may type other characters.'));
  }
  if (box?.update) add('update', 5, strip('update', 'info', 'An update for your box is ready.', "Resetting the box's system applies it, and your files stay.",
    [sm("Reset the box's system…", 'reset', '', () => askReset(true))]));
  const od = shown.onedrive;
  if (od === 'missing') add('onedrive', 6, strip('onedrive', 'info', 'Your box can read files from a folder named Sluse in your OneDrive.', 'The folder does not exist yet.', [sm('Create the folder', 'plus', '', createOneDrive)]));
  if (od === 'no-client') add('onedrive', 6, strip('onedrive', 'info', 'Your box can read files from a folder named Sluse in your OneDrive.', 'OneDrive is not set up on this computer, so create the folder at the top of your OneDrive on the web.', [sm('Open OneDrive', 'external', '', openOneDriveWeb)]));
  if (od === 'made') add('onedrive', 6, strip('onedrive', 'info', 'Created the Sluse folder in your OneDrive.', 'Files you put in it reach your box once OneDrive has synced the folder.'));
  out.sort((a, b) => a.sev - b.sev);
  const showing = unfold ? out : out.slice(0, 1);
  if (out.length > 1) {
    const more = out.length - 1;
    const fold = sm(unfold ? 'Show fewer notices' : `${more} more notice${more === 1 ? '' : 's'}`, unfold ? 'chevron-up' : 'chevron-down', 'btn--quiet', () => { unfold = !unfold; renderNotices(); });
    fold.setAttribute('aria-expanded', String(unfold));
    showing[0].el.querySelector('.banner__actions').append(fold);
  }
  $('notices').replaceChildren(...showing.map((n) => n.el));
}

// ---- Dialogs ------------------------------------------------------------
/** Open a native dialog; resolves with the button's value. */
function ask(id) {
  return new Promise((resolve) => {
    const d = $(id);
    for (const m of document.querySelectorAll('details.menu[open]')) m.open = false;
    d.returnValue = '';
    d.onclose = () => resolve(d.returnValue);
    d.showModal();
  });
}

/** What alert() was: a title, a sentence, and the raw text for IT. */
function message(title, text, raw, { icon = 'problem', address = false } = {}) {
  $('message-t').textContent = title;
  $('message-text').textContent = text;
  $('message-raw').textContent = raw;
  $('message-address').hidden = !address;
  $('message-icon')?.toggleAttribute('hidden', !icon);
  return ask('message');
}
$('copy-message').onclick = () => copyText($('copy-message'), $('message-raw').textContent);
$('copy-address').onclick = () => clip.writeText('https://www.microsoft365.com/onedrive').catch(() => {});

// Close the box always asks first (Q27), from the bar or a notice.
async function askClose() {
  if (await ask('close-ask') === 'ok') closeBox();
}
async function askReset(update = false) {
  $('reset-update').hidden = !update;
  if (await ask('reset-ask') === 'ok') reset(false);
}
async function askWipe(config = false) {
  $('wipe-config').hidden = !config;
  if (await ask('wipe-ask') === 'ok') reset(true);
}

// ---- Opening, resetting, closing ----------------------------------------
// The theme in use, carried into the box at each open and at every change
// (Q70). A change during an open is refused as busy, and sent once the box
// is up. One at a time, the latest last: two quick switches landed out of
// order, or the second was refused as busy and never sent (L1, 2026-10-21).
let sentTheme = null;
let sendingTheme = false;
async function sendTheme() {
  if (sendingTheme) return;
  sendingTheme = true;
  for (let tries = 0, theme; viewer && tries < 5 && (theme = window.sluseTheme()) !== sentTheme; tries++) {
    try {
      await invoke('set_theme', { theme });
      sentTheme = theme;
      tries = -1;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  sendingTheme = false;
}
document.addEventListener('sluse-theme', sendTheme);

// Sluse Inputs is offered in every state (Q17), so before this open's
// answer says whether the config has it, the last answer does.
// ponytail: a first open on this computer learns it at Ready.
function offerInputs(has) {
  $('inputs').hidden = !has;
  try { localStorage.setItem('sluse.inputs', has ? '1' : ''); } catch { /* storage refused */ }
}
try { $('inputs').hidden = !localStorage.getItem('sluse.inputs'); } catch { /* storage refused */ }

async function open(carryOn = false) {
  const mine = ++opening;
  if (!carryOn || !att) begin('open');
  wait(carryOn ? undefined : 'Opening your box…');
  await getFacts();
  try {
    sentTheme = window.sluseTheme();
    box = await invoke('open_box', { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, theme: sentTheme });
    // The person quit, and the box came up anyway: it is closed (Q26).
    if (quitting) { await invoke('close_box').catch(() => {}); quit('the box came up after a Quit, closed'); return; }
    offerInputs(box.inputs);
    $('ms-window').hidden = $('ms-window-sep').hidden = !box.sign_in_window;
    await getFacts();
    // Said once per window: the config notice names what changed, the wipe
    // only when what Sluse may read did (D-038 point 4, D-045 point 3, Q31).
    if (shown.config === undefined) shown.config = box.config_changes?.length ? box.config_changes : box.config_changed ? ['sources'] : [];
    signState = facts.signed_out ? { cause: 'signed-out' } : { cause: 'ok' };
    renderWho();
    renderNotices();
    if (box.onedrive) invoke('onedrive_folder', { create: false }).then((s) => { shown.onedrive = s; renderNotices(); }, () => {});
    // The wait stays over the box until its console answers (Q9); past its
    // limit the box is running, and closing it is what is offered.
    slog('open: ready');
    // The steps after the service's: the viewer, then the console, so the
    // wait never shows the screen's step once the screen answered (D-066).
    progress({ step: NAME.connect, phase: 'connect' });
    consoleUp = invoke('wait_for_console');
    consoleUp.then(() => slog('console: answered'), () => {});
    consoleUp.catch((e) => {
      if (mine !== opening || !viewer) return;
      stopViewer();
      failed(e, 'open');
    });
    tries = 0;
    connect();
    keepSignedIn(true);
    sendTheme();
  } catch (e) {
    failed(e);
  }
}

let resetting = false;
async function reset(wipe) {
  // One at a time; the service refuses a second one as well.
  if (resetting) return;
  resetting = true;
  stopViewer();
  begin(wipe ? 'wipe' : 'reset');
  wait(wipe ? 'Wiping the box…' : 'Resetting the box\'s system…');
  try {
    await invoke('reset_box', { wipe });
    resetting = false;
    // Quit during the reset's build: it is done, and the box stays closed.
    if (quitting) {
      notify('built', 'Your box\'s system is ready', 'Sluse has finished preparing it. Open Sluse to start your box.', [OPEN]);
      quit('the reset finished after a Quit');
      return;
    }
    await open(true);
  } catch (e) {
    resetting = false;
    failed(e);
  }
}

// How long the last words stay before the window goes (D-034 point 6).
const CLOSED_MS = 2000;

async function closeBox() {
  slog('close: the box, as asked in the window');
  stopViewer();
  begin('close');
  show('closing', 'Closing your box…');
  try {
    await invoke('close_box');
    invoke('withdraw', { tags: ['open', 'left'] }).catch(() => {});
    show('closed');
    setTimeout(() => quit('the box is closed'), CLOSED_MS);
  } catch (e) {
    const f = asFailure(e);
    failed(f.code === 'busy' ? f : { ...f, code: 'closeFailed' }, 'close');
  }
}

// ---- The bar's buttons ----------------------------------------------------
// Explorer takes a moment to show, and each click opens another window: busy
// for a while after it (L1, 2026-10-06). A folder that will not open is no
// reason to hide the box.
const FOLDER = { artifacts: 'Sluse Artifacts', inputs: 'Sluse Inputs' };
function openFolder(which) {
  const b = $(which);
  if (b.getAttribute('aria-busy') === 'true') return;
  b.setAttribute('aria-busy', 'true');
  b.disabled = true;
  const done = () => { b.removeAttribute('aria-busy'); b.disabled = false; };
  invoke('open_folder', { which }).then(() => setTimeout(done, 2000), (e) => {
    done();
    message(`${FOLDER[which]} did not open`, 'Sluse could not open the folder in File Explorer. If it keeps happening, send the details to your IT department.',
      details('folder', String(e), null));
  });
}
$('artifacts').onclick = () => openFolder('artifacts');
$('inputs').onclick = () => openFolder('inputs');
$('close').onclick = askClose;
$('reset').onclick = () => askReset();

// ---- A Microsoft sign-in, five minutes, the person's (D-075) -----------
// Opened only here, never from the box; the Gate closes it on time
// whatever this window does, and this countdown only says so.
const MS_WINDOW_MS = 5 * 60 * 1000;
let msUntil = 0;
let msTimer = null;
function msTick() {
  const left = Math.max(0, Math.round((msUntil - Date.now()) / 1000));
  if (!left || state() !== 'running') {
    msUntil = 0;
    clearInterval(msTimer);
    msTimer = null;
    $('ms-open').hidden = true;
    return;
  }
  $('ms-open-text').textContent = `Microsoft sign-in allowed, ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} left`;
  $('ms-open').hidden = false;
}
async function allowMsSignIn() {
  $('more').open = false;
  // The account by its address where Sluse is signed in (copy review C-02).
  $('ms-window-who').textContent = facts.entra && facts.user ? `your Microsoft account, ${facts.user}` : "your organisation's Microsoft account";
  if (await ask('ms-window-ask') !== 'ok') return;
  try {
    await invoke('sign_in_window', { close: false });
    slog('sign-in window: opened, five minutes');
    msUntil = Date.now() + MS_WINDOW_MS;
    clearInterval(msTimer);
    msTimer = setInterval(msTick, 1000);
    msTick();
  } catch (e) {
    const f = asFailure(e);
    message('Sluse did not allow the sign-in', f.code === 'notAllowed' ? f.message : `Try again. If it keeps happening, ${it}`, details(f.code, f.message, null));
  }
}
async function closeMsSignIn() {
  try {
    await invoke('sign_in_window', { close: true });
    slog('sign-in window: closed by the person');
  } catch { /* it closes on time anyway */ }
  msUntil = 0;
  msTick();
}
$('ms-window').onclick = allowMsSignIn;
$('ms-close').onclick = closeMsSignIn;
$('wipe').onclick = () => askWipe();

// The user's OneDrive Sluse folder (D-054): offered while it is missing, made
// by the user's own click, through the OneDrive client on this computer.
function createOneDrive() {
  invoke('onedrive_folder', { create: true }).then(() => { shown.onedrive = 'made'; renderNotices(); }, (e) =>
    message('The Sluse folder was not created', 'Sluse could not create it in your OneDrive. You can make a folder named Sluse at the top of your OneDrive yourself.',
      details('onedrive', String(e), null)));
}
function openOneDriveWeb() {
  invoke('open_onedrive_web').catch((e) =>
    message('OneDrive did not open', 'Sluse could not open your web browser. You can open this address in it yourself:', details('browser', String(e), null), { address: true }));
}

// ---- The window's X (D-034 point 5) ---------------------------------------
// Asked by the shell's Rust, which closes on a second X within 5 s whatever
// this page does, and closes the box with it while it is on screen (Q29).
// Quit never leaves a box running that this window opened (Q26, Q75): the
// service finishes a build and leaves the box closed.
const LEAVE = {
  'sign-in': ['Sluse has not started opening your box', 'Sluse is still signing you in. If you quit now, your box does not open, and opening Sluse again starts over.'],
  build: ["Your box's system is still being prepared", "If you quit, Sluse finishes preparing it without this window and leaves your box closed. Windows tells you when it is ready. Your box starts the next time you open Sluse."],
  open: ['Your box is still opening', 'If you quit, Sluse stops opening it and leaves your box closed. Your files stay. Opening Sluse again starts over.'],
  reset: ["Your box's system is still being reset", 'The reset finishes without this window and leaves your box closed. Your box starts the next time you open Sluse.'],
  wipe: ['Your box is still being wiped', 'The wipe finishes without this window and leaves your box closed. Your box starts the next time you open Sluse.'],
  close: ['Your box is still closing', 'It finishes closing without this window.'],
};

function leaveText() {
  const idn = identity();
  return idn === 'windows' ? 'Left running, your box goes on reading files as your Windows account until you close it. Opening Sluse again takes you straight back to it.'
    : 'Left running, your box goes on reading files as you until you close it. Opening Sluse again takes you straight back to it.';
}

listen('close-requested', async () => {
  const s = state();
  if ($('leave').open) return;
  if (s === 'running') {
    $('leave-title').textContent = 'Close your box, or leave it running?';
    $('leave-text').textContent = leaveText();
    $('leave-more').textContent = 'Closed, it stops and its apps close. Your files stay either way.';
    $('leave-more').hidden = false;
    $('leave-keep').textContent = 'Leave it running';
    $('leave-close').textContent = 'Close the box';
    $('leave-cancel').hidden = false;
  } else if (s === 'waiting' || s === 'closing') {
    const phase = att?.cur?.phase;
    const which = att?.kind === 'close' ? 'close' : phase === 'sign-in' ? 'sign-in'
      : (att?.kind === 'reset' || att?.kind === 'wipe') && !OPENING.includes(phase) ? att.kind
        : BUILD.includes(phase) ? 'build' : 'open';
    [$('leave-title').textContent, $('leave-text').textContent] = LEAVE[which];
    $('leave-more').hidden = true;
    $('leave-keep').textContent = 'Quit';
    // Keep waiting is the cancel here, and the default.
    $('leave-close').textContent = 'Keep waiting';
    $('leave-cancel').hidden = true;
  } else {
    quit(`the X, with no box open (${s})`);
    return;
  }
  const v = await ask('leave');
  if (s === 'running' && v === 'close') closeBox();
  else if (s === 'running' && v === 'leave') {
    // Left running: the window goes, Sluse stays in the tray.
    notify('left', 'Your box is still running', 'Sluse goes on reading files for it as you until you close it. Sluse is in the notification area.', [OPEN, CLOSE]);
    invoke('leave');
  } else if (v === 'leave') {
    // Quit: the service is told to leave the box closed; during a build the
    // process stays in the tray until it is done (Q26, Q75).
    quitting = building();
    invoke('quit_open', { building: quitting });
    edges();
  }
});

// ---- A file dragged onto the window ---------------------------------------
// It is answered with where files go; nothing is copied (D-025: no file
// channel). The window has no drop handling of its own (`dragDropEnabled`).
const dropText = () => (box?.inputs ? 'Put the file in Sluse Inputs, and your box can read it from there.'
  : box?.onedrive ? 'Put the file in the Sluse folder in your OneDrive, and your box can read it once OneDrive has synced it.'
    : 'Sluse lets files into your box only from the sources your IT department chose.');
document.addEventListener('dragover', (e) => {
  e.preventDefault();
  if (state() !== 'running' || !$('drag').hidden) return;
  $('drop-text').textContent = dropText();
  $('drag').removeAttribute('data-dropped');
  $('drag').hidden = false;
});
document.addEventListener('dragleave', (e) => { if (!e.relatedTarget && !$('drag').hasAttribute('data-dropped')) $('drag').hidden = true; });
document.addEventListener('drop', (e) => {
  e.preventDefault();
  if (state() !== 'running') return;
  $('drag').setAttribute('data-dropped', '');
  $('drop-inputs').hidden = !box?.inputs;
  $('drop-dismiss').focus();
});
$('drop-dismiss').onclick = () => { $('drag').hidden = true; viewer?.focus(); };
$('drop-inputs').onclick = () => { $('drag').hidden = true; openFolder('inputs'); };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('drag').hasAttribute('data-dropped')) $('drop-dismiss').click(); });

$('copy-stuck').onclick = () => copyText($('copy-stuck'), stuckText);
$('copy').onclick = () => copyText($('copy'), lastRaw);

open();
