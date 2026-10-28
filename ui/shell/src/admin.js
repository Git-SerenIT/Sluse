// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Sluse Admin's screens (D-039 slice 6, D-062 slice 6), drawn as
// docs/design/mockups/admin/ draws them. Every action is a command in
// src-tauri/src/admin.rs over sluse-admin; this page holds the admin's
// choices and draws them. Text from Graph and from files is set as text,
// never as markup. Errors stay in the step that made them, with the raw
// text under "For whoever supports Sluse".

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// ---- Helpers --------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const kids = (k) => k.flat(9).filter((x) => x != null && x !== false && x !== '');
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (k === 'class') n.className = v;
    else n.setAttribute(k, v === true ? '' : String(v));
  }
  n.append(...kids(children));
  return n;
}
const fill = (node, ...children) => { node.replaceChildren(...kids(children)); return node; };
const icon = (name, cls) => el('i', { 'data-icon': name, class: cls });
const mono = (t) => el('span', { class: 'mono' }, t);
const b = (t) => el('b', {}, t);
const pill = (status, text) => el('span', { class: 'pill', 'data-status': status }, text);
const status = (kind, ...t) => el('p', { class: 'status', 'data-status': kind }, ...t);
const note = (kind, ...t) => el('p', { class: 'note', 'data-kind': kind }, el('span', {}, ...t));
const chip = (text, label, copy) => el('span', { class: 'chip-mono', title: text },
  el('code', {}, text), el('button', { class: 'chip-mono__copy', type: 'button', 'data-copy': copy ?? text, 'aria-label': label }, icon('copy')));
const tech = (raw, label = 'For whoever supports Sluse') => el('div', { class: 'techdetails' },
  el('div', { class: 'techdetails__bar' }, el('span', { class: 't-label' }, label), el('button', { class: 'btn btn--sm btn--quiet', type: 'button', 'data-copy': raw }, 'Copy details')),
  el('pre', {}, raw));
function banner(kind, title, text, { raw, actions, more, label } = {}) {
  return el('div', { class: 'banner', 'data-kind': kind, role: kind === 'info' ? 'status' : 'alert' },
    el('div', { class: 'banner__body' },
      el('p', { class: 'banner__title' }, title), text ? el('p', { class: 'banner__text' }, text) : null, more,
      actions?.length ? el('div', { class: 'banner__actions' }, actions) : null,
      raw ? tech(raw, label) : null));
}
const btn = (label, onclick, { cls = '', ico, busy, disabled } = {}) =>
  el('button', { class: `btn ${cls}`.trim(), type: 'button', onclick, 'aria-busy': busy ? 'true' : null, disabled }, ico ? icon(ico) : null, label);
const goBtn = (label, step, cls = 'btn--sm') => el('button', { class: `btn ${cls}`, type: 'button', 'data-go': step }, label);
const diffLine = (sign, text, p) => el('li', {}, el('span', { class: 'diff__sign' }, sign), el('span', {}, text), p);
const goesStays = (goes, stays) => el('div', { class: 'consequences' },
  el('div', { class: 'consequences__col consequences__col--goes' }, el('h3', {}, icon('wipe'), 'Goes'), el('ul', {}, goes.map((g) => el('li', {}, g)))),
  el('div', { class: 'consequences__col' }, el('h3', {}, icon('check'), 'Stays'), el('ul', {}, stays.map((s) => el('li', {}, s)))));

const hhmm = (d = new Date()) => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
const day = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
const mmss = (ms) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
const clock = (since) => mmss(Date.now() - since);
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
/** 60 seconds, 10 minutes, 1 minute 30 seconds (Q52). */
function inWords(s) {
  if (s < 60) return plural(s, 'second');
  const m = Math.floor(s / 60), r = s % 60;
  return plural(m, 'minute') + (r ? ` ${plural(r, 'second')}` : '');
}
const base = (p) => String(p).split(/[\\/]/).pop();
const dir = (p) => String(p).slice(0, String(p).length - base(p).length).replace(/[\\/]$/, '');
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32) || 'source';
const expired = (e) => /: 401\b/.test(String(e));

const clip = (text) => invoke('plugin:clipboard-manager|write_text', { text });
const dialog = {
  open: (filters, directory = false) => invoke('plugin:dialog|open', { options: { multiple: false, directory, filters } }),
  save: (defaultPath, filters) => invoke('plugin:dialog|save', { options: { defaultPath, filters } }),
};
const JSON_FILTER = [{ name: 'Sluse configuration', extensions: ['json'] }];

function toast(text, action) {
  const t = el('div', { class: 'toast', 'data-kind': 'done', 'data-entering': '' }, el('span', { style: 'flex:1' }, text),
    action ? el('button', { class: 'btn btn--sm', type: 'button', onclick: () => { action.fn(); t.remove(); } }, action.label) : null,
    el('button', { class: 'btn btn--sm btn--icon', type: 'button', 'aria-label': 'Dismiss', onclick: () => t.remove() }, icon('close')));
  $('toasts').append(t);
  setTimeout(() => t.removeAttribute('data-entering'), 400);
  setTimeout(() => t.remove(), action ? 8000 : 4000);
}

// A fault in the page itself is said and logged, never left as a turning
// ring: an exception while drawing stopped Make or repair before it asked
// anything (L1, 2026-10-28).
function fault(e) {
  const text = String(e?.message ?? e);
  invoke('shell_log', { line: `${new Date().toISOString()} admin page: ${e?.stack ?? text}` }).catch(() => {});
  problemToast(`Sluse Admin's page hit an error: ${text}. Close Sluse Admin and open it again. If it comes back, send us this text and shell.log.`);
}
/** A problem stays until dismissed: unlike a toast, it must be read. */
function problemToast(text) {
  const t = el('div', { class: 'toast', 'data-kind': 'problem' }, el('span', { style: 'flex:1' }, text),
    el('button', { class: 'btn btn--sm btn--icon', type: 'button', 'aria-label': 'Dismiss', onclick: () => t.remove() }, icon('close')));
  $('toasts').append(t);
}
window.addEventListener('error', (e) => fault(e.error ?? e.message));
window.addEventListener('unhandledrejection', (e) => fault(e.reason));

/** One question in the window's dialog; resolves with the button's value. */
function ask({ ico = 'warning', title, body, actions, destructive = false }) {
  const d = $('dlg-ask');
  d.classList.toggle('dialog--destructive', destructive);
  fill($('dlg-ask-head'), icon(ico), el('h2', { class: 'dialog__title', id: 'dlg-ask-t' }, title));
  fill($('dlg-ask-body'), body);
  fill($('dlg-ask-actions'), actions.map(([value, label, cls = '', ico2], i) =>
    el('button', { class: `btn ${cls}`.trim(), value, autofocus: i === 0 }, ico2 ? icon(ico2) : null, label)));
  return show(d);
}
function show(d) {
  return new Promise((resolve) => {
    for (const m of document.querySelectorAll('details.menu[open]')) m.open = false;
    d.returnValue = '';
    d.onclose = () => resolve(d.returnValue);
    d.showModal();
  });
}

// ---- What the admin has chosen, and where the window is -----------------------
const STEPS = [['start', 'Start'], ['tenant', 'Tenant'], ['sources', 'Sources'], ['egress', 'Egress'], ['advanced', 'Advanced'], ['review', 'Review'], ['publish', 'Publish']];
const LEVELS = [[1, 'Public'], [2, 'Internal'], [3, 'Confidential'], [4, 'Highly confidential']];
const USER_KINDS = ['onedrive', 'inputs'];
const S = {
  step: 'start',
  visited: new Set(['start']),
  who: null, // { tenant, account, tenantName }
  expiredAt: null,
  picked: false, // the next sign-in opens Microsoft's account picker (Q82)
  signing: null, // { since, pick, window }
  startError: null,
  roles: null, rolesError: null,
  file: null, // { path, authored }: the deployment this window continues
  fileError: null,
  saved: null, // { at, revision }: the last save in this window
  baseline: '', baselineAt: new Date(),
  draftId: crypto.randomUUID(),
  app: { state: 'none' }, // none | not-signed-in | running | ready | problem
  consent: { state: 'idle' }, // idle | waiting | granted | error
  assigned: { state: 'before', list: [] }, // before | loading | read | error
  inWindow: new Map(), // group id: when it was assigned in this window
  people: { state: 'idle', found: [], shown: 50 },
  assign: { state: 'idle' },
  sources: [],
  catalog: null, catalogError: null,
  bundles: new Set(),
  review: { verdict: 'none' },
  msi: null,
  save: { state: 'idle' },
  pub: { what: 'here', state: 'idle', groups: null, shown: 50 },
};

const fileDeployment = () => S.file?.authored?.deployment ?? null;
const tenantId = () => S.file?.authored?.entra?.tenantId ?? S.who?.tenant ?? null;
const tenantWord = () => (S.who && (!S.file?.authored?.entra || S.who.tenant === tenantId()) ? S.who.tenantName : null);
const mismatch = () => !!(S.who && S.file?.authored?.entra?.tenantId && S.file.authored.entra.tenantId !== S.who.tenant);
/** Sluse's app: made in this window, in this file's tenant, or the file's. */
const clientId = () => (S.app.result && !mismatch() ? S.app.result.appId : S.file?.authored?.entra?.clientId ?? null);
const depName = () => $('dep-name').value.trim();
const nextRevision = () => (fileDeployment()?.revision ?? 0) + 1;

// ---- The configuration, from the page -------------------------------------------
function allowList() {
  const out = [];
  const add = (h) => { if (h && !out.includes(h)) out.push(h); };
  for (const bd of S.catalog?.bundles ?? []) if (bd.locked || S.bundles.has(bd.id)) bd.hosts.forEach(add);
  ownHosts().forEach(add);
  return out;
}
const ownHosts = () => $('own-hosts').value.split('\n').map((h) => h.trim().toLowerCase()).filter(Boolean);
const num = (id) => { const v = $(id).value.trim(); return v === '' ? undefined : Number(v); };
const radio = (name) => Number(document.querySelector(`input[name="${name}"]:checked`)?.value);

function authored() {
  if (!S.catalog) throw new Error('the bundle catalog was not read');
  const dep = fileDeployment();
  const mb = (id) => { const v = num(id); return v == null ? undefined : v * 1048576; };
  const a = {
    schemaVersion: 3,
    deployment: { id: dep?.id ?? S.draftId, name: depName(), revision: (dep?.revision ?? 0) + 1 },
    entra: { tenantId: tenantId(), clientId: clientId() },
    sources: S.sources.map(({ name, kind, scope, sensitivity }) => ({ name, kind, scope, sensitivity })),
    volume: { admissions: num('v-files'), windowSeconds: num('v-window'), bytes: mb('v-mb') },
    maxFetchBytes: mb('fetch-mb'),
    egress: {
      catalog: S.catalog.version,
      bundles: S.catalog.bundles.filter((bd) => !bd.locked && S.bundles.has(bd.id)).map((bd) => bd.id),
      allow: allowList(),
      log: $('egress-log').checked ? { enabled: true, maxMB: num('egress-mb') } : undefined,
    },
    box: { memoryGB: radio('mem'), homeGB: radio('disk'), copyOut: $('copy-out').checked },
    accounts: accountsFromForm(),
  };
  if (!a.entra.tenantId || !a.entra.clientId) delete a.entra;
  return JSON.parse(JSON.stringify(a));
}

/** The runtimes' accounts (D-072), from the Advanced step; absent when empty. */
const words = (id) => $(id).value.split(/[\s,]+/).map((w) => w.trim()).filter(Boolean);
function accountsFromForm() {
  const a = { chatgptWorkspaces: words('acc-workspaces'), claudeOrganisation: $('acc-claude').value.trim() || undefined };
  return a.chatgptWorkspaces.length || a.claudeOrganisation ? a : undefined;
}

/** The choices, by step, to tell unsaved work and which steps it touched. */
function snapshot() {
  return {
    Sources: JSON.stringify([depName(), S.sources.map(({ name, kind, scope, sensitivity }) => [name, kind, scope, sensitivity])]),
    Egress: JSON.stringify([[...S.bundles].sort(), $('own-hosts').value]),
    Advanced: JSON.stringify(['v-files', 'v-mb', 'v-window', 'fetch-mb', 'egress-mb', 'acc-workspaces', 'acc-claude'].map((id) => $(id).value)
      .concat([radio('mem'), radio('disk'), $('copy-out').checked, $('egress-log').checked])),
  };
}
const changedSteps = () => { const now = snapshot(), was = JSON.parse(S.baseline || '{}'); return Object.keys(now).filter((k) => now[k] !== was[k]); };
const dirty = () => changedSteps().length > 0;
function setBaseline() { S.baseline = JSON.stringify(snapshot()); S.baselineAt = new Date(); }
/** After any change of the choices: the rail, the bar, the guard on X. */
function changed() {
  drawTop(); drawRail(); drawFoot();
  invoke('admin_guard', { on: dirty() || S.pub.state === 'publishing' }).catch(() => {});
}

// ---- Navigation ------------------------------------------------------------------
function go(step) {
  if (S.step === 'tenant' && step !== 'tenant') pauseConsent();
  const back = S.step !== step && step === 'tenant';
  S.step = step;
  S.visited.add(step);
  for (const s of document.querySelectorAll('section[data-step]')) s.hidden = s.dataset.step !== step;
  $('scroll').scrollTop = 0;
  if (step === 'tenant' && back) returnToTenant();
  if (step === 'egress') drawEgress();
  if (step === 'review') runReview();
  if (step === 'publish') drawPublish();
  draw();
}

function drawRail() {
  const lines = railLines();
  const word = { done: 'done', warning: 'has things to know', problem: 'has a problem' };
  fill($('rail'), STEPS.map(([id, name]) => {
    const [sum, flag] = lines[id];
    return el('li', { class: 'stepper__item', 'data-flag': flag || null },
      el('button', { class: 'stepper__btn', type: 'button', 'data-go': id, 'aria-current': S.step === id ? 'step' : null, 'aria-label': `${name}: ${sum}${flag ? `, ${word[flag]}` : ''}` },
        el('span', { class: 'stepper__text' }, el('span', { class: 'stepper__name' }, name), el('span', { class: 'stepper__sum' }, sum))));
  }));
}

/** What the rail says under each step: [summary, flag], from the page's own state. */
function railLines() {
  const dep = fileDeployment();
  const groups = S.assigned.state === 'read' ? S.assigned.list.length : null;
  const tenant = S.app.state === 'ready'
    ? S.consent.state === 'granted'
      ? [`App ready, consent granted, ${groups == null ? 'groups not read' : groups ? plural(groups, 'group') : 'no group'}`, groups === 0 ? 'warning' : groups ? 'done' : '']
      : S.consent.state === 'waiting' && S.step !== 'tenant' ? ['Waiting for consent; checks again when you return', '']
        : S.consent.state === 'waiting' ? ['Waiting for consent', ''] : ['App ready, consent not checked', '']
    : S.app.state === 'problem' ? ["Sluse's app: a problem", 'problem']
      : clientId() ? ['From the file', 'done'] : S.who ? ['Not made in this window', ''] : ['Not checked', ''];
  const src = S.sources.filter((s) => !USER_KINDS.includes(s.kind.type)).length, uf = S.sources.length - src;
  const sources = S.sources.length ? [`${plural(src, 'source')}${uf ? `, ${plural(uf, 'user folder')}` : ''}`, S.visited.has('sources') || S.file ? 'done' : '']
    : ['No sources yet', ''];
  const bundles = (S.catalog?.bundles ?? []).filter((bd) => bd.locked || S.bundles.has(bd.id)).length;
  const egress = S.catalog ? [S.visited.has('egress') || S.file ? `${plural(bundles, 'bundle')}, ${plural(allowList().length, 'host')}` : `Defaults: ${plural(bundles, 'bundle')}`, S.visited.has('egress') || S.file ? 'done' : '']
    : ['The bundle catalog could not be read', 'problem'];
  const n = advancedChanges();
  const advanced = [n ? `${plural(n, 'change')} from the defaults` : 'Defaults', S.visited.has('advanced') || S.file ? 'done' : ''];
  const out = {
    start: S.who ? [S.who.account, 'done'] : dep ? [`Opened ${dep.name || 'a deployment'}, revision ${dep.revision}`, 'done'] : S.file ? ['Opened a configuration', 'done'] : ['Not signed in', ''],
    tenant, sources, egress, advanced,
    review: ['Not checked', ''],
    publish: S.pub.state === 'published' ? [`Published revision ${S.pub.revision}`, 'done']
      : S.saved && !dirty() ? [`Saved revision ${S.saved.revision}`, 'done'] : dep ? [`Saves revision ${dep.revision + 1}`, ''] : ['Not saved', ''],
  };
  const r = S.review;
  if (r.verdict === 'checking') out.review = ['Checking', ''];
  else if (r.verdict === 'accepted') {
    const k = knowCount();
    out.review = k ? [`Accepted, ${plural(k, 'thing')} to know`, 'warning'] : ['Accepted, nothing to know', 'done'];
    if (!S.saved || dirty()) out.publish[0] = out.publish[0] === 'Not saved' ? 'Ready to save' : out.publish[0];
  } else if (r.verdict === 'refused') {
    out.review = ['Refused', 'problem'];
    const why = refusal(r.error);
    if (why.step && out[why.step]) out[why.step] = [why.rail, 'problem'];
  }
  return out;
}
function advancedChanges() {
  let n = 0;
  if (num('v-files') !== 25 || num('v-window') !== 60 || num('v-mb') !== 50) n++;
  if (num('fetch-mb') != null) n++;
  if (radio('mem') !== 6) n++;
  if (radio('disk') !== 40) n++;
  if (!$('copy-out').checked) n++;
  if ($('egress-log').checked) n++;
  return n;
}

function drawFoot() {
  const i = STEPS.findIndex(([id]) => id === S.step);
  const prev = STEPS[i - 1], next = STEPS[i + 1];
  $('back').disabled = !prev;
  fill($('back').querySelector('span'), prev ? `Back: ${prev[1]}` : 'Back');
  $('next').hidden = !next;
  if (next) fill($('next').querySelector('span'), `Next: ${next[1]}`);
  const busy = (t) => [icon('spinner', 'icon--spinner'), ` ${t}`];
  const done = (t) => [icon('check'), ` ${t}`];
  fill($('foot-status'),
    S.pub.state === 'publishing' ? busy('Publishing to Intune…')
      : S.save.state === 'saving' ? busy('Saving…')
        : S.review.verdict === 'checking' ? busy('Checking the configuration…')
          : S.signing ? busy('Signing in…')
            : S.step === 'review' && S.review.at ? done(`Checked at ${hhmm(S.review.at)}.`)
              : S.step === 'publish' && S.pub.state === 'published' ? done(`Published revision ${S.pub.revision} at ${hhmm(S.pub.at)}.`)
                : S.step === 'publish' && S.saved ? done(`Saved revision ${S.saved.revision} at ${hhmm(S.saved.at)}.`)
                  : S.step === 'start' && S.who ? done(`Signed in to ${S.who.tenantName ?? 'your tenant'} at ${hhmm(S.who.at)}.`) : null);
}

// ---- The top bar: the file, who Sluse Admin acts as --------------------------------
function drawTop() {
  const dep = fileDeployment();
  const isDirty = dirty();
  const name = dep?.name || (S.file ? base(S.file.path) : 'New configuration');
  fill($('file-summary'), icon('file'), el('span', { class: 'ad-file__name' }, S.file ? name : 'New configuration'),
    S.file && dep && !(S.saved && !isDirty) ? el('span', {}, `revision ${dep.revision}`) : null,
    S.file && !(S.saved && !isDirty) ? el('span', { class: 'ad-file__path mono' }, base(S.file.path)) : null,
    !S.file ? pill('none', 'Not saved') : isDirty ? pill('changed', 'Unsaved changes') : S.saved ? pill('done', `Saved as revision ${S.saved.revision}`) : null);
  fill($('file-card'), S.file
    ? [el('p', {}, b(name), dep ? [', deployment ', mono(dep.id)] : ', which names no deployment'),
      el('p', { class: 't-muted' }, S.saved ? 'Saved to ' : 'Opened from ', mono(S.file.path)),
      el('p', { class: 't-muted' }, 'Keep this file: it is how you change this deployment later. Intune cannot give it back.')]
    : el('p', { class: 't-muted' }, 'Nothing is saved until Publish. Saving writes revision 1 of a new deployment.'));

  const signedIn = !!S.who;
  const fileOnly = !signedIn && !!S.file;
  $('who-signin').hidden = signedIn || fileOnly;
  $('who').hidden = !(signedIn || fileOnly);
  $('who-expired').hidden = !S.expiredAt;
  const v = $('who-value');
  v.classList.toggle('t-muted', fileOnly);
  v.removeAttribute('title');
  if (signedIn) {
    if (S.who.tenantName) fill(v, `${S.who.account} in ${S.who.tenantName}`);
    else { fill(v, `${S.who.account} in tenant ${S.who.tenant.slice(0, 8)}…`); v.title = `Tenant ${S.who.tenant}`; }
  } else fill(v, 'Not signed in');
  fill($('who-card'), signedIn
    ? [S.expiredAt ? pill('signed-out', `Sign-in expired at ${hhmm(S.expiredAt)}`) : pill('signed-in', 'Signed in'),
      S.who.tenantName ? el('p', {}, 'Sluse Admin acts as ', b(S.who.account), ' in ', b(S.who.tenantName), '.')
        : el('p', {}, 'Sluse Admin acts as ', b(S.who.account), ". Your organisation's name could not be read, so the tenant is shown by its id. Everything else works."),
      chip(S.who.tenant, 'Copy the tenant id'),
      el('p', { class: 't-muted' }, "Sluse Admin keeps its token in this window only and never writes it to disk. Microsoft's sign-in page may remember you on this PC."),
      S.who.tenantName ? null : btn('Read the name again', readName, { cls: 'btn--sm', ico: 'refresh' })]
    : fileOnly ? [pill('signed-out', 'Not signed in'),
      el('p', {}, 'The opened configuration is for tenant ', mono(tenantId() ?? 'not named'), ". The file holds the tenant's id, not its name; the name shows once you sign in."),
      el('p', { class: 't-muted' }, 'Sign in to that tenant to browse for sources or publish straight to Intune. Everything else works without signing in.')] : null);
  $('who-menu-signin').hidden = signedIn && !S.expiredAt;
  $('who-menu-other').hidden = !signedIn;
  $('who-menu-out').hidden = !signedIn;
  $('expired-strip').hidden = !S.expiredAt;
  fill($('expired-title'), `Your sign-in to ${S.who?.tenantName ?? 'your tenant'} has expired.`);
}

async function readName() {
  try { Object.assign(S.who, await invoke('admin_whoami')); if (S.who.tenantName) toast(`Read the organisation's name: ${S.who.tenantName}.`); } catch (e) { if (expired(e)) S.expiredAt = new Date(); }
  draw();
}
function sawError(e) { if (expired(e) && S.who && !S.expiredAt) { S.expiredAt = new Date(); drawTop(); } }

// ---- Start ------------------------------------------------------------------------
async function signIn(pick = false) {
  if (S.signing) return;
  if (pick) { S.picked = true; await invoke('admin_pick_account'); }
  S.signing = { since: Date.now(), pick: S.picked, window: false };
  S.startError = null;
  go('start');
  try {
    const w = await invoke('admin_sign_in');
    const before = S.who;
    S.who = { ...w, at: new Date() };
    S.expiredAt = null;
    // Signed in again to the same tenant (an expired sign-in): the app's
    // state stays; to another, it is that tenant's to find out.
    if (before?.tenant !== w.tenant) {
      S.app = { state: 'none' };
      S.consent = { state: 'idle' };
      S.assigned = { state: 'before', list: [] };
    }
    S.signing = null;
    draw();
    readRoles();
    // The providers' connectors, read once a sign-in is there (D-071).
    if (before?.tenant !== w.tenant) { PROV.state = 'idle'; PROV.report = null; }
    readProviders();
    return;
  } catch (e) {
    S.startError = signInError(String(e));
  }
  S.signing = null;
  draw();
}

function signInError(e) {
  const blocked = el('details', { class: 'disclosure' }, el('summary', {}, 'Did Microsoft\'s page show AADSTS7000112 or AADSTS50105?'),
    el('div', { class: 'disclosure__body' }, el('p', { class: 't-small' }, 'Then your tenant blocks Microsoft Graph Command Line Tools. Allow it for this setup in Enterprise applications, or run the setup from a command prompt with a public client of your own:'),
      chip("sluse admin setup --client-id <your public client's id>", 'Copy the command')));
  const raw = `sluse-admin, sign-in\nSigning in: ${e}\n${new Date().toISOString()}`;
  if (e.includes('the sign-in window was closed')) return { kind: 'info', title: 'The sign-in window was closed before the sign-in finished.', text: 'Sign in again when you are ready.', more: blocked };
  if (e.includes('not finished')) return { kind: 'warning', title: 'The sign-in was not finished within 10 minutes.', text: "Microsoft's window closed itself. Sign in again and finish it in one go." };
  if (e.includes('did not answer')) return { kind: 'problem', title: "Microsoft's sign-in did not answer.", text: "This PC got no answer from Microsoft's sign-in. Check its connection to login.microsoftonline.com, then sign in again.", raw };
  const said = /the sign-in did not complete: (.*)/.exec(e);
  if (said) return { kind: 'problem', title: 'Microsoft did not complete the sign-in.', text: `Microsoft said: ${said[1]} Sign in again; each try gets a new code.`, raw };
  if (/WebView2|sign-in's browser|LOCALAPPDATA|the sign-in window:/.test(e)) return { kind: 'problem', title: 'The sign-in window could not open.', text: "Sluse Admin shows Microsoft's sign-in through the Microsoft Edge WebView2 Runtime, which did not start. Install or repair the WebView2 Runtime, then sign in again.", raw };
  if (e.includes('Windows only')) return { kind: 'problem', title: 'Signing in needs Windows.', text: 'On this computer you can open a saved configuration, change it and save it. Signing in, reading an MSI and publishing need Windows.', raw };
  if (/JWT|base64|has no tid/.test(e)) return { kind: 'problem', title: "Microsoft's answer could not be read.", text: 'The sign-in finished, but the token Microsoft returned names no tenant. Sign in again; if it repeats, copy the details for whoever supports Sluse.', raw };
  return { kind: 'problem', title: 'The sign-in did not finish.', text: 'Sign in again; if it repeats, copy the details for whoever supports Sluse.', raw };
}

async function readRoles() {
  S.rolesError = null;
  try { S.roles = await invoke('admin_roles'); } catch (e) { S.roles = null; S.rolesError = String(e); sawError(e); }
  drawStart(); drawRail();
}

const SLUSE_ROLES = ['Global Administrator', 'Application Administrator', 'Cloud Application Administrator', 'Privileged Role Administrator', 'Intune Administrator'];
function drawStart() {
  const dep = fileDeployment();
  const opened = !!S.file;
  const signed = !!S.who;
  fill($('start-title'), opened ? 'Opened a saved configuration'
    : signed ? (S.who.tenantName ? `Signed in to ${S.who.tenantName}` : `Signed in as ${S.who.account}`) : 'Set up Sluse for your organisation');
  fill($('start-lead'), opened ? 'Change any step, then save the next revision at Publish.'
    : signed ? (S.who.tenantName
      ? ['Sluse Admin acts as ', b(S.who.account), ` in ${S.who.tenantName}, as your organisation's profile in Entra names it. It keeps its token in this window only and never writes it to disk. Microsoft's sign-in page may remember you on this PC.`]
      : ['Sluse Admin acts as ', b(S.who.account), ' in tenant ', mono(S.who.tenant), ". Your organisation's name could not be read; every step works without it. It keeps its token in this window only and never writes it to disk."])
      : "Sluse Admin makes Sluse's app registration in your tenant, helps you write one configuration for one deployment, and hands it to Intune. It reads your directory as you, and keeps its token in this window only.");

  const e = S.startError;
  const fe = S.fileError;
  fill($('start-banner'),
    e ? banner(e.kind, e.title, e.text, { raw: e.raw, more: e.more }) : null,
    fe ? banner('problem', fe.title, fe.text, { raw: fe.raw, actions: fe.actions }) : null,
    mismatch() ? banner('problem', `You signed in to ${S.who.tenantName ?? `tenant ${S.who.tenant.slice(0, 8)}…`}, but the opened configuration is for another tenant.`,
      ['A configuration belongs to one tenant, and Sluse Admin never writes another tenant\'s id into it. ', dep?.name || base(S.file.path), ' is for tenant ', mono(`${tenantId().slice(0, 8)}…`),
        `: sign in to that tenant to keep working on it, or start a new configuration for ${S.who.tenantName ?? 'this tenant'}.`],
      { actions: [btn("Sign in to the file's tenant", () => signIn(true), { cls: 'btn--sm btn--primary', ico: 'sign-in' }), el('button', { class: 'btn btn--sm', type: 'button', 'data-act': 'new-file' }, 'Start a new configuration…')],
        more: el('details', { class: 'disclosure' }, el('summary', {}, 'Tenant ids'), el('div', { class: 'disclosure__body t-small' },
          el('p', {}, 'Signed in: ', mono(S.who.tenant), S.who.tenantName ? ` (${S.who.tenantName})` : ''), el('p', {}, 'The configuration: ', mono(tenantId()), ' (the file holds no name)'))) }) : null);

  $('start-choices').hidden = signed || opened;
  $('signin-idle').hidden = !!S.signing;
  $('signin-wait').hidden = !S.signing;
  $('blocked-help').hidden = !!e && e.more != null;
  if (S.signing) drawSigning();

  $('start-roles').hidden = !signed;
  if (signed) {
    const r = S.roles;
    fill($('roles-pill'), r ? pill('signed-in', 'Roles read') : S.rolesError ? pill('unknown', 'Roles not known') : pill('working', 'Reading'));
    fill($('roles-banner'), S.rolesError ? banner('warning', 'Your roles could not be read.', 'You are signed in, and setup works without this: each step says so if Entra refuses it. Read them again to see before you start which steps need someone else.',
      { raw: `Signing in: ${S.rolesError}`, actions: [btn('Read my roles again', readRoles, { cls: 'btn--sm', ico: 'refresh' })] }) : null);
    for (const td of document.querySelectorAll('[data-role]')) {
      fill(td, !r ? el('span', { class: 'status', 'data-status': 'unknown' }, 'Not known')
        : r[td.dataset.role] ? el('span', { class: 'status', 'data-status': 'allowed' }, 'You can') : el('span', { class: 'status', 'data-status': 'warning' }, 'Needs someone else'));
    }
    const used = r?.names.filter((n) => SLUSE_ROLES.includes(n)) ?? [];
    const other = r?.names.filter((n) => !SLUSE_ROLES.includes(n)) ?? [];
    fill($('roles-line'), !r ? null : !r.names.length ? 'Your account holds no directory role.'
      : !other.length ? `Your directory roles: ${used.join(', ')}.`
        : !used.length ? `Your directory roles: ${other.join(', ')}. Sluse uses none of them.`
          : `Roles Sluse uses: ${used.join(', ')}. Your other roles: ${other.join(', ')}.`);
  }

  const box = $('start-opened');
  box.hidden = !opened;
  if (opened) drawOpened(box, dep);
}

function drawSigning() {
  const g = S.signing;
  const step = (st, text, time, sub) => el('li', { class: 'step', 'data-step': st }, el('span', { class: 'step__text' }, text), time ? el('span', { class: 'step__time' }, time) : null, sub ? el('span', { class: 'step__sub' }, sub) : null);
  const finish = g.pick ? 'Pick an account, or Use another account. Then MFA and the consent page. The window closes by itself.' : 'Finish there: account, MFA, then the consent page. The window closes by itself.';
  fill($('signin-steps'),
    g.pick ? [step('done', 'No quiet try: you asked to sign in as someone else'), step('current', "Microsoft's sign-in window is open at its account picker", clock(g.since), finish)]
      : g.window ? [step('done', 'No quiet sign-in: Microsoft wants you to choose or confirm'), step('current', "Microsoft's sign-in window is open", clock(g.window), finish)]
        : [step('current', 'Trying your Windows sign-in, without a window', clock(g.since)), step('next', "Microsoft's sign-in window, if it is needed")],
    step('next', 'Reading your roles'));
  fill($('signin-meta'), g.pick || g.window ? "Microsoft's window waits up to 10 minutes. Close it to stop." : "The quiet try gives up after 30 seconds and opens Microsoft's window.");
  $('signin-clock').textContent = clock(g.since);
}

function drawOpened(box, dep) {
  const a = S.file.authored;
  const srcs = a.sources ?? [];
  const kindWord = { sharepoint: 'SharePoint', smb: 'file share', 'local-folder': 'folder on the device' };
  const company = srcs.filter((s) => !USER_KINDS.includes(s.kind.type)).map((s) => `${s.name} (${kindWord[s.kind.type] ?? s.kind.type})`);
  const user = [srcs.some((s) => s.kind.type === 'onedrive') ? 'the OneDrive Sluse folder' : null, srcs.some((s) => s.kind.type === 'inputs') ? 'Sluse Inputs' : null].filter(Boolean);
  const all = [...company, ...user];
  const own = (a.egress?.allow ?? []).filter((h) => !(S.catalog?.bundles ?? []).some((bd) => bd.hosts.includes(h))).length;
  const signedHere = S.who && !mismatch();
  fill(box,
    el('div', { class: 'card card--outline' },
      el('div', { class: 'card__head' }, icon('file'), el('h2', { class: 'card__title', id: 'o-t' }, dep ? `${dep.name || 'A deployment'}, revision ${dep.revision}` : base(S.file.path)),
        dep ? pill('current', 'Opened') : pill('warning', 'Names no deployment')),
      dep ? null : note('warning', 'This configuration names no deployment, so saving it makes a new deployment, revision 1. A device that already runs another deployment refuses it.'),
      dep ? el('dl', { class: 'facts' },
        el('div', {}, el('dt', {}, 'Deployment'), el('dd', { class: 'mono' }, dep.id)),
        el('div', {}, el('dt', {}, 'Saving makes'), el('dd', {}, `Revision ${dep.revision + 1}, which devices take as an update`)),
        el('div', {}, el('dt', {}, 'Tenant'), el('dd', {}, signedHere && S.who.tenantName ? S.who.tenantName
          : [mono(tenantId() ?? 'not named'), el('br'), el('span', { class: 't-small t-muted' }, "The file holds the tenant's id; its name shows once you sign in.")])),
        a.entra?.clientId ? el('div', {}, el('dt', {}, "Sluse's app"), el('dd', { class: 'mono' }, a.entra.clientId)) : null) : null,
      el('ul', { class: 'rows' },
        el('li', { class: 'row' }, icon('source'), el('span', { class: 'row__main' }, b('Sources:'), ' ', all.length ? all.join(', ').replace(/, ([^,]*)$/, ' and $1') : 'none'), goBtn('Sources', 'sources', 'btn--sm btn--quiet')),
        el('li', { class: 'row' }, icon('globe'), el('span', { class: 'row__main' }, b('Egress:'), ` ${plural(1 + (a.egress?.bundles?.length ?? 0), 'bundle')}${own ? ` and ${plural(own, 'host')} of your own` : ''}, ${plural(a.egress?.allow?.length ?? 0, 'host')} in all`), goBtn('Egress', 'egress', 'btn--sm btn--quiet')),
        el('li', { class: 'row' }, icon('settings'), el('span', { class: 'row__main' }, b('Advanced:'), ` ${advancedChanges() ? plural(advancedChanges(), 'change') + ' from the defaults' : 'the defaults'}`), goBtn('Advanced', 'advanced', 'btn--sm btn--quiet'))),
      el('div', { class: 'card__foot' }, el('span', { class: 't-small t-muted' }, 'From ', mono(S.file.path)))),
    S.who ? null : note('info', 'You are not signed in. That is enough to change the scopes and settings you have and to save. Sign in to browse for new sources or to publish straight to Intune.'),
    el('div', { class: 'btn-row' }, el('button', { class: 'btn btn--primary', type: 'button', 'data-go': 'sources' }, 'Go to Sources', icon('chevron-right')),
      S.who ? null : btn('Sign in to this tenant', () => signIn(false), { ico: 'sign-in' })));
}

// ---- Opening a file, starting new -------------------------------------------------
async function loseChanges(what) {
  if (!dirty()) return true;
  const name = fileDeployment()?.name || (S.file ? base(S.file.path) : 'the new configuration');
  const steps = changedSteps().join(' and ');
  if (what === 'open') {
    return await ask({ ico: 'folder-open', title: 'Open another configuration?', destructive: true,
      body: el('p', {}, `Your unsaved changes to ${name} are lost: ${steps}.${S.file && fileDeployment() ? ` The saved file stays as it is, revision ${fileDeployment().revision}.` : ''}`),
      actions: [['cancel', 'Cancel'], ['ok', 'Lose the changes and open…', 'btn--destructive', 'folder-open']] }) === 'ok';
  }
  return await ask({ ico: 'plus', title: 'Start a new configuration?', destructive: true,
    body: [el('p', {}, `Every step goes back to its defaults, and your unsaved changes to ${name} are lost. Your sign-in and Sluse's app stay.`),
      fileDeployment() ? el('p', { class: 't-small t-muted' }, `A new configuration is a new deployment. A device that runs ${name} refuses a second deployment, so to change ${name}, open its file instead.`) : null],
    actions: [['cancel', 'Cancel'], ['ok', 'Lose the changes and start new', 'btn--destructive', 'reset']] }) === 'ok';
}

async function openFile() {
  if (!(await loseChanges('open'))) return;
  const path = await dialog.open(JSON_FILTER).catch(() => null);
  if (!path) return;
  S.fileError = null;
  try {
    const a = await invoke('admin_open', { path });
    const t = a.entra?.tenantId;
    if (S.who && t && t !== S.who.tenant) {
      S.fileError = { title: 'This configuration is for another tenant.', text: [mono(base(path)), ' is for tenant ', mono(`${t.slice(0, 8)}…`), `, and you are signed in to ${S.who.tenantName ?? 'another tenant'}. Sign in to that tenant to change it, or open one of ${S.who.tenantName ? `${S.who.tenantName}'s` : 'this tenant\'s'} configurations.`],
        raw: `Opening: ${path}: this configuration is tenant ${t}'s, and you are signed in to ${S.who.tenant}`,
        actions: [btn('Sign in as someone else', () => signIn(true), { cls: 'btn--sm', ico: 'sign-in' })] };
    } else {
      load(a, path);
    }
  } catch (e) {
    S.fileError = openError(String(e), path);
  }
  go('start');
}

function openError(e, path) {
  const raw = `Opening: ${path}: ${e}`;
  const name = base(path);
  if (e.includes('not valid JSON')) return { title: `${name} is not a Sluse configuration.`, text: 'It is not valid JSON. Open the file you saved from Sluse Admin.', raw };
  if (e.includes('no numeric schemaVersion')) return { title: 'This file names no schema version.', text: 'Every configuration Sluse Admin saves names one. Open the file you saved from Sluse Admin.', raw };
  const old = /schemaVersion (\d+), which this build no longer accepts/.exec(e);
  if (old) return { title: 'This configuration was saved by an older Sluse Admin.', text: `It is schema ${old[1]}. Since schema 3 the file holds only what you decide, and each device writes its own half. Build it again here and publish it.`, raw };
  const newer = /schemaVersion (\d+) is unknown; this build understands (\d+)/.exec(e);
  if (newer) return { title: 'This configuration is newer than this Sluse Admin.', text: `It is schema ${newer[1]}, and this Sluse Admin understands ${newer[2]}. Open it with a Sluse Admin of the same release or later.`, raw };
  if (e.includes('does not match schema')) return { title: 'This file does not match schema 3.', text: 'A field is not what schema 3 expects. Fix the field named in the details, or open the copy you saved from Sluse Admin.', raw };
  if (/cannot be read|os error|denied/i.test(e)) return { title: 'Sluse Admin could not read the file.', text: 'Windows refused access to it. Copy the file somewhere you can read, then open the copy.', raw };
  const plain = refusal(e);
  return { title: plain.title, text: plain.text, raw };
}

/** A file opened: every step takes its choices from it. */
function load(a, path) {
  S.file = { path, authored: a };
  S.saved = null;
  S.review = { verdict: 'none' };
  S.save = { state: 'idle' };
  S.pub = { what: 'here', state: 'idle', groups: null, shown: 50 };
  S.app = { state: 'none' };
  S.consent = { state: 'idle' };
  S.assigned = { state: 'before', list: [] };
  $('dep-name').value = a.deployment?.name ?? '';
  $('acc-workspaces').value = (a.accounts?.chatgptWorkspaces ?? []).join(' ');
  $('acc-claude').value = a.accounts?.claudeOrganisation ?? '';
  // A SharePoint source from a file has no library id to browse by until its
  // site is found again (Q48).
  S.sources = (a.sources ?? []).map((s) => ({ ...s, scope: s.scope ?? [], mark: ['sharepoint', 'mcp'].includes(s.kind.type) ? 'from-file' : null }));
  const e = a.egress ?? { bundles: [], allow: [] };
  S.bundles = new Set(e.bundles);
  const fromCatalog = (S.catalog?.bundles ?? []).flatMap((bd) => bd.hosts);
  $('own-hosts').value = (e.allow ?? []).filter((h) => !fromCatalog.includes(h)).join('\n');
  const v = a.volume ?? {};
  $('v-files').value = v.admissions ?? 25;
  $('v-window').value = v.windowSeconds ?? 60;
  $('v-mb').value = v.bytes ? Math.round(v.bytes / 1048576) : '';
  $('fetch-mb').value = a.maxFetchBytes != null ? Math.round(a.maxFetchBytes / 1048576) : '';
  const bx = a.box ?? {};
  drawCards(bx.memoryGB ?? 6, bx.homeGB ?? 40);
  $('copy-out').checked = bx.copyOut ?? true;
  $('egress-log').checked = !!e.log?.enabled;
  $('egress-mb').value = e.log?.maxMB ?? 50;
  buildBundles();
  drawSources(); drawAdvanced();
  setBaseline();
}

function startNew() {
  S.file = null;
  S.saved = null;
  S.fileError = null;
  S.draftId = crypto.randomUUID();
  S.review = { verdict: 'none' };
  S.save = { state: 'idle' };
  S.pub = { what: 'here', state: 'idle', groups: null, shown: 50 };
  $('dep-name').value = '';
  S.sources = [];
  S.bundles = new Set((S.catalog?.bundles ?? []).filter((bd) => bd.default && !bd.locked).map((bd) => bd.id));
  $('own-hosts').value = '';
  $('v-files').value = 25; $('v-window').value = 60; $('v-mb').value = 50; $('fetch-mb').value = '';
  drawCards(6, 40);
  $('copy-out').checked = true; $('egress-log').checked = false; $('egress-mb').value = 50;
  $('acc-workspaces').value = ''; $('acc-claude').value = '';
  buildBundles();
  drawSources(); drawAdvanced();
  setBaseline();
}

// ---- Tenant -----------------------------------------------------------------------
const SCOPES = [['Read files the signed-in user can open', ['Files.Read.All']], ['Read SharePoint sites the signed-in user can open', ['Sites.Read.All']],
  ['Keep the user signed in while the box runs', ['offline_access']], ['Sign the user in and read their name', ['openid', 'profile']]];
let consentTimer = null;

async function register() {
  if (!S.who) { S.app = { state: 'not-signed-in' }; drawTenant(); return; }
  S.app = { state: 'running' };
  drawTenant();
  try {
    const r = await invoke('admin_register');
    S.app = { state: 'ready', result: r };
    S.consent = { state: 'waiting', since: Date.now(), missing: SCOPES.flatMap(([, p]) => p) };
    checkConsent(false);
    readAssigned();
  } catch (e) {
    S.app = { state: 'problem', error: String(e) };
    sawError(e);
  }
  drawTenant(); changed();
}

async function checkConsent(returned) {
  try {
    const missing = await invoke('admin_consent_missing');
    S.consent = { ...S.consent, missing, at: new Date(), returned };
    if (!missing.length) { S.consent.state = 'granted'; stopConsent(); }
    else { S.consent.state = 'waiting'; if (S.step === 'tenant' && !consentTimer) consentTimer = setInterval(() => checkConsent(false), 5000); }
  } catch (e) {
    S.consent = { ...S.consent, state: 'error', error: String(e) };
    stopConsent();
    sawError(e);
  }
  drawTenant(); drawRail();
}
function stopConsent() { clearInterval(consentTimer); consentTimer = null; }
/** Checking pauses off Tenant (Q45). */
function pauseConsent() { stopConsent(); }
function returnToTenant() { if (S.consent.state === 'waiting') checkConsent(true); }

async function readAssigned() {
  if (!S.app.result) return;
  S.assigned = { ...S.assigned, state: 'loading' };
  drawTenant();
  try {
    S.assigned = { ...S.assigned, state: 'read', list: await invoke('admin_assigned'), at: new Date() };
  } catch (e) {
    S.assigned = { ...S.assigned, state: 'error', error: String(e) };
    sawError(e);
  }
  drawTenant(); drawRail();
  if (S.step === 'review' && S.review.verdict === 'accepted') drawReview();
}

async function findPeople() {
  const query = $('people-query').value.trim();
  S.people = { state: 'searching', found: [], shown: 50, query };
  drawTenant();
  try {
    const found = await invoke('admin_groups', { query });
    S.people = { state: found.length ? 'results' : 'none', found, shown: 50, query };
  } catch (e) {
    S.people = { state: 'error', found: [], query, error: String(e) };
    sawError(e);
  }
  drawTenant();
}

async function assign() {
  const g = S.people.picked;
  if (!g) return;
  S.assign = { state: 'assigning', group: g };
  drawTenant();
  try {
    const r = await invoke('admin_assign', { group: g.id });
    if (r.changed.some((c) => c.endsWith('may sign in'))) S.inWindow.set(g.id, new Date());
    S.assign = { state: 'done', group: g, result: r };
    S.assigned.removed = null;
    readAssigned();
  } catch (e) {
    S.assign = { state: 'error', group: g, error: String(e) };
    sawError(e);
  }
  drawTenant();
}

async function removeGroup(a) {
  const list = S.assigned.list;
  const last = list.length === 1;
  const other = list.filter((x) => x.id !== a.id).map((x) => x.name);
  const t = S.who?.tenantName ?? 'your tenant';
  const stays = ['The group itself, in Entra', `Sluse on ${last ? 'the' : 'their'} devices: that is Intune's assignment, at Publish`, "The record of every admission, in the Event Log on each device, in Sluse's channel"];
  const answer = await ask(last
    ? { ico: 'warning', destructive: true, title: `Remove ${a.name}, the only group assigned?`,
      body: [el('p', {}, 'Assignment required stays on, so after this no one can sign in to Sluse until a group is assigned again. A box that is open keeps the sign-in it has until that sign-in runs out.'),
        goesStays([`${a.name}' assignment to Sluse's app`, `Every next sign-in to Sluse in ${t}`], stays)],
      actions: [['cancel', 'Cancel'], ['ok', 'Remove the last group', 'btn--destructive', 'close']] }
    : { ico: 'group', destructive: true, title: `Remove ${a.name} from Sluse's app?`,
      body: [el('p', {}, `Entra then refuses the next sign-in to Sluse of anyone in ${a.name}, unless another assigned group holds them too. A box that is open keeps the sign-in it has until that sign-in runs out.`),
        goesStays([`${a.name}' assignment to Sluse's app`, "Its members' next sign-in to Sluse"], stays),
        el('p', { class: 't-small t-muted' }, `${other.join(' and ')} ${other.length === 1 ? 'stays' : 'stay'} assigned. You can assign ${a.name} again here at any time.`)],
      actions: [['cancel', 'Cancel'], ['ok', `Remove ${a.name}`, 'btn--destructive', 'close']] });
  if (answer !== 'ok') return;
  try {
    await invoke('admin_unassign', { id: a.id });
    S.inWindow.delete(a.group);
    S.assigned.removed = { name: a.name, last };
    S.assign = { state: 'idle' };
    toast(last ? `Removed ${a.name}. No group is assigned to Sluse's app.` : `Removed ${a.name} from Sluse's app.`);
    readAssigned();
  } catch (e) {
    S.assigned = { ...S.assigned, state: 'error', error: `Removing ${a.name}: ${e}` };
    sawError(e);
    drawTenant();
  }
}

function drawTenant() {
  const t = tenantWord();
  fill($('tenant-title'), S.who ? `Sluse's app in ${t ?? 'your tenant'}` : "Sluse's app in this configuration's tenant");
  const a = S.app;
  const fromFile = a.state === 'none' && S.file?.authored?.entra?.clientId;
  fill($('app-pill'), a.state === 'running' ? pill('working', 'Working') : a.state === 'ready' ? pill('ready', 'Ready')
    : a.state === 'problem' ? pill('problem', 'Problem') : fromFile ? pill('not-checked', 'From the file, not checked') : pill('not-checked', 'Not checked'));
  fill($('app-note'),
    fromFile ? note('info', 'The opened file names Sluse\'s app ', mono(S.file.authored.entra.clientId), '. Make or repair it to check it, and to see its consent and who may sign in.') : null,
    !S.who && (a.state === 'not-signed-in' || a.state === 'none') ? note('warning', `Sign in first: making Sluse's app acts as you in ${t ?? 'your tenant'}. `, el('button', { class: 'btn--link', type: 'button', 'data-go': 'start' }, 'Go to Start')) : null);
  const reg = $('register');
  reg.className = `btn ${a.state === 'ready' ? '' : 'btn--primary'}`;
  reg.setAttribute('aria-busy', String(a.state === 'running'));
  reg.disabled = a.state === 'running';
  fill($('app-result'), a.state === 'ready' ? appResult(a.result) : a.state === 'problem' ? appProblem(a.error) : null);

  const ready = a.state === 'ready';
  $('seq-app').dataset.seq = ready ? 'done' : '';
  $('seq-consent').dataset.seq = ready ? (S.consent.state === 'granted' ? 'done' : '') : 'waits';
  $('seq-who').dataset.seq = ready ? (S.assigned.list?.length ? 'done' : '') : 'waits';
  if (ready) { drawConsent(); drawWho(); }
  drawProviders();
}

// ---- The providers' own connectors (D-071 slice 7) ------------------------------------------
const PROV = { state: 'idle' };
async function readProviders() {
  if (!S.who) return;
  PROV.state = 'reading'; drawProviders();
  try {
    PROV.report = await invoke('admin_connectors');
    PROV.state = 'read';
  } catch (e) {
    PROV.state = 'error'; PROV.error = String(e);
    sawError(e);
  }
  drawProviders();
}
const CONSENT_WORDS = {
  Off: ['done', 'Users cannot consent to apps themselves: an admin decides each one.'],
  VerifiedLowRisk: ['warning', "Users may consent for themselves to verified publishers' apps asking low-risk permissions. The providers' apps may be among them."],
  On: ['warning', 'Users may consent to any app for themselves, the providers\' included.'],
};
function drawProviders() {
  $('prov-read').setAttribute('aria-busy', String(PROV.state === 'reading'));
  $('prov-read').disabled = !S.who || PROV.state === 'reading';
  const r = PROV.report;
  const open = r ? r.findings.filter((f) => f.open).length : 0;
  fill($('prov-pill'), PROV.state === 'read' ? (open ? pill('warning', `${open} open`) : pill('done', 'Closed')) : pill('not-checked', 'Not read'));
  if (!S.who) { fill($('prov-body'), note('info', 'Sign in to read them.')); return; }
  if (PROV.state === 'error') { fill($('prov-body'), banner('problem', 'They could not be read.', 'Sign in again, then read them again.', { raw: PROV.error })); return; }
  if (PROV.state !== 'read') { fill($('prov-body'), PROV.state === 'reading' ? status('working', 'Reading the providers\' apps…') : null); return; }
  const uc = r.userConsent;
  const consent = uc.state === 'Unknown' ? note('info', 'Whether users may consent for themselves could not be read: it needs Policy.Read.All, which your sign-in did not grant. Entra admin center, Enterprise applications, Consent and permissions, says.')
    : uc.state === 'Other' ? note('info', 'Users consent under these policies: ', mono(uc.policies.join(', ')), '.')
      : note(CONSENT_WORDS[uc.state][0], CONSENT_WORDS[uc.state][1]);
  fill($('prov-body'),
    consent,
    el('ul', { class: 'rows' }, r.findings.map((f) => el('li', { class: 'row', style: 'flex-wrap: wrap' },
      icon(f.open ? 'warning' : 'sealed'),
      el('span', { class: 'row__main' }, b(f.name), ` (${f.provider})`, el('br'),
        el('span', { class: 't-small t-muted' },
          !f.servicePrincipal ? 'Not in this tenant. Anyone allowed to consent can add it; turning its sign-in off now means no one can.'
            : f.signInEnabled === false ? 'Sign-in is off: Entra issues no token for it.'
              : [`In this tenant, sign-in on. ${f.tenantScopes.length ? `Admin consent for everyone: ${f.tenantScopes.join(', ')}.` : 'No admin consent for everyone.'}`,
                f.userGrants ? ` ${plural(f.userGrants, 'user')} consented for themselves.` : '',
                f.assignmentRequired ? ' Only people assigned to it may sign in.' : ''].join(''))),
      f.canBlock ? btn('Turn its sign-in off', () => blockProvider(f), { cls: 'btn--sm' }) : null))),
    note('info', "OpenAI publishes no app id for its connectors' app, so it is found here by name once it is in this tenant, and cannot be turned off before. A connector a user adds to a personal Claude or ChatGPT account involves no app of yours, and nothing here sees it."));
}
async function blockProvider(f) {
  const ok = await ask({ ico: 'warning', title: `Turn sign-in off for ${f.name}?`, destructive: true,
    body: [el('p', {}, `Entra then issues no token for it: ${f.provider}'s connector stops working for everyone in this tenant, whatever anyone consented to.`),
      el('p', { class: 't-small t-muted' }, f.servicePrincipal ? 'It is undone in Entra admin center: Enterprise applications, the app, Properties, Enabled for users to sign in.'
        : 'Its service principal is made now, with sign-in off, before anyone consents. It is undone in Entra admin center, as any app.')],
    actions: [['cancel', 'Cancel'], ['ok', 'Turn it off', 'btn--destructive']] }) === 'ok';
  if (!ok) return;
  try {
    const done = await invoke('admin_connector_block', { appId: f.appId ?? null, servicePrincipal: f.servicePrincipal ?? null });
    toast(`${f.name}: ${done}.`);
  } catch (e) {
    // Said here: the read again below would replace an error kept in PROV.
    problemToast(`${f.name}'s sign-in could not be turned off: ${e}`); sawError(e);
  }
  readProviders();
}
$('prov-read').onclick = readProviders;

function appResult(r) {
  const said = r.changed.map((c) => {
    let m;
    if (/^application "/.test(c)) return ['+', `Made the app registration ${c.slice('application '.length)}`, pill('plain', 'Made')];
    if (/^service principal/.test(c)) return ['+', 'Made its enterprise application, which consent and assignment name', pill('plain', 'Made')];
    if ((m = /^removed: owner (.*)/.exec(c))) return ['−', `Removed an owner of the app, id ${m[1].slice(0, 8)}… Owners can add credentials to an app, so Sluse's app keeps none; administrators still manage it.`, pill('changed', 'Removed')];
    if (c.includes('access_as_user')) return ['−', ['Removed the ', mono('access_as_user'), ' scope an older Sluse sign-in used'], pill('changed', 'Removed')];
    if (c.includes('certificate')) return ['−', 'Removed the certificate an older Sluse sign-in used', pill('changed', 'Removed')];
    if ((m = /client secret \((.*)\)/.exec(c))) return ['−', ['Removed a client secret, key ', mono(m[1].slice(0, 8)), ". Sluse's app is a public client and keeps none."], pill('changed', 'Removed')];
    if ((m = /federated credential \((.*)\)/.exec(c))) return ['−', ['Removed a federated credential, ', mono(m[1])], pill('changed', 'Removed')];
    if ((m = /^deleted: application ("[^"]*")/.exec(c))) return ['−', `Deleted the app registration ${m[1]}, which an older Sluse sign-in used`, pill('changed', 'Deleted')];
    return ['±', c, pill('changed', 'Changed')];
  });
  return el('div', { class: 'panel stack', style: '--stack-gap: var(--space-3)' },
    el('dl', { class: 'facts facts--wide' }, el('div', {}, el('dt', {}, 'Name'), el('dd', {}, 'Sluse Gate')),
      el('div', {}, el('dt', {}, 'Application (client) id'), el('dd', {}, chip(r.appId, 'Copy the application id')))),
    el('hr', { class: 'rule' }),
    said.length ? el('ul', { class: 'diff' }, said.map(([s, t, p]) => diffLine(s, t, p))) : status('done', "Nothing to change: Sluse's app is as it should be."),
    said.length ? el('details', { class: 'disclosure' }, el('summary', {}, 'Details'), tech([`Sluse's app: ${r.appId}`, ...r.changed].join('\n'), 'As the engine reported it')) : null);
}

function appProblem(e) {
  const raw = `Making Sluse's app: ${e}`;
  if (/applications are named/.test(e)) {
    const ids = (/appId ([^)]*)\)/.exec(e)?.[1] ?? '').split(', ').filter(Boolean);
    return banner('problem', 'Two app registrations are named "Sluse Gate".', "Sluse finds its app by that name, so it cannot tell which one is Sluse's, and changed neither. Remove or rename the one that is not Sluse's in App registrations, then run this again.",
      { raw, more: el('div', { class: 'stack', style: '--stack-gap: var(--space-1)' }, ids.map((id, i) => chip(id, `Copy application id ${i + 1}`))) });
  }
  if (expired(e)) return banner('warning', 'Your sign-in has expired.', "Sign in again, then make or repair Sluse's app.", { raw, actions: [btn('Sign in again', () => signIn(false), { cls: 'btn--sm btn--primary', ico: 'sign-in' })] });
  if (/: 403\b/.test(e)) return banner('problem', 'Entra refused to make or change the app registration.', 'This needs an Application Administrator, a Cloud Application Administrator or a Global Administrator. Ask someone with one of those roles to run this step; the other steps work without it.', { raw });
  if (/no delegated scope/.test(e)) return banner('problem', "Microsoft Graph does not offer a permission Sluse's app needs.", 'Nothing was changed. This is not expected; copy the details for whoever supports Sluse.', { raw });
  return banner('problem', "Sluse's app could not be made or repaired.", 'Run this again; if it repeats, copy the details for whoever supports Sluse.', { raw });
}

function drawConsent() {
  const c = S.consent;
  const t = tenantWord() ?? 'your tenant';
  const granted = c.state === 'granted';
  fill($('consent-pill'), granted ? pill('granted', 'Granted') : c.state === 'error' ? pill('stale', 'Not checking') : pill('waiting', 'Waiting'));
  fill($('consent-lead'), `Sluse's app reads files as each signed-in user, never more than they can open. An administrator grants that once for ${t}, in the Azure portal. This page sees it by itself.`);
  $('consent-how').hidden = granted;
  $('portal-url').textContent = `https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/${S.app.result.appId}`;
  $('portal-url').parentElement.title = $('portal-url').textContent;
  $('portal-url').nextElementSibling.dataset.copy = $('portal-url').textContent;
  fill($('consent-there'), 'There, choose ', b(`Grant admin consent for ${t}`), ', then ', b('Yes'), '. Someone else can do it: copy the link for them.');
  const missing = c.missing ?? [];
  fill($('consent-rows'), SCOPES.map(([what, perms]) => {
    const ok = granted || (c.at && perms.every((p) => !missing.includes(p)));
    return el('tr', {}, el('td', {}, what), el('td', { class: 'mono' }, perms.join(', ')), el('td', {}, ok ? pill('granted', 'Granted') : pill('waiting', 'Waiting')));
  }));
  fill($('consent-state'),
    c.state === 'waiting' && !c.returned ? status('checking', 'Checking every 5 seconds while this step is open. Waiting ', el('span', { class: 't-num', id: 'consent-clock' }, clock(c.since)), '.') : null,
    c.state === 'waiting' && c.returned ? status('checking', `Checked when you came back, at ${hhmm(c.at)}: still waiting. Checking every 5 seconds again while this step is open.`) : null,
    granted && !c.returned ? status('done', 'Consent is granted. Checking stopped.') : null,
    granted && c.returned ? status('done', `Consent was granted while you were on another step. Seen when you came back, at ${hhmm(c.at)}. Checking stopped.`) : null,
    c.state === 'waiting' ? el('p', { class: 't-small t-muted' }, 'On another step, checking pauses. It checks once more when you come back to Tenant.') : null,
    c.state === 'error' ? (expired(c.error)
      ? banner('warning', 'Checking stopped: your sign-in has expired.', 'Sign in again to check consent. Consent granted in the portal stays granted either way.',
        { raw: c.error, actions: [btn('Sign in again', () => signIn(false), { cls: 'btn--sm btn--primary', ico: 'sign-in' })] })
      : banner('warning', 'Checking stopped: Entra did not answer the consent check.', 'Consent granted in the portal stays granted either way. Check again when you are ready.',
        { raw: c.error, actions: [btn('Check again', () => { S.consent.state = 'waiting'; checkConsent(false); }, { cls: 'btn--sm', ico: 'refresh' })] })) : null);
}

function drawWho() {
  const as = S.assigned;
  const list = as.list ?? [];
  const removed = as.removed;
  const turnedOn = S.assign.state === 'done' && S.assign.result.changed.some((c) => c.startsWith('Turned on'));
  fill($('who-pill'), as.state !== 'read' ? pill('not-checked', 'Not read') : list.length || turnedOn ? pill('on', 'Assignment required')
    : removed ? pill('warning', 'No group: no one signs in') : pill('none', 'No group yet'));
  fill($('assigned-at'), as.state === 'read' ? `Read from Entra at ${hhmm(as.at)}` : null);
  $('assigned-again').hidden = as.state === 'loading';
  fill($('assigned'),
    as.state === 'loading' ? status('working', "Reading the groups assigned to Sluse's app…") : null,
    as.state === 'error' ? banner('warning', "The groups assigned to Sluse's app could not be read.", 'Assigning a group below still works. Read them again, or see them in the Entra admin center: Enterprise applications, Sluse broker, Users and groups.',
      { raw: `Reading assignments: ${as.error}`, actions: [btn('Read again', readAssigned, { cls: 'btn--sm', ico: 'refresh' })] }) : null,
    as.state === 'read' && list.length ? el('ul', { class: 'rows ad-assigned', 'aria-labelledby': 'as-t' }, list.map((g) => el('li', { class: 'row' }, icon('group'),
      el('span', { class: 'row__main' }, b(g.name), el('br'), el('span', { class: 't-small t-muted' },
        S.inWindow.has(g.group) ? `Assigned in this window, at ${hhmm(S.inWindow.get(g.group))}` : g.created ? `Assigned ${day(g.created)}, before this window` : 'Assigned before this window')),
      el('button', { class: 'btn btn--sm btn--quiet', type: 'button', 'aria-label': `Remove ${g.name}…`, onclick: () => removeGroup(g) }, icon('close'), 'Remove…')))) : null,
    as.state === 'read' && !list.length ? el('div', { class: 'empty', style: 'padding: var(--space-4) 0' }, el('span', { class: 'empty__icon' }, icon('group')),
      el('p', { class: 'empty__title' }, "No group is assigned to Sluse's app."),
      el('p', { class: 'empty__text' }, removed ? 'With Assignment required on, no one can sign in to Sluse until a group is assigned again.' : 'Assign one below. Assigning the first group also turns on Assignment required, so only the groups assigned here sign in.')) : null,
    turnedOn ? el('ul', { class: 'diff' }, diffLine('+', ['Turned on ', b('Assignment required'), ": only the groups assigned to Sluse's app sign in"], pill('on', 'On'))) : null,
    removed ? el('ul', { class: 'diff' }, diffLine('−', removed.last
      ? ['Removed ', b(removed.name), " from Sluse's app, the only group assigned. No one's next sign-in to Sluse is accepted until a group is assigned again."]
      : ['Removed ', b(removed.name), " from Sluse's app. Its members' next sign-in to Sluse is refused, unless another assigned group holds them."], pill('changed', 'Removed'))) : null);

  const p = S.people;
  const find = $('people-find');
  find.setAttribute('aria-busy', String(p.state === 'searching'));
  $('find-hint').hidden = p.state !== 'idle';
  fill($('people-pick'), p.state === 'idle' ? null : el('div', { class: 'picklist' },
    p.state === 'searching' ? el('div', { class: 'picklist__state' }, status('working', 'Finding groups…')) : null,
    p.state === 'none' ? el('div', { class: 'empty', style: 'padding: var(--space-4)' }, el('span', { class: 'empty__icon' }, icon('group')),
      el('p', { class: 'empty__title' }, `No group's name starts with "${p.query}".`), el('p', { class: 'empty__text' }, 'Search matches the start of the display name only. Check the spelling, or type less of it.')) : null,
    p.state === 'error' ? el('div', { class: 'picklist__state' }, banner('problem', 'Microsoft Graph did not list the groups.', 'Your sign-in may have expired. Sign in again, then find again.', { raw: `Finding groups: ${p.error}` })) : null,
    p.state === 'results' ? [
      el('ul', { class: 'rows', role: 'radiogroup', 'aria-label': 'Groups' }, p.found.slice(0, p.shown).map((g) => el('li', { class: 'row' },
        el('label', { class: 'radio' }, el('input', { type: 'radio', name: 'grp', checked: p.picked?.id === g.id, onchange: () => { p.picked = g; drawWho(); } }), el('span', { class: 'radio__dot' }), icon('group'), g.name)))),
      el('div', { class: 'picklist__foot' },
        el('span', { class: 'spacer' }, p.found.length > p.shown ? `The first ${p.shown} groups. Type more of the name to narrow it.` : plural(p.found.length, 'group')),
        p.found.length > p.shown ? btn('Show 50 more', () => { p.shown += 50; drawWho(); }, { cls: 'btn--sm btn--quiet' }) : null,
        p.picked ? btn(`Assign ${p.picked.name}`, assign, { cls: 'btn--primary', busy: S.assign.state === 'assigning', disabled: S.assign.state === 'assigning' })
          : btn('Pick a group to assign', null, { cls: 'btn--primary', disabled: true }))] : null));

  const r = S.assign;
  const already = r.state === 'done' && !r.result.changed.some((c) => c.endsWith('may sign in'));
  fill($('assign-result'),
    already ? note('info', `${r.group.name} was already assigned to Sluse's app. Nothing changed.`) : null,
    r.state === 'done' ? el('p', { class: 't-small t-muted' }, 'Picking another group adds it beside these.') : null,
    r.state === 'done' ? r.result.warnings.map((w) => note('warning', w)) : null,
    r.state === 'error' ? banner('problem', `Entra refused to assign ${r.group.name}.`, /: 403\b/.test(r.error)
      ? 'Assigning a group needs an Application Administrator, a Cloud Application Administrator or a Global Administrator. Ask someone with one of those roles to run this step.'
      : 'Try again; if it repeats, copy the details for whoever supports Sluse.', { raw: `Assigning ${r.group.name}: ${r.error}` }) : null);
}

// ---- Sources ----------------------------------------------------------------------
const kindWord = { sharepoint: 'SharePoint', smb: 'File share', 'local-folder': 'Folder on the device', mcp: 'Tool server' };
const kindIcon = { sharepoint: 'library', smb: 'server', 'local-folder': 'folder', mcp: 'apps' };
const where = (s) => s.kind.type === 'sharepoint' ? [mono(s.kind.address.siteUrl), `, library ${s.kind.address.library}`]
  : s.kind.type === 'smb' ? mono(s.kind.address.unc) : s.kind.type === 'mcp' ? [mono(s.kind.address.url), `, MCP ${s.kind.address.protocol}`] : mono(s.kind.address?.root ?? '');
const whole = (s) => s.kind.type === 'sharepoint' ? ['The whole library ', s.kind.address.library] : s.kind.type === 'smb' ? ['The whole share ', mono(s.kind.address.unc)]
  : s.kind.type === 'mcp' ? ['Every tool of ', mono(s.kind.address.url)] : ['All of ', mono(s.kind.address.root)];
const levelSelect = (s, id) => el('select', { class: 'select', id, onchange: (e) => { s.sensitivity = Number(e.target.value); changed(); } },
  LEVELS.map(([v, t]) => el('option', { value: v, selected: v === s.sensitivity }, t)));
function uniqueName(n, except) { let name = slug(n), i = 2; while (S.sources.some((s) => s !== except && s.name === name)) name = `${slug(n).slice(0, 29)}-${i++}`; return name; }

function drawSources() {
  fill($('dep-hint'), `Intune's app is named after it, for example "Sluse: ${depName() || 'Pilot'}, revision ${nextRevision()}".`);
  const company = S.sources.filter((s) => !USER_KINDS.includes(s.kind.type));
  const graph = S.sources.filter((s) => ['sharepoint', 'onedrive', 'mcp'].includes(s.kind.type));
  $('add-source-top').hidden = !company.length;
  fill($('sources-banner'), graph.length && !clientId() ? banner('warning', `${graph[0].name} reads through Sluse's app, which this configuration does not name yet.`,
    "SharePoint, OneDrive and tool server sources need it. Make or repair it at Tenant, or open the saved configuration that names it. Review refuses the configuration until then.",
    { actions: [goBtn('Go to Tenant', 'tenant'), el('button', { class: 'btn btn--sm btn--quiet', type: 'button', 'data-act': 'open-file' }, icon('folder-open'), 'Open a saved configuration…')] }) : null);
  fill($('sources'), company.length ? company.map(srcCard) : el('div', { class: 'empty' }, el('span', { class: 'empty__icon' }, icon('source')),
    el('p', { class: 'empty__title' }, 'No sources yet'),
    el('p', { class: 'empty__text' }, 'A source is a SharePoint library or a file share. Add one, then pick the folders in reach. Without a source, or a folder each user fills below, the box can admit nothing.'),
    el('div', { class: 'empty__action' }, el('button', { class: 'btn btn--primary', type: 'button', 'data-act': 'add-source' }, icon('plus'), 'Add a source'))));
  for (const row of document.querySelectorAll('[data-uf]')) {
    const type = row.dataset.uf;
    const s = S.sources.find((x) => x.kind.type === type);
    row.querySelector('input[type=checkbox]').checked = !!s;
    row.querySelector('.togglerow__more').hidden = !s;
    row.toggleAttribute('data-on', !!s);
    const sel = $(`sens-${type}`);
    fill(sel, LEVELS.map(([v, t]) => el('option', { value: v, selected: v === (s?.sensitivity ?? 2) }, t)));
    sel.onchange = () => { if (s) { s.sensitivity = Number(sel.value); changed(); } };
  }
}

function srcCard(s) {
  if (s.kind.type === 'mcp') return mcpCard(s);
  const unbrowsable = s.kind.type === 'sharepoint' && !s.driveId;
  const n = s.scope.length;
  const local = s.kind.type === 'local-folder';
  const id = `src-${s.name}`;
  const rename = s.renaming != null ? (() => {
    const proposed = slug(s.renaming);
    const dup = S.sources.some((x) => x !== s && x.name === proposed);
    const input = el('input', { class: `input${dup ? ' input--mono' : ''}`, type: 'text', value: s.renaming, 'aria-invalid': dup ? 'true' : null,
      oninput: (e) => { s.renaming = e.target.value; const keep = e.target.selectionStart; drawSources(); const i = document.querySelector(`#${CSS.escape(id)} .srccard__reach input`); if (i) { i.focus(); i.setSelectionRange(keep, keep); } } });
    return el('div', { class: 'srccard__reach' },
      el('label', { class: `field${dup ? ' field--invalid' : ''}` }, el('span', { class: 'field__label' }, 'Name'), input,
        dup ? el('span', { class: 'field__msg' }, icon('problem'), `Another source is named ${proposed}. The box refuses two sources of one name; pick another.`)
          : el('span', { class: 'field__hint' }, 'Saved as ', mono(proposed), ': lowercase letters, digits, - and _, up to 32 characters. Users see this name in the box.')),
      el('div', { class: 'btn-row' }, btn('Rename', () => { if (!dup) { s.name = proposed; s.renaming = null; drawSources(); changed(); } }, { cls: 'btn--sm btn--primary', disabled: dup }),
        btn('Cancel', () => { s.renaming = null; drawSources(); }, { cls: 'btn--sm btn--quiet' })));
  })() : null;
  return el('article', { class: 'srccard', id, 'aria-labelledby': `${id}-n` },
    el('div', { class: 'srccard__head' },
      el('span', { class: 'srccard__kind' }, icon(kindIcon[s.kind.type] ?? 'folder')),
      el('div', {},
        el('div', { class: 'srccard__title' }, el('h3', { class: 'srccard__name', id: `${id}-n` }, s.name), pill('plain', kindWord[s.kind.type] ?? s.kind.type),
          s.mark === 'from-file' && (unbrowsable || local) ? pill('not-checked', 'From the file') : null,
          s.mark === 'added' ? pill('plain', 'Just added') : null, s.mark === 'reattached' ? pill('done', 'Reattached') : null),
        el('p', { class: 'srccard__where' }, where(s))),
      el('div', { class: 'srccard__tools' },
        el('label', { class: 'visually-hidden', for: `${id}-sens` }, `Sensitivity of ${s.name}`), levelSelect(s, `${id}-sens`),
        el('details', { class: 'menu' }, el('summary', { class: 'btn btn--quiet btn--icon', 'aria-label': `More for ${s.name}` }, icon('more')),
          el('div', { class: 'menu__list' },
            el('button', { class: 'menu__item', type: 'button', onclick: () => { s.renaming = s.name; drawSources(); } }, icon('settings'), 'Rename'),
            el('hr', { class: 'menu__sep' }),
            el('button', { class: 'menu__item menu__item--destructive', type: 'button', onclick: () => removeSource(s) }, icon('wipe'), `Remove ${s.name}`,
              el('span', { class: 'menu__hint' }, 'Undo stays offered for a few seconds')))))),
    rename,
    el('div', { class: 'srccard__reach' },
      n ? [el('div', { class: 'srccard__reachhead' }, el('span', {}, b('In reach:'), ` ${plural(n, 'folder')}`), el('span', { class: 'spacer' }),
        local ? null : unbrowsable ? btn('Find its site again', () => openAdd('sp'), { cls: 'btn--sm', ico: 'search' }) : btn('Pick folders', () => openScope(s), { cls: 'btn--sm', ico: 'folder' })),
      el('div', { class: 'cluster' }, s.scope.map((p) => el('span', { class: 'chip' }, mono(p),
        el('button', { class: 'chip__remove', type: 'button', 'aria-label': `Remove ${p} from ${s.name}`, onclick: () => { s.scope = s.scope.filter((x) => x !== p); drawSources(); changed(); } }, icon('close')))))]
        : [el('div', { class: 'srccard__reachhead' }, pill('warning', 'No scope'), el('span', { class: 'spacer' }),
          local ? null : unbrowsable ? btn('Find its site again', () => openAdd('sp'), { cls: 'btn--sm', ico: 'search' }) : btn('Pick folders', () => openScope(s), { cls: 'btn--sm btn--primary', ico: 'folder' })),
        note('warning', whole(s), ' is in reach of the agent, as far as each user can open it.', local ? '' : ' Pick folders to narrow it, or leave it whole.')],
      unbrowsable ? note('info', `To pick more folders, find its site again: picking ${s.kind.address.siteUrl.split('/').pop()}, library ${s.kind.address.library}, reattaches it, and its folders are kept.`) : null,
      s.mark === 'reattached' ? note('info', 'Found again at the same site address and library, so this is still ', mono(s.name), `, with its name, sensitivity and ${plural(n, 'folder')}. Pick folders now browses it.`) : null,
      local ? note('info', 'A test folder on each device, from the opened file. Its folders are kept as written; Sluse Admin does not browse it.') : null));
}

/** A tool server's card (D-071): its tools in reach, each one's fixed
 * arguments, and Pick tools, which reads the server again. */
function mcpCard(s) {
  const id = `src-${s.name}`;
  const pins = s.kind.address.pins ?? {};
  return el('article', { class: 'srccard', id, 'aria-labelledby': `${id}-n` },
    el('div', { class: 'srccard__head' },
      el('span', { class: 'srccard__kind' }, icon('apps')),
      el('div', {},
        el('div', { class: 'srccard__title' }, el('h3', { class: 'srccard__name', id: `${id}-n` }, s.name), pill('plain', 'Tool server'),
          s.mark === 'from-file' ? pill('not-checked', 'From the file') : null, s.mark === 'added' ? pill('plain', 'Just added') : null),
        el('p', { class: 'srccard__where' }, where(s))),
      el('div', { class: 'srccard__tools' },
        el('label', { class: 'visually-hidden', for: `${id}-sens` }, `Sensitivity of ${s.name}`), levelSelect(s, `${id}-sens`),
        el('details', { class: 'menu' }, el('summary', { class: 'btn btn--quiet btn--icon', 'aria-label': `More for ${s.name}` }, icon('more')),
          el('div', { class: 'menu__list' },
            el('button', { class: 'menu__item menu__item--destructive', type: 'button', onclick: () => removeSource(s) }, icon('wipe'), `Remove ${s.name}`,
              el('span', { class: 'menu__hint' }, 'Undo stays offered for a few seconds')))))),
    el('div', { class: 'srccard__reach' },
      el('div', { class: 'srccard__reachhead' }, el('span', {}, b('In reach:'), ` ${plural(s.scope.length, 'tool')}`), el('span', { class: 'spacer' }),
        btn('Pick tools', () => editMcp(s), { cls: 'btn--sm', ico: 'apps' })),
      el('div', { class: 'cluster' }, s.scope.map((t) => el('span', { class: 'chip' }, mono(t),
        pins[t] ? el('span', { class: 't-muted' }, ` (${Object.entries(pins[t]).map(([k, v]) => `${k} = ${JSON.stringify(v)}`).join(', ')})`) : null))),
      note('info', 'Sluse calls only these, as each user. It cannot tell whether a tool changes anything: keep only tools that read.')));
}

function removeSource(s) {
  const at = S.sources.indexOf(s);
  S.sources.splice(at, 1);
  drawSources(); changed();
  toast(`Removed ${s.name}.`, { label: 'Undo', fn: () => { S.sources.splice(at, 0, s); drawSources(); changed(); } });
}

// The folders each user fills (D-054): a source of their kind, or none.
for (const row of document.querySelectorAll('[data-uf]')) {
  row.querySelector('input[type=checkbox]').onchange = (e) => {
    const type = row.dataset.uf;
    S.sources = S.sources.filter((s) => s.kind.type !== type);
    if (e.target.checked) S.sources.push({ name: type, kind: { type }, scope: [], sensitivity: Number($(`sens-${type}`).value) || 2 });
    drawSources(); changed();
  };
}
$('dep-name').oninput = () => { fill($('dep-hint'), `Intune's app is named after it, for example "Sluse: ${depName() || 'Pilot'}, revision ${nextRevision()}".`); changed(); };

// ---- Add a source -------------------------------------------------------------------
const ADD = { tab: 'sp', sp: { state: 'idle' }, tm: { state: 'idle' }, share: '', mcp: { state: 'idle' } };
function openAdd(tab = 'sp') {
  ADD.tab = tab;
  if (tab === 'sp' && ADD.sp.state === 'libs') ADD.sp = { ...ADD.sp, state: ADD.sp.sites ? 'results' : 'idle' };
  drawAdd();
  const d = $('dlg-add');
  for (const m of document.querySelectorAll('details.menu[open]')) m.open = false;
  d.showModal();
}
const sameLibrary = (s, site, lib) => s.kind.type === 'sharepoint' && s.kind.address.siteUrl.toLowerCase().replace(/\/$/, '') === site.url.toLowerCase().replace(/\/$/, '')
  && s.kind.address.library.toLowerCase() === lib.name.toLowerCase();

function drawAdd() {
  for (const t of document.querySelectorAll('#dlg-add [data-tab]')) t.setAttribute('aria-selected', String(t.dataset.tab === ADD.tab));
  $('pane-sp').hidden = ADD.tab !== 'sp';
  $('pane-tm').hidden = ADD.tab !== 'tm';
  $('pane-sh').hidden = ADD.tab !== 'sh';
  $('pane-mcp').hidden = ADD.tab !== 'mcp';
  const t = tenantWord() ?? 'your tenant';
  fill($('add-as'), S.who ? `You browse as ${S.who.account}. Each user still reaches only what they can open themselves.` : 'Each user still reaches only what they can open themselves.');
  const go = $('add-go');
  const sp = ADD.sp;
  const orphan = S.sources.find((s) => s.kind.type === 'sharepoint' && !s.driveId);
  fill($('sp-note'),
    S.who ? null : note('warning', `Sign in to browse SharePoint: finding sites and Teams reads ${t} as you. A file share needs no sign-in. `,
      el('button', { class: 'btn--link', type: 'button', onclick: () => { $('dlg-add').close(); go_('start'); } }, 'Go to Start')),
    orphan ? note('info', `Pick ${orphan.kind.address.siteUrl.split('/').pop()}, library ${orphan.kind.address.library}, to reattach `, mono(orphan.name),
      ': the same site address and the same library are the same source, and its folders are kept. Another library is added as a new source.') : null);
  $('sp-search').hidden = sp.state === 'libs' || sp.state === 'nolibs' || sp.state === 'libs-loading';
  $('site-hint').hidden = sp.state !== 'idle';
  $('site-find').setAttribute('aria-busy', String(sp.state === 'searching'));
  fill($('sp-results'),
    ['searching', 'results', 'none'].includes(sp.state) ? el('div', { class: 'picklist' },
      sp.state === 'searching' ? el('div', { class: 'picklist__state' }, status('working', 'Finding sites…')) : null,
      sp.state === 'none' ? el('div', { class: 'empty', style: 'padding: var(--space-4)' }, el('span', { class: 'empty__icon' }, icon('search')),
        el('p', { class: 'empty__title' }, `No site matches "${sp.query}".`), el('p', { class: 'empty__text' }, "Check the spelling, or try a word from the site's name.")) : null,
      sp.state === 'results' ? [el('div', { class: 'rows' }, sp.sites.map((site) => el('button', { class: 'row', type: 'button', onclick: () => pickSite(site) },
        icon('library'), el('span', { class: 'row__main' }, site.name, el('br'), el('span', { class: 'mono t-muted' }, site.url)), icon('chevron-right')))),
      el('div', { class: 'picklist__foot' }, el('span', {}, `${plural(sp.sites.length, 'site')}. Pick one to see its libraries.`))] : null) : null,
    ['libs', 'nolibs', 'libs-loading'].includes(sp.state) ? el('div', { class: 'stack', style: '--stack-gap: var(--space-2)' },
      el('ol', { class: 'crumbs' }, el('li', {}, el('button', { type: 'button', onclick: () => { ADD.sp.state = ADD.sp.sites ? 'results' : 'idle'; drawAdd(); } }, ADD.sp.fromTeams ? 'Teams' : 'Sites')),
        el('li', {}, el('span', { 'aria-current': 'page' }, sp.site.name))),
      el('div', { class: 'picklist' },
        sp.state === 'libs-loading' ? el('div', { class: 'picklist__state' }, status('working', 'Reading libraries…')) : null,
        sp.state === 'nolibs' ? el('div', { class: 'empty', style: 'padding: var(--space-4)' }, el('span', { class: 'empty__icon' }, icon('library')),
          el('p', { class: 'empty__title' }, `${sp.site.name} has no document library you can open.`), el('p', { class: 'empty__text' }, `You browse as ${S.who?.account ?? 'yourself'}. Pick another site, or ask its owner for access.`)) : null,
        sp.state === 'libs' ? el('ul', { class: 'rows', role: 'radiogroup', 'aria-label': `Libraries in ${sp.site.name}` }, sp.libs.map((lib) => {
          const already = S.sources.find((s) => sameLibrary(s, sp.site, lib));
          return el('li', { class: 'row' }, el('label', { class: 'radio' }, el('input', { type: 'radio', name: 'lib', checked: sp.lib?.id === lib.id, onchange: () => { sp.lib = lib; drawAdd(); } }),
            el('span', { class: 'radio__dot' }), icon('folder'), lib.name), already ? el('span', { class: 'row__meta' }, `Already a source: ${already.name}`) : null);
        })) : null)) : null,
    sp.state === 'error' ? banner('problem', 'Microsoft Graph refused the site search.', 'Your sign-in may have expired, or your account cannot read sites. Sign in again, then search again.', { raw: sp.error }) : null);

  const tm = ADD.tm;
  fill($('tm-lead'), `A Team is a way to find its SharePoint site; the source is the site's library. Listing reads every Team in ${t}, one at a time.`);
  fill($('tm-body'),
    tm.state === 'idle' ? el('div', { class: 'btn-row' }, btn('List Teams', listTeams, { ico: 'group' })) : null,
    tm.state === 'reading' ? el('div', { class: 'ad-wait' },
      el('div', { class: 'wait__head' }, el('p', { class: 'wait__title' }, 'Listing Teams'), el('p', { class: 'wait__clock', 'data-label': 'Waiting', id: 'tm-clock' }, clock(tm.since))),
      el('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': tm.of || 0, 'aria-valuenow': tm.read || 0, 'aria-label': 'Teams read', style: `--value: ${tm.of ? Math.round((100 * tm.read) / tm.of) : 0}%` }, el('div', { class: 'progress__fill' })),
      el('p', { class: 'wait__meta' }, tm.of ? `${tm.read} of ${tm.of} Teams read. ` : '', 'A Team whose site cannot be read is left out and named at the end.')) : null,
    tm.state === 'done' ? [el('div', { class: 'picklist' }, el('div', { class: 'rows' }, tm.sites.map((site) => el('button', { class: 'row', type: 'button', onclick: () => { ADD.tab = 'sp'; pickSite(site, true); } },
      icon('group'), el('span', { class: 'row__main' }, site.name, el('br'), el('span', { class: 'mono t-muted' }, site.url)), icon('chevron-right')))),
    el('div', { class: 'picklist__foot' }, el('span', {}, tm.skipped.length ? `${tm.sites.length} of ${tm.sites.length + tm.skipped.length} Teams.` : `${plural(tm.sites.length, 'Team')}.`),
      el('span', { class: 'spacer' }), btn('List again', listTeams, { cls: 'btn--sm btn--quiet', ico: 'refresh' }))),
    tm.skipped.length ? el('div', { class: 'note', 'data-kind': 'warning' }, el('div', { class: 'stack', style: '--stack-gap: var(--space-1)' },
      el('span', {}, `${plural(tm.skipped.length, "Team's site", "Teams' sites")} could not be read and ${tm.skipped.length === 1 ? 'is' : 'are'} left out. The other ${tm.sites.length} are listed.`),
      el('ul', { class: 'ad-skipped' }, tm.skipped.map((k) => el('li', {}, b(k.name), `: ${k.reason}`))),
      el('span', { class: 't-small' }, 'To add one of these, ask its owner for access, or find its site by name under SharePoint site.'))) : null] : null,
    tm.state === 'error' ? banner('problem', 'Microsoft Graph did not list the Teams.', 'Your sign-in may have expired. Sign in again, then list them again.', { raw: `Listing Teams: ${tm.error}`, actions: [btn('List again', listTeams, { cls: 'btn--sm', ico: 'refresh' })] }) : null);

  const unc = $('share-path').value.trim();
  const valid = /^\\\\[^\\]+\\[^\\]+/.test(unc);
  const invalid = unc !== '' && !valid;
  $('share-field').classList.toggle('field--invalid', invalid);
  $('share-path').setAttribute('aria-invalid', String(invalid));
  $('share-msg').hidden = !invalid;
  $('share-hint').hidden = invalid;

  if (ADD.tab === 'sh') { fill(go, 'Add the share'); go.disabled = !valid; go.className = 'btn btn--primary'; return; }
  if (ADD.tab === 'mcp') { drawMcp(); return; }
  if (ADD.tab === 'sp' && sp.state === 'libs' && sp.lib) {
    const already = S.sources.find((s) => sameLibrary(s, sp.site, sp.lib));
    fill(go, already ? (already.driveId ? `${already.name} is already a source` : `Reattach ${already.name}`) : `Add ${sp.lib.name}`);
    go.disabled = !!already?.driveId;
    return;
  }
  fill(go, 'Add the library');
  go.disabled = true;
}
const go_ = (s) => go(s);

async function findSites() {
  const query = $('site-query').value.trim();
  if (!S.who) return;
  ADD.sp = { state: 'searching', query };
  drawAdd();
  try {
    const sites = await invoke('admin_sites', { query });
    ADD.sp = { state: sites.length ? 'results' : 'none', sites, query };
  } catch (e) {
    ADD.sp = { state: 'error', query, error: `Finding sites: ${e}` };
    sawError(e);
  }
  drawAdd();
}
async function pickSite(site, fromTeams = false) {
  ADD.sp = { ...ADD.sp, state: 'libs-loading', site, lib: null, fromTeams };
  drawAdd();
  try {
    const libs = await invoke('admin_libraries', { site: site.id });
    ADD.sp = { ...ADD.sp, state: libs.length ? 'libs' : 'nolibs', libs, lib: libs.length === 1 ? libs[0] : null };
  } catch (e) {
    ADD.sp = { ...ADD.sp, state: 'error', error: `Reading libraries: ${e}` };
    sawError(e);
  }
  drawAdd();
}
async function listTeams() {
  if (!S.who) { ADD.tm = { state: 'error', error: 'not signed in' }; drawAdd(); return; }
  ADD.tm = { state: 'reading', since: Date.now(), read: 0, of: 0 };
  drawAdd();
  try {
    const r = await invoke('admin_teams');
    ADD.tm = { state: 'done', sites: r.sites, skipped: r.skipped };
  } catch (e) {
    ADD.tm = { state: 'error', error: String(e) };
    sawError(e);
  }
  drawAdd();
}
listen('teams-progress', (e) => { if (ADD.tm.state === 'reading') { [ADD.tm.read, ADD.tm.of] = e.payload; drawAdd(); } });

$('add-go').onclick = () => {
  if (ADD.tab === 'mcp') { addMcp(); return; }
  if (ADD.tab === 'sh') {
    const unc = $('share-path').value.trim();
    const [server, share] = unc.split('\\').filter(Boolean);
    const name = uniqueName(`${server}-${share}`);
    S.sources.push({ name, kind: { type: 'smb', address: { unc } }, scope: [], sensitivity: 2, mark: 'added' });
    $('share-path').value = '';
    toast(`Added ${name}.`);
  } else {
    const { site, lib } = ADD.sp;
    const already = S.sources.find((s) => sameLibrary(s, site, lib));
    if (already) {
      already.driveId = lib.id;
      already.mark = 'reattached';
      toast(`Reattached ${already.name}. ${already.scope.length ? `Its ${plural(already.scope.length, 'folder')} ${already.scope.length === 1 ? 'is' : 'are'} kept.` : ''}`);
    } else {
      const name = uniqueName(site.name);
      S.sources.push({ name, kind: { type: 'sharepoint', address: { siteUrl: site.url, library: lib.name } }, scope: [], sensitivity: 2, driveId: lib.id, mark: 'added' });
      toast(`Added ${name}. Pick its folders next.`);
    }
    ADD.sp = { state: 'idle' };
  }
  $('dlg-add').close();
  drawSources(); changed();
};
for (const t of document.querySelectorAll('#dlg-add [data-tab]')) t.onclick = () => { ADD.tab = t.dataset.tab; drawAdd(); };
$('site-find').onclick = findSites;
$('mcp-read').onclick = readMcp;
$('mcp-list').onclick = listMcp;
$('share-path').oninput = drawAdd;

// ---- A tool server (D-071) --------------------------------------------------------------
/** The server's permission on Sluse's app, admin consent for it, then its
 * tools as Sluse's app reads them: the version it answered is kept. */
async function readMcp() {
  const url = $('mcp-url').value.trim(), scope = $('mcp-scope').value.trim();
  const m = ADD.mcp;
  if (!S.who) { ADD.mcp = { ...m, state: 'error', error: 'not signed in' }; drawAdd(); return; }
  if (!clientId()) { ADD.mcp = { ...m, state: 'error', error: "Sluse's app is not set up" }; drawAdd(); return; }
  ADD.mcp = { ...m, url, scope, state: 'requiring' };
  drawAdd();
  try {
    const r = await invoke('admin_mcp_require', { scope });
    ADD.mcp = { ...ADD.mcp, resource: r.resource, added: r.added };
    if (!r.consented) { ADD.mcp.state = 'consent'; drawAdd(); return; }
    await probeMcp();
  } catch (e) {
    ADD.mcp = { ...ADD.mcp, state: 'error', error: String(e) };
    sawError(e);
    drawAdd();
  }
}
/** The permissions the server's app offers, to pick one (L1, 2026-10-28:
 * Azure DevOps MCP's names are documented nowhere). */
async function listMcp() {
  const typed = $('mcp-scope').value.trim();
  if (!S.who) { ADD.mcp = { ...ADD.mcp, state: 'error', error: 'not signed in' }; drawAdd(); return; }
  if (!typed) { $('mcp-scope').focus(); return; }
  ADD.mcp = { ...ADD.mcp, state: 'listing' }; drawAdd();
  try {
    ADD.mcp = { ...ADD.mcp, state: 'offered', offered: await invoke('admin_mcp_offered', { typed }) };
  } catch (e) {
    ADD.mcp = { ...ADD.mcp, state: 'error', error: String(e) };
    sawError(e);
  }
  drawAdd();
}
function pickScope(o) {
  $('mcp-scope').value = `${ADD.mcp.offered.resource}/${o.value}`;
  ADD.mcp = { ...ADD.mcp, state: 'chosen', chosen: o.value };
  drawAdd();
}
async function consentAgain() {
  ADD.mcp.state = 'requiring'; drawAdd();
  try {
    if (await invoke('admin_mcp_consented', { scope: ADD.mcp.scope })) { await probeMcp(); return; }
    ADD.mcp.state = 'consent'; ADD.mcp.notYet = true;
  } catch (e) { ADD.mcp = { ...ADD.mcp, state: 'error', error: String(e) }; sawError(e); }
  drawAdd();
}
async function probeMcp() {
  ADD.mcp.state = 'probing'; drawAdd();
  try {
    const p = await invoke('admin_mcp_probe', { url: ADD.mcp.url, scope: ADD.mcp.scope, client: clientId() });
    const keep = ADD.mcp.editing;
    ADD.mcp = { ...ADD.mcp, state: 'tools', probe: p,
      picked: new Set(keep ? keep.scope.filter((t) => p.tools.some((x) => x.name === t)) : []),
      pins: structuredClone(keep?.kind.address.pins ?? {}) };
  } catch (e) {
    ADD.mcp = { ...ADD.mcp, state: 'error', error: String(e) };
    sawError(e);
  }
  drawAdd();
}
/** A pin's value as the tool's schema types the argument. */
function pinValue(schema, raw) {
  const t = schema?.type;
  if (t === 'number' || t === 'integer') return Number(raw);
  if (t === 'boolean') return raw === 'true';
  return raw;
}
function drawMcp() {
  const m = ADD.mcp;
  const go = $('add-go');
  $('mcp-read').setAttribute('aria-busy', String(['requiring', 'probing'].includes(m.state)));
  $('mcp-list').setAttribute('aria-busy', String(m.state === 'listing'));
  const made = (r) => r?.made ? note('info', `${r.name} was not in your tenant yet: Sluse Admin added it as an enterprise application, as Microsoft does the first time a vendor's app is used.`) : null;
  fill($('mcp-body'),
    m.state === 'listing' ? status('working', "Reading the permissions the server's app offers…") : null,
    m.state === 'offered' ? [made(m.offered),
      m.offered.scopes.length
        ? [el('p', { class: 't-small' }, `${m.offered.name} offers these permissions. Pick one that only reads: Sluse's app gets it, and the server lets the agent do no more than it allows.`),
          el('ul', { class: 'rows' }, m.offered.scopes.map((o) => el('li', { class: 'row', style: 'flex-wrap: wrap' },
            el('span', { class: 'row__main' }, mono(o.value), o.name ? ` ${o.name}` : '', o.description ? [el('br'), el('span', { class: 't-small t-muted' }, o.description)] : null),
            btn('Use this', () => pickScope(o), { cls: 'btn--sm' }))))]
        : note('warning', `${m.offered.name} offers no delegated permissions here. Check its documentation for the app it uses.`)] : null,
    m.state === 'chosen' ? note('info', `${m.chosen} is filled in. Read its tools next: Sluse's app gets the permission, then waits for your admin consent.`) : null,
    m.state === 'requiring' ? status('working', "Adding the server's permission to Sluse's app…") : null,
    m.state === 'probing' ? status('working', "Signing in as Sluse's app for this permission, then asking the server which MCP version it speaks and which tools it has. Microsoft's sign-in may ask you to confirm.") : null,
    m.state === 'consent' ? made(m.resource) : null,
    m.state === 'consent' ? banner(m.notYet ? 'warning' : 'info', `${m.resource.name}'s ${m.resource.scope} is on Sluse's app${m.added ? ' now' : ''}, without admin consent yet.`,
      `Open the portal at Sluse Gate's API permissions and click Grant admin consent for your organisation. The line for ${m.resource.name}, ${m.resource.scope}, then says Granted. Check again here: Sluse signs in as its app for this permission, learns which MCP version the server speaks, and reads its tools.${m.notYet ? ' Consent was not there yet; Entra can take a minute to show it.' : ''}`,
      { actions: [btn('Open the portal', () => invoke('admin_open_portal', { appId: clientId() }), { cls: 'btn--sm', ico: 'external' }), btn('Check again', consentAgain, { cls: 'btn--sm btn--primary', ico: 'refresh' })] }) : null,
    m.state === 'error' ? banner('problem', m.error === 'not signed in' ? 'Sign in first.' : m.error === "Sluse's app is not set up" ? "Sluse's app is not set up yet." : 'The tool server could not be read.',
      m.error === 'not signed in' ? 'Reading a tool server checks its permission in your tenant as you.' : m.error === "Sluse's app is not set up" ? 'Make it at Tenant first: the server is read as that app.'
        : 'Check the address and the permission, then read it again.', { raw: m.error }) : null,
    m.state === 'tools' ? [
      el('p', { class: 't-small' }, `Speaks MCP ${m.probe.protocol}, which Sluse keeps for this server. Tick the tools the agent may call; keep only tools that read.`),
      el('ul', { class: 'rows' }, m.probe.tools.map((t) => {
        const on = m.picked.has(t.name);
        const props = Object.entries(t.inputSchema?.properties ?? {});
        return el('li', { class: 'row', style: 'flex-wrap: wrap' },
          el('label', { class: 'check' }, el('input', { type: 'checkbox', checked: on, onchange: (e) => { e.target.checked ? m.picked.add(t.name) : m.picked.delete(t.name); drawAdd(); } }),
            el('span', { class: 'check__box' }), mono(t.name)),
          t.readOnly === true ? pill('plain', 'The server says it only reads') : t.readOnly === false ? pill('warning', 'The server says it changes things') : null,
          el('span', { class: 'row__meta' }, t.description ?? ''),
          on && props.length ? el('div', { class: 'stack', style: 'width: 100%; --stack-gap: var(--space-1)' },
            el('span', { class: 't-small t-muted' }, 'Fix an argument, and the agent cannot set it:'),
            props.map(([k, schema]) => el('label', { class: 'field' }, el('span', { class: 'field__label' }, mono(k)),
              el('input', { class: 'input input--mono', type: 'text', placeholder: 'The agent sets it', value: m.pins[t.name]?.[k] ?? '',
                onchange: (e) => {
                  const v = e.target.value.trim();
                  m.pins[t.name] = { ...(m.pins[t.name] ?? {}) };
                  if (v === '') delete m.pins[t.name][k]; else m.pins[t.name][k] = pinValue(schema, v);
                  if (!Object.keys(m.pins[t.name]).length) delete m.pins[t.name];
                } })))) : null);
      }))] : null);
  fill(go, m.editing ? `Use ${plural(m.picked?.size ?? 0, 'tool')}` : 'Add the tool server');
  go.disabled = m.state !== 'tools' || !m.picked.size;
}
function addMcp() {
  const m = ADD.mcp;
  const tools = [...m.picked];
  const pins = Object.fromEntries(Object.entries(m.pins).filter(([t]) => m.picked.has(t)));
  const address = { url: m.url, entraScope: m.scope, protocol: m.probe.protocol, ...(Object.keys(pins).length ? { pins } : {}) };
  if (m.editing) {
    m.editing.kind = { type: 'mcp', address };
    m.editing.scope = tools;
    m.editing.mark = null;
    toast(`${m.editing.name}: ${plural(tools.length, 'tool')}.`);
  } else {
    const name = uniqueName(new URL(m.url).hostname.split('.')[0] || 'tools');
    S.sources.push({ name, kind: { type: 'mcp', address }, scope: tools, sensitivity: 2, mark: 'added' });
    toast(`Added ${name}.`);
  }
  ADD.mcp = { state: 'idle' };
  $('mcp-url').value = ''; $('mcp-scope').value = '';
  $('dlg-add').close();
  drawSources(); changed();
}
/** Pick tools again: the server read again, what was picked kept. */
function editMcp(s) {
  ADD.mcp = { state: 'idle', editing: s };
  $('mcp-url').value = s.kind.address.url; $('mcp-scope').value = s.kind.address.entraScope;
  openAdd('mcp');
  readMcp();
}

// ---- Pick folders -------------------------------------------------------------------
const SCOPE = { s: null, picked: [], tree: null, error: null };
function openScope(s) {
  Object.assign(SCOPE, { s, picked: [...s.scope], tree: null, error: null });
  fill($('sc-t'), `Folders in reach: ${s.name}`);
  fill($('sc-where'), where(s));
  fill($('sc-as'), s.kind.type === 'smb' ? 'You browse as your own Windows account on this PC. Each user still reaches only what they can open themselves.'
    : `You browse as ${S.who?.account ?? 'yourself'}. Each user still reaches only what they can open themselves.`);
  drawScope();
  show($('dlg-scope')).then((v) => {
    if (v !== 'ok') return;
    s.scope = [...SCOPE.picked];
    drawSources(); changed();
    toast(s.scope.length ? `${s.name}: ${plural(s.scope.length, 'folder')} in reach.` : `${s.name}: the whole source is in reach.`);
  });
  readFolders(null).then((kids) => { if (kids) { SCOPE.tree = kids; drawScope(); } });
}
async function readFolders(node) {
  const s = SCOPE.s;
  try {
    return await (s.kind.type === 'sharepoint' ? invoke('admin_folders', { drive: s.driveId, item: node?.id || null })
      : invoke('admin_share_folders', { root: s.kind.address.unc, rel: node?.path ?? '' }));
  } catch (e) {
    if (!node) { SCOPE.error = String(e); drawScope(); }
    sawError(e);
    return null;
  }
}
function drawScope() {
  const s = SCOPE.s;
  const row = (f) => {
    const open = !!f.open;
    const leaf = f.count === 0;
    return el('li', {},
      el('div', { class: 'tree__row' },
        leaf ? el('button', { class: 'tree__toggle tree__toggle--leaf', type: 'button', tabindex: -1, 'aria-hidden': 'true' })
          : el('button', { class: 'tree__toggle', type: 'button', 'aria-expanded': String(open), 'aria-label': `${open ? 'Close' : 'Open'} ${f.name}`, onclick: async () => {
            f.open = !open;
            if (f.open && !f.kids) { f.loading = true; drawScope(); f.kids = (await readFolders(f)) ?? []; f.loading = false; }
            drawScope();
          } }, icon('chevron-right')),
        el('label', { class: 'check' }, el('input', { type: 'checkbox', checked: SCOPE.picked.includes(f.path), onchange: (e) => {
          SCOPE.picked = e.target.checked ? [...SCOPE.picked, f.path] : SCOPE.picked.filter((p) => p !== f.path);
          drawScope();
        } }), el('span', { class: 'check__box' }), f.name),
        f.count != null ? el('span', { class: 'tree__count' }, plural(f.count, 'item')) : null),
      open ? el('ul', {}, f.loading ? el('li', {}, el('div', { class: 'tree__status' }, icon('spinner', 'icon--spinner'), 'Reading folders…'))
        : f.kids?.length ? f.kids.map(row) : el('li', {}, el('div', { class: 'tree__status' }, icon('dash'), `No folders here, only files. Tick ${f.name} to bring them.`))) : null);
  };
  const smb = s.kind.type === 'smb';
  fill($('sc-tree'),
    SCOPE.error ? banner('problem', smb ? ['Windows refused ', mono(s.kind.address.unc), ' to your account.'] : "Microsoft Graph could not read this library's folders.",
      smb ? 'Sluse Admin browses the share as your Windows account on this PC. Users reach it as themselves, so they may see more or less than you. Without folders ticked, the whole share stays in reach.'
        : 'The library may have moved, or your sign-in expired. Sign in again, or find the site again.', { raw: `Reading folders: ${SCOPE.error}` })
      : !SCOPE.tree ? el('div', { class: 'tree__status' }, icon('spinner', 'icon--spinner'), 'Reading folders…')
        : SCOPE.tree.length ? el('ul', { class: 'tree', 'aria-label': `Folders in ${s.name}` }, SCOPE.tree.map(row))
          : el('div', { class: 'tree__status' }, icon('dash'), 'No folders here, only files. With nothing ticked, the whole source is in reach.'));
  const inside = SCOPE.picked.map((p) => [p, SCOPE.picked.find((q) => q !== p && p.toLowerCase().startsWith(`${q.toLowerCase()}/`))]).filter(([, q]) => q);
  fill($('sc-chips'),
    SCOPE.picked.length ? el('div', { class: 'cluster' }, SCOPE.picked.map((p) => el('span', { class: 'chip' }, mono(p),
      el('button', { class: 'chip__remove', type: 'button', 'aria-label': `Remove ${p}`, onclick: () => { SCOPE.picked = SCOPE.picked.filter((x) => x !== p); drawScope(); } }, icon('close')))))
      : el('p', { class: 't-small' }, `Nothing ticked: the whole ${smb ? 'share' : s.kind.type === 'sharepoint' ? 'library' : 'source'}.`),
    inside.map(([p, q]) => note('info', `${p} is inside ${q}, which is already in reach. It changes nothing; remove it or keep it.`)));
  const n = SCOPE.picked.length;
  fill($('sc-go'), n ? `Use ${n === 1 ? 'this folder' : `these ${n} folders`}` : `Keep the whole ${smb ? 'share' : s.kind.type === 'sharepoint' ? 'library' : 'source'}`);
}

// ---- Egress -------------------------------------------------------------------------
const SHARED = ['sharepoint.com', 'onmicrosoft.com', 'blob.core.windows.net', 'azurewebsites.net', 'amazonaws.com', 'cloudfront.net', 'googleapis.com',
  'googleusercontent.com', 'appspot.com', 'herokuapp.com', 'github.io', 'githubusercontent.com', 'vercel.app', 'netlify.app', 'workers.dev', 'pages.dev'];
const SIGN_IN = ['login.microsoftonline.com', 'login.microsoft.com', 'login.windows.net', 'device.login.microsoftonline.com'];
const measuredWords = (m) => { const d = /^(\d{4}-\d{2}-\d{2})/.exec(m ?? ''); return d ? `measured ${day(d[1])}` : 'not yet measured'; };
/** What the opened file's catalog had for a bundle: hosts the file lists. */
const newHosts = (bd) => S.file && (S.file.authored.egress?.catalog ?? 0) < S.catalog.version && S.file.authored.egress?.bundles?.includes(bd.id)
  ? bd.hosts.filter((h) => !(S.file.authored.egress.allow ?? []).includes(h)) : [];

function buildBundles() {
  if (!S.catalog) return;
  fill($('catalog-version'), `Catalog version ${S.catalog.version}, shipped with this Sluse Admin`);
  fill($('bundles'), S.catalog.bundles.map((bd) => {
    const added = newHosts(bd);
    return el('li', { class: 'ad-bundle' },
      el('label', { class: 'check' }, el('input', { type: 'checkbox', checked: bd.locked || S.bundles.has(bd.id), disabled: bd.locked, 'aria-label': bd.locked ? `${bd.name}, always on` : bd.name,
        onchange: (e) => { if (e.target.checked) S.bundles.add(bd.id); else S.bundles.delete(bd.id); drawEgress(); changed(); } }), el('span', { class: 'check__box' })),
      el('div', { class: 'ad-bundle__body' },
        el('div', { class: 'ad-bundle__title' }, b(bd.name), bd.locked ? pill('on', 'Always on') : null, bd.uploads ? pill('warning', 'Takes uploads') : null,
          added.length ? pill('changed', `${plural(added.length, 'host')} added`) : null),
        el('p', { class: 'ad-bundle__text' }, bd.description),
        el('details', { class: 'disclosure' }, el('summary', {}, `${plural(bd.hosts.length, 'host')}, ${measuredWords(bd.measured)}`),
          el('div', { class: 'disclosure__body' }, el('div', { class: 'ad-hostchips' }, bd.hosts.map((h) => el('code', { class: 'mono-inline' }, h))),
            bd.measured ? el('p', { class: 't-small t-muted' }, bd.measured) : null))));
  }));
}

function hostHint(h) {
  const sharepoint = S.sources.filter((s) => s.kind.type === 'sharepoint').map((s) => s.kind.address.siteUrl.replace(/^https:\/\//, '').split('/')[0].toLowerCase());
  if (/:\/\/|\/|:\d+$/.test(h)) {
    const clean = h.replace(/^[a-z]+:\/\//, '').split('/')[0].split(':')[0];
    return ['problem', ['Not a host name. Write ', mono(clean), '; the box refuses a scheme or a path.']];
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) return ['problem', "An address, not a host name. The box refuses addresses; write the host's name."];
  if (SIGN_IN.includes(h)) return ['warning', "Microsoft's sign-in. With it, something in the box can get the user's own SharePoint token and use it past the scopes and the record of admissions. The AI apps sign in on the computer instead."];
  if (sharepoint.includes(h) || /\.sharepoint\.com$/.test(h) && !h.startsWith('*.')) return ['warning', 'Your SharePoint, which the box does not need: Sluse brings its files. On the list, it is a way around the scopes for anything in the box with a token.'];
  if (h.startsWith('*.') && SHARED.some((s) => h.slice(2) === s || h.slice(2).endsWith(`.${s}`))) return ['warning', 'A name many organisations share: the box can reach whatever any of them hosts there.'];
  return ['info', 'Your own addition, not from a bundle.'];
}

function drawEgress() {
  if (!S.catalog) {
    fill($('egress-banner'), banner('problem', 'The bundle catalog could not be read.', 'It ships inside Sluse Admin, so this is a damaged install. Your own hosts below still work; repair or reinstall Sluse Admin to choose bundles.', { raw: `The bundle catalog: ${S.catalogError}` }));
    $('bundles-part').hidden = true;
  } else {
    const older = S.file && (S.file.authored.egress?.catalog ?? 0) < S.catalog.version;
    fill($('egress-banner'), older ? banner('info', 'The catalog changed since this file was saved.', 'Sluse never widens a box by itself: nothing changes on any device until you save and publish. Saving uses today\'s hosts for each ticked bundle, marked below. Review lists every host that changes.') : null);
  }
  const own = ownHosts();
  fill($('own-check'), own.map((h) => { const [k, t] = hostHint(h); return el('li', {}, el('code', { class: 'mono' }, h), el('span', { class: 'status', 'data-status': k }, t)); }));
  $('own-check').hidden = !own.length;
  $('own-hint').hidden = !own.length;
  const fromCatalog = (S.catalog?.bundles ?? []).flatMap((bd) => bd.hosts);
  $('own-from-file').hidden = !(S.file && (S.file.authored.egress?.allow ?? []).some((h) => !fromCatalog.includes(h)));
  const fileAllow = S.file?.authored.egress?.allow;
  const isNew = (h) => !!fileAllow && !fileAllow.includes(h);
  const groups = (S.catalog?.bundles ?? []).filter((bd) => bd.locked || S.bundles.has(bd.id)).map((bd) => [bd.name, bd.hosts]);
  if (own.length) groups.push(['Your own', own]);
  const all = allowList();
  fill($('host-count'), String(all.length));
  fill($('hostlist'), groups.map(([name, hosts]) => el('div', { class: 'hostlist__group' }, el('span', { class: 't-label' }, name),
    el('ul', {}, hosts.map((h) => el('li', { 'data-new': isNew(h) && name !== 'Your own' ? '' : null, title: isNew(h) && name !== 'Your own' ? 'New since the file was saved' : null }, h))))));
  $('hostlist-new').hidden = !all.some((h) => isNew(h) && !own.includes(h));
}
$('own-hosts').oninput = () => { drawEgress(); changed(); };
$('copy-hosts').onclick = () => clip(allowList().join('\n')).then(() => toast('Copied the list.'), () => {});

// ---- Advanced -----------------------------------------------------------------------
function drawCards(mem, disk) {
  const card = (name, value, word, current) => el('label', { class: 'choicecard' },
    el('input', { type: 'radio', name, value, checked: value === current, onchange: () => { drawAdvanced(); changed(); } }), b(`${value} GB`), word ? el('span', {}, word) : null);
  const memChoices = [[4, 'For light work'], [6, 'Default'], [8, 'Needs a 16 GB device']];
  const diskChoices = [[40, 'Default'], [80], [120]];
  fill($('mem-cards'), memChoices.map(([v, w]) => card('mem', v, w, mem)), memChoices.some(([v]) => v === mem) ? null : card('mem', mem, 'From the opened file', mem));
  fill($('disk-cards'), diskChoices.map(([v, w]) => card('disk', v, w, disk)), diskChoices.some(([v]) => v === disk) ? null : card('disk', disk, 'From the opened file', disk));
}
/** The volume alert in words (Q16, Q52): one sentence, used here and at Review. */
function volumeWords() {
  const f = num('v-files'), m = num('v-mb'), w = num('v-window');
  return `${f} different files${m ? `, or ${m} MB,` : ''} from one source within ${inWords(w)} raises a volume alert. Nothing is stopped.${m ? '' : ' With no MB, the alert counts files only: one large file raises nothing.'}`;
}
function drawAdvanced() {
  const f = num('v-files'), w = num('v-window');
  const badF = !(Number.isInteger(f) && f >= 1), badW = !(Number.isInteger(w) && w >= 1);
  $('f-files').classList.toggle('field--invalid', badF);
  $('v-files').setAttribute('aria-invalid', String(badF));
  $('f-secs').classList.toggle('field--invalid', badW);
  $('v-window').setAttribute('aria-invalid', String(badW));
  $('m-files').hidden = !badF;
  $('m-secs').hidden = !badW;
  fill($('w-words'), badW ? null : inWords(w));
  const p = $('v-preview');
  p.hidden = badF || badW;
  if (!p.hidden) fill(p, icon(num('v-mb') ? 'info' : 'warning'), el('span', {}, volumeWords()));
  const mem = radio('mem');
  const odd = ![4, 6, 8].includes(mem);
  $('mem-note').hidden = !(mem > 6);
  fill($('mem-note'), odd ? `The opened file asks for ${mem} GB, which is not one of the choices here. It is kept as it is unless you pick another. A box of ${mem} GB needs a device with about ${mem * 2} GB or more.`
    : `A box of ${mem} GB needs a device with about ${mem * 2} GB or more; on a smaller one, Windows gets little.`);
  const log = $('egress-log').checked;
  $('log-more').hidden = !log;
  const zero = log && !(num('egress-mb') >= 1);
  $('f-log').classList.toggle('field--invalid', zero);
  $('m-log').hidden = !zero;
}
for (const id of ['v-files', 'v-mb', 'v-window', 'fetch-mb', 'egress-mb', 'acc-workspaces', 'acc-claude']) $(id).oninput = () => { drawAdvanced(); changed(); };
for (const id of ['copy-out', 'egress-log']) $(id).onchange = () => { drawAdvanced(); changed(); };

// ---- Review -------------------------------------------------------------------------
const STEP_NAME = Object.fromEntries(STEPS);
/** A loader refusal in words: what, where to fix it, and the rail's line (Q57: one at a time). */
function refusal(e) {
  e = String(e ?? '');
  let m;
  const r = (title, text, step, rail) => ({ title, text, step, rail: rail ?? title });
  if ((m = /source "([^"]+)" reads through Microsoft Graph/.exec(e))) return { ...r(`${m[1]} reads through Microsoft Graph, and this configuration does not name Sluse's app.`, "Sign in and make or repair Sluse's app at Tenant, or open the saved configuration that names it.", 'tenant', 'Not named in this configuration'), open: true };
  if ((m = /source name "([^"]+)" is used twice/.exec(e))) return r(`Two sources are named ${m[1]}.`, 'Rename one of them at Sources.', 'sources', 'A source name used twice');
  if ((m = /egress\.allow: "([^"]+)" is not a host name/.exec(e))) return r(`${m[1]} is not a host name.`, ['In your own hosts at Egress, write ', mono(m[1].replace(/^[a-z]+:\/\//, '').split('/')[0].split(':')[0]), ', with no scheme, port, path or address.'], 'egress', 'An own host is not a host name');
  if ((m = /volume\.(\w+) is 0/.exec(e))) { const f = { admissions: 'Files', windowSeconds: 'Seconds', bytes: 'MB' }[m[1]] ?? m[1]; return r(`The volume alert's ${f} is 0, which would alert on every admission.`, 'Set it to 1 or more at Advanced.', 'advanced', `Volume alert: ${f} is 0`); }
  if (/egress\.log\.maxMB is 0/.test(e)) return r('The egress log is on with 0 MB.', 'Give it 1 MB or more at Advanced, or turn it off.', 'advanced', 'Egress log on with 0 MB');
  if (/defines no sources/.test(e)) return r('There is nothing for the box to read.', 'A box with no sources can admit nothing. Add a source, or turn on a folder each user fills, at Sources.', 'sources', 'No sources');
  if (/maxFetchBytes is 0/.test(e)) return r('The largest single fetch is 0, which would refuse every fetch. Leave it empty for no limit.', 'Change it at Advanced.', 'advanced', 'The largest fetch is 0');
  if ((m = /box\.(\w+) is 0/.exec(e))) return r(`The box's ${m[1] === 'homeGB' ? 'home disk' : 'memory'} is 0.`, 'Pick a size at Advanced.', 'advanced');
  if ((m = /source "([^"]+)": scope entry "([^"]+)"/.exec(e))) return r(`A folder of ${m[1]} is written in a way the box cannot use: ${m[2]}.`, 'Remove it at Sources and pick it again.', 'sources', 'A folder the box cannot use');
  if ((m = /source "([^"]+)": address "[^"]*" is not a UNC path/.exec(e))) return r(`${m[1]} is not a share path: write \\\\server\\share.`, 'Remove it at Sources and add the share again.', 'sources', 'Not a share path');
  if ((m = /source "([^"]+)": site URL/.exec(e))) return r(`${m[1]}'s site address must start with https://.`, 'Find its site again at Sources.', 'sources', 'A site address');
  if ((m = /source "([^"]+)" claims sensitivity/.exec(e))) return r(`${m[1]} has a sensitivity the box does not know.`, 'Pick one of the four at Sources.', 'sources', 'A sensitivity');
  if ((m = /source "([^"]+)": root/.exec(e))) return r(`${m[1]}'s folder must be a full path.`, 'Open the saved configuration and correct it, or remove the source at Sources.', 'sources');
  if (/entra\.\w+ "[^"]*" is not a GUID/.test(e)) return { ...r("Sluse's app is named wrongly in this configuration.", "Make or repair Sluse's app at Tenant, or open the saved configuration that names it.", 'tenant', "Sluse's app named wrongly"), open: true };
  if (/deployment\.id/.test(e)) return r("The deployment's id is not one the box accepts.", 'Open the saved configuration again, or start a new one.', 'start');
  if (/deployment\.revision/.test(e)) return r("The deployment's revision is not one the box accepts.", 'Open the saved configuration again, or start a new one.', 'start');
  if (/bundle catalog/.test(e)) return r('The bundle catalog could not be read, so the configuration cannot be written.', 'It ships inside Sluse Admin, so this is a damaged install. Repair or reinstall Sluse Admin.', 'egress', 'The bundle catalog could not be read');
  if (/does not match schema/.test(e)) return r('This configuration does not match schema 3.', "A field is not what schema 3 expects; the box's own words below name it.", null);
  return r('The box would refuse this configuration.', "The box's own words below say why.", null);
}

async function runReview() {
  S.review = { verdict: 'checking' };
  drawReview(); drawRail(); drawFoot();
  if (S.app.result && S.who && S.assigned.state !== 'loading') readAssigned();
  const at = new Date();
  try {
    const a = authored();
    const d = await invoke('admin_author', { authored: a });
    const diff = S.file ? await invoke('admin_diff', { old: S.file.authored, new: a }) : null;
    S.review = { verdict: 'accepted', at, a, draft: d, diff };
  } catch (e) {
    S.review = { verdict: 'refused', at, error: String(e?.message ?? e) };
  }
  drawReview(); drawRail(); drawFoot();
  return S.review;
}

const WARNING_STEP = { 'whole-source': 'sources', 'user-chosen': 'sources', 'mcp-server-trust': 'sources', uploads: 'egress', 'bundle-trimmed': 'egress', 'shared-wildcard': 'egress', 'sharepoint-host': 'egress',
  'own-host': 'egress', 'microsoft-sign-in': 'egress', 'box-memory': 'advanced', 'egress-log': 'advanced', 'no-byte-alert': 'advanced' };
const noGroup = () => S.assigned.state === 'read' && !S.assigned.list.length;
const knowCount = () => (S.review.draft?.warnings.length ?? 0) + (noGroup() ? 1 : 0);

function sourceWords(s) {
  const n = s.scope.length;
  const lvl = LEVELS.find(([v]) => v === s.sensitivity)?.[1] ?? '';
  const what = s.kind.type === 'sharepoint' ? (n ? `${plural(n, 'folder')} of the SharePoint library ${s.kind.address.library}` : `the whole SharePoint library ${s.kind.address.library}`)
    : s.kind.type === 'smb' ? (n ? [`${plural(n, 'folder')} of the share `, mono(s.kind.address.unc)] : ['the whole share ', mono(s.kind.address.unc)])
      : s.kind.type === 'onedrive' ? "each user's own OneDrive Sluse folder" : s.kind.type === 'inputs' ? "each user's own Sluse Inputs folder on the device"
        : s.kind.type === 'mcp' ? [`${plural(n, 'tool')} of the tool server `, mono(s.kind.address.url), `, called as each user`]
        : n ? [`${plural(n, 'folder')} of `, mono(s.kind.address.root)] : ['all of ', mono(s.kind.address.root)];
  return el('p', {}, mono(s.name), ': ', what, `. ${lvl}.`);
}

function drawReview() {
  const r = S.review;
  const sheet = $('sheet');
  sheet.dataset.verdict = r.verdict === 'refused' ? 'refused' : r.verdict === 'checking' || r.verdict === 'none' ? 'checking' : 'ok';
  const ok = r.verdict === 'accepted';
  const k = ok ? knowCount() : 0;
  const head = el('header', { class: 'ad-sheet__head' },
    el('span', { class: 'srccard__kind', style: 'width:48px;height:48px' }, icon(r.verdict === 'refused' ? 'problem' : 'journal', 'icon--lg')),
    el('div', {}, el('h2', { class: 't-h3 ad-sheet__title', id: 'sh-t' }, ok ? 'The box would accept this configuration.' : r.verdict === 'refused' ? 'The box would refuse this configuration.' : 'Checking the configuration…'),
      el('p', { class: 'ad-sheet__sub' }, ok ? `Checked at ${hhmm(r.at)} by the same check every box runs. ${k ? 'Read what to know below before you publish.' : 'Nothing to know before you publish.'}`
        : r.verdict === 'refused' ? `Checked at ${hhmm(r.at)}. Fix the one thing below, then check again; the check stops at the first thing it refuses.` : 'The same check every box runs when it starts.')),
    el('div', { class: 'stack', style: '--stack-gap: var(--space-2); justify-items: end' },
      ok ? pill('allowed', 'Accepted') : r.verdict === 'refused' ? pill('problem', 'Refused') : pill('checking', 'Checking'),
      r.verdict === 'checking' ? null : btn('Check again', runReview, { cls: 'btn--sm btn--quiet', ico: 'refresh' })));
  if (r.verdict === 'refused') {
    const why = refusal(r.error);
    fill(sheet, head, el('div', { style: 'padding: var(--space-6)' }, banner('problem', why.title, why.text, { raw: r.error, label: "The box's own words",
      actions: [why.step ? goBtn(`Go to ${STEP_NAME[why.step]}`, why.step) : null, why.open ? el('button', { class: 'btn btn--sm btn--quiet', type: 'button', 'data-act': 'open-file' }, icon('folder-open'), 'Open a saved configuration…') : null].filter(Boolean) })));
  } else if (!ok) {
    fill(sheet, head, el('div', { style: 'padding: var(--space-6)' }, status('working', "Running the box's own check on your choices…")));
  } else {
    const a = r.a;
    const dep = fileDeployment();
    const all = allowList();
    const ticked = (S.catalog?.bundles ?? []).filter((bd) => bd.locked || S.bundles.has(bd.id));
    const own = all.filter((h) => !ticked.some((bd) => bd.hosts.includes(h))).length;
    const uploads = ticked.filter((bd) => bd.uploads).length;
    const fetch = num('fetch-mb');
    const as = S.assigned;
    const row = (dt, dd, step, attention) => el('div', { class: `ad-sheet__row${attention ? ' ad-sheet__row--attention' : ''}` }, el('dt', {}, attention ? icon('warning') : null, dt), el('dd', {}, dd),
      step ? goBtn(attention ? `Go to ${STEP_NAME[step]}` : step === 'tenant' ? 'Tenant' : 'Change', step, attention ? 'btn--sm' : 'btn--sm btn--quiet') : el('span'));
    const groupsWords = as.list.map((g) => `${g.name}, ${S.inWindow.has(g.group) ? 'assigned in this window' : g.created ? `assigned ${day(g.created)}` : 'assigned before this window'}`);
    fill(sheet, head,
      el('dl', { class: 'ad-sheet__rows' },
        row('Deployment', dep ? [el('p', {}, `${a.deployment.name || dep.name}, revision ${a.deployment.revision}.`), el('p', { class: 't-small' }, `Revision ${dep.revision} runs on devices now; this one replaces it as an update.`)]
          : el('p', {}, `${a.deployment.name || 'A deployment with no name'}, a new deployment, revision 1.`), 'sources'),
        row('What Sluse may read', S.sources.map(sourceWords), 'sources'),
        row('Where the box may connect', el('p', {}, `${plural(all.length, 'host')}: ${plural(ticked.length, 'bundle')}${own ? ` and ${own} of your own` : ''}.${uploads ? ` ${plural(uploads, 'bundle')} ${uploads === 1 ? 'takes' : 'take'} uploads.` : ''}`), 'egress'),
        row('The box', el('p', {}, `${radio('mem')} GB of memory and a ${radio('disk')} GB home disk. Copying text out is ${$('copy-out').checked ? 'on' : 'off'}. The egress log is ${$('egress-log').checked ? `on, up to ${num('egress-mb')} MB` : 'off'}.`), 'advanced'),
        row('Volume alert', [el('p', {}, volumeWords()), el('p', { class: 't-small' }, fetch ? `A single fetch larger than ${fetch} MB is refused.` : 'No limit on a single fetch.')], 'advanced')),
      // Who may sign in is Entra's assignment, not part of the configuration:
      // the box's check never sees it, so it sits beside the rows.
      el('div', { class: 'ad-sheet__beside', 'aria-labelledby': 'bs-t' }, el('span', { class: 't-label', id: 'bs-t' }, 'Not in this configuration, so not checked'),
        el('dl', { style: 'margin: 0' }, noGroup()
          ? row('Who may sign in', [el('p', {}, el('b', { class: 'ad-attn-word' }, 'No group assigned.'), ' With Assignment required on, no one can sign in to Sluse.'),
            el('p', { class: 't-small' }, `As Entra held it at ${hhmm(as.at)}. You can publish; assign a group at Tenant before devices take this revision. It is also under What to know below.`)], 'tenant', true)
          : row('Who may sign in', as.state === 'read' ? [el('p', {}, `${groupsWords.join(', and ')}.`), el('p', { class: 't-small' }, `As Entra held them at ${hhmm(as.at)}. Entra holds the assignment, so the box's check does not see it.`)]
            : !S.who ? [el('p', {}, "Not read: sign in to see the groups Entra holds for Sluse's app."), el('p', { class: 't-small' }, 'Entra holds the assignment, not this configuration, so nothing here depends on it.')]
              : [el('p', {}, "Not read: make or repair Sluse's app at Tenant to see the groups Entra holds for it."), el('p', { class: 't-small' }, 'Entra holds the assignment, not this configuration, so nothing here depends on it.')], 'tenant'))),
      el('footer', { class: 'ad-sheet__foot' }, icon('admit'), el('span', {}, "Every admission is recorded in the Event Log on the device, in Sluse's channel. This configuration names what may be read; it does not check what the files contain.")));
  }

  // What to know, grouped by the step that made it.
  const know = $('know');
  know.hidden = !ok;
  if (ok) {
    const ws = r.draft.warnings;
    const groups = [];
    if (noGroup()) groups.push(['tenant', 'group', [note('warning', "No group is assigned to Sluse's app, and Assignment required is on, so no one can sign in to Sluse until a group is assigned. Entra holds the assignment, not this configuration: you can publish now and assign a group at Tenant afterwards.")]]);
    for (const [step, ico] of [['sources', 'source'], ['egress', 'globe'], ['advanced', 'settings']]) {
      const mine = ws.filter((w) => (WARNING_STEP[w.code] ?? 'sources') === step);
      if (mine.length) groups.push([step, ico, mine.map((w) => el('li', { class: 'note', 'data-kind': w.code === 'own-host' ? 'info' : 'warning' }, el('span', {}, w.text,
        w.hosts?.length ? [' ', el('details', { class: 'disclosure' }, el('summary', {}, `Its ${plural(w.hosts.length, 'host')}`), el('div', { class: 'disclosure__body' }, el('span', { class: 'mono t-small' }, w.hosts.join(', '))))] : null)))]);
    }
    fill(know, el('div', { class: 'ad-sec__head' }, el('h2', { class: 't-h3', id: 'k-t' }, 'What to know before you publish'), k ? el('span', { class: 'pill pill--count', 'data-status': 'warning' }, String(k)) : pill('none', 'None')),
      k ? el('p', { class: 'ad-sec__lead' }, k === 1 ? 'This is allowed. It is here so you choose it knowingly; it does not stop you publishing.' : 'Each of these is allowed. They are here so you choose them knowingly; none of them stops you publishing.')
        : el('p', { class: 't-small' }, 'Nothing. Every source has a scope, no bundle takes uploads, and the rest are defaults.'),
      k ? el('div', { class: 'ad-know' }, groups.map(([step, ico, items]) => el('div', { class: 'ad-know__group' },
        el('header', {}, icon(ico), el('h4', {}, STEP_NAME[step]), goBtn(`Change in ${STEP_NAME[step]}`, step, 'btn--sm btn--quiet')),
        el('ul', { class: 'ad-know__list' }, items.map((i) => (i.tagName === 'LI' ? i : el('li', { class: 'note', 'data-kind': 'warning' }, i.firstChild))))))) : null);
  }

  // What changed.
  const saved = !!S.saved;
  const dep = fileDeployment();
  fill($('changed'), el('div', { class: 'ad-sec__head' }, el('h2', { class: 't-h3', id: 'd-t' }, saved ? 'What changed since you saved' : 'What changed since the file you opened')),
    !ok ? el('p', { class: 't-small t-muted' }, r.verdict === 'refused' ? 'Shown again when the box would accept the configuration.' : 'Shown once the check is done.')
      : !S.file ? el('div', { class: 'empty', style: 'padding: var(--space-2) 0' }, el('span', { class: 'empty__icon' }, icon('file')), el('p', { class: 'empty__title' }, 'A new configuration'),
        el('p', { class: 'empty__text' }, 'Nothing to compare it with. Saving makes revision 1 of a new deployment. To change a deployment that is already published, open its saved file instead.'))
        : el('div', { class: 'stack', style: '--stack-gap: var(--space-3)' },
          el('p', { class: 't-small' }, saved ? `Compared with what you saved at ${hhmm(S.saved.at)}, revision ${dep.revision}. Saving again makes revision ${dep.revision + 1}.`
            : dep ? ['Compared with ', mono(base(S.file.path)), `, revision ${dep.revision}. Saving makes revision ${dep.revision + 1}.`] : ['Compared with ', mono(base(S.file.path)), '.']),
          diffList(r.diff)));
}

function diffList(lines) {
  const said = lines.filter((l) => l !== 'deployment changed').map((l) => {
    let m;
    const words = { 'entra changed': ["Sluse's app changed", 'tenant'], 'sources changed': ['Sources changed', 'sources'], 'maxFetchBytes changed': ['The largest single fetch changed', 'advanced'],
      'volume changed': ['The volume alert changed', 'advanced'], 'box changed': ['The box changed: memory or home disk', 'advanced'], 'the egress log changed': ['The egress log changed', 'advanced'] }[l];
    if (words) return ['±', words[0], words[1]];
    if ((m = /^the box may now reach (.*)/.exec(l))) {
      const host = m[1];
      const oldBundles = S.file.authored.egress?.bundles ?? [];
      const bd = (S.catalog?.bundles ?? []).find((x) => x.hosts.includes(host) && (x.locked || (oldBundles.includes(x.id) && S.bundles.has(x.id))));
      return ['+', ['The box may now reach ', mono(host), bd ? el('span', { class: 't-muted' }, ` (the catalog added it to ${bd.name})`) : null], 'egress'];
    }
    if ((m = /^the box may no longer reach (.*)/.exec(l))) return ['−', ['The box may no longer reach ', mono(m[1])], 'egress'];
    return ['±', l, null];
  });
  if (!said.length) return el('p', { class: 't-small' }, 'Nothing changed.');
  return el('ul', { class: 'diff' }, said.map(([s, t, step]) => diffLine(s, t, step ? goBtn(STEP_NAME[step], step, 'btn--sm btn--quiet') : null)));
}

// ---- Publish ------------------------------------------------------------------------
async function pickMsi() {
  const path = await dialog.open([{ name: 'Windows Installer', extensions: ['msi'] }]).catch(() => null);
  if (!path) return; // cancelling keeps the earlier pick
  try {
    S.msi = await invoke('admin_msi', { path });
  } catch (e) {
    S.msi = { path, error: String(e) };
  }
  drawPublish();
}

/** Save: the box's check, then the file, then the package (D-043), asking first over a deployment (Q49). */
async function save() {
  const r = await runReview();
  if (r.verdict !== 'accepted') { S.save = { state: 'refused', error: r.error }; drawPublish(); return; }
  const name = `${slug(depName() || 'deployment')}.json`;
  let path = await dialog.save(S.file?.path ?? name, JSON_FILTER).catch(() => null);
  let holds = null;
  for (;;) {
    if (!path) return;
    holds = null;
    try { holds = (await invoke('admin_open', { path })).deployment ?? null; } catch { /* not a configuration: nothing to continue */ }
    const mine = fileDeployment();
    if (!holds || (mine && holds.id === mine.id && S.file?.path === path)) break;
    const same = mine && holds.id === mine.id;
    const answer = await ask(same
      ? { ico: 'file', title: `Save as revision ${holds.revision + 1} of ${holds.name || 'this deployment'}?`,
        body: [el('p', {}, mono(base(path)), ` already holds the deployment ${holds.name || holds.id}, at revision ${holds.revision}. Saving here continues it: devices that run ${holds.name || 'it'} take revision ${holds.revision + 1} as an update.`),
          el('p', { class: 't-small t-muted' }, 'To start a separate deployment, choose another file name. A device runs one deployment and refuses a second.')],
        actions: [['cancel', 'Cancel'], ['other', 'Choose another file…'], ['ok', `Save as revision ${holds.revision + 1}`, 'btn--primary']] }
      : { ico: 'warning', destructive: true, title: `Save this ${mine ? '' : 'new '}configuration over ${holds.name || holds.id}?`,
        body: [el('p', {}, mono(base(path)), ` holds the deployment ${holds.name || holds.id}, at revision ${holds.revision}. This configuration is ${mine ? `${mine.name || 'another deployment'}'s` : 'new'}, and saving it here makes it revision ${holds.revision + 1} of ${holds.name || 'that deployment'}: devices that run ${holds.name || 'it'} take its sources, hosts and settings in place of theirs, as an update.`),
          el('dl', { class: 'facts' }, el('div', {}, el('dt', {}, 'The file holds'), el('dd', {}, `${holds.name || holds.id}, revision ${holds.revision}`)),
            el('div', {}, el('dt', {}, 'Saving here makes'), el('dd', {}, `${holds.name || holds.id}, revision ${holds.revision + 1}, from this configuration`))),
          goesStays([[`Revision ${holds.revision}'s sources, hosts and settings in `, mono(base(path)), `, which then holds revision ${holds.revision + 1}`],
            [`The revision ${holds.revision} package beside it: `, mono(base(path).replace(/\.json$/i, '.package')), ' and ', mono('.intunewin'), ' are written again']],
          [`${holds.name || 'The deployment'} and its id: devices take this as an update`, `Revision ${holds.revision} in Intune, until you publish revision ${holds.revision + 1}`,
            `Revision ${holds.revision} on devices, until they take revision ${holds.revision + 1}`, "The record of every admission, in the Event Log on each device, in Sluse's channel"]),
          el('p', { class: 't-small t-muted' }, 'To start a separate deployment, choose another file name. A device runs one deployment and refuses a second.')],
        actions: [['cancel', 'Cancel'], ['other', 'Choose another file…'], ['ok', `Replace revision ${holds.revision} with this configuration`, 'btn--destructive', 'reset']] });
    if (answer === 'ok') break;
    if (answer !== 'other') return;
    path = await dialog.save(name, JSON_FILTER).catch(() => null);
  }
  S.save = { state: 'saving', since: Date.now(), path, revision: holds && holds.id !== fileDeployment()?.id ? holds.revision + 1 : r.a.deployment.revision };
  drawPublish(); drawFoot();
  try {
    const res = await invoke('admin_save', { config: path, text: r.draft.text, msi: S.msi.path });
    const a = JSON.parse(res.text);
    S.file = { path: res.config, authored: a };
    S.saved = { at: new Date(), revision: a.deployment.revision, res, over: res.continued ? holds : null };
    S.save = { state: 'saved' };
    setBaseline();
    S.review = { verdict: 'none' };
    toast(`Saved revision ${a.deployment.revision} of ${a.deployment.name || 'the deployment'}.`);
  } catch (e) {
    S.save = { state: 'error', error: String(e) };
  }
  draw();
}

function savedPart() {
  const s = S.saved;
  const res = s.res;
  const a = S.file.authored;
  const dname = a.deployment.name || 'the deployment';
  const appName = `Sluse: ${a.deployment.name || a.deployment.id}, revision ${a.deployment.revision}`;
  const ps = (extra) => `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${res.script}${extra}`;
  const tr = (th, td, hint) => el('tr', {}, el('th', { scope: 'row' }, th), el('td', {}, td, hint ? el('span', { class: 't-small' }, hint) : null));
  const c = (v, label) => chip(v, `Copy the ${label}`);
  const fileRow = (ico, title, path, text) => el('li', { class: 'ad-file-row' }, el('span', { class: 'ad-file-row__icon' }, icon(ico)),
    el('div', { class: 'ad-file-row__main' }, b(title), chip(base(path), `Copy the path of ${base(path)}`, String(path)), el('p', {}, text)));
  return el('div', { class: 'stack', style: '--stack-gap: var(--space-4)' },
    el('p', { class: 't-body' }, b(`Saved revision ${a.deployment.revision} of ${dname}`), ` at ${hhmm(s.at)}, in `, mono(dir(res.config)), '.'),
    s.over ? note('info', `The file you saved over held ${s.over.name || s.over.id} at revision ${s.over.revision}, and you chose to continue it. Devices that run ${s.over.name || 'it'} take revision ${a.deployment.revision} as an update.`) : null,
    el('ul', { class: 'ad-files' },
      fileRow('upload', 'Upload to Intune', res.intunewin, `Carries Sluse ${res.msiVersion} and this configuration; nothing else goes to the devices.`),
      fileRow('file', 'Keep', res.config, 'Your copy of the configuration. Open it here to change this deployment; Intune cannot give it back. It goes nowhere else.'),
      fileRow('folder', 'Can be deleted once published', res.package, 'What the .intunewin was made from, and what Publish to Intune below uploads.')),
    el('details', { class: 'disclosure' }, el('summary', {}, "Upload it by hand: Intune's form, field by field"),
      el('div', { class: 'disclosure__body' },
        el('p', { class: 't-small' }, 'In Intune: one Windows app (Win32) from the .intunewin, assigned, required, to a device group. No other app.'),
        el('table', { class: 'fieldtable' }, el('caption', {}, 'App information'),
          tr('Name', c(appName, 'name')), tr('Description', c(`Sluse ${res.msiVersion} and the ${dname} configuration, revision ${a.deployment.revision}.`, 'description')),
          tr('Publisher', c('SerenIT and Prompted', 'publisher')), tr('App version', c(res.msiVersion, 'app version')), tr('Developer', c('SerenIT and Prompted', 'developer')),
          tr('Information URL', 'Leave empty', 'Sluse has no web address yet. The installed README is on each device.')),
        el('table', { class: 'fieldtable' }, el('caption', {}, 'Program'),
          tr('Install command', c(ps(''), 'install command')), tr('Uninstall command', c(ps(' -Uninstall'), 'uninstall command')),
          tr('Install behavior', 'System'), tr('Device restart behavior', 'Determine behavior based on return codes', '3010 when Hyper-V needs a restart')),
        el('table', { class: 'fieldtable' }, el('caption', {}, 'Requirements'), tr('Operating system architecture', '64-bit'), tr('Minimum operating system', 'Windows 10 2004')),
        el('table', { class: 'fieldtable' }, el('caption', {}, 'Detection rules: a custom rule, add both'),
          tr('Rule 1, type', 'Registry'), tr('Key path', c('HKEY_LOCAL_MACHINE\\SOFTWARE\\Sluse\\Deployment', 'key path')), tr('Value name', c('PackageVersion', 'value name')),
          tr('Detection method', 'String comparison'), tr('Operator', 'Equals'), tr('Value', c(res.packageVersion, 'value')), tr('Associated with a 32-bit app on 64-bit clients', 'No'),
          tr('Rule 2, type', 'File'), tr('Path', c('%ProgramFiles%\\Sluse\\bin', 'path'), 'The folder only'), tr('File or folder', c('sluse.exe', 'file name')), tr('Detection method', 'File or folder exists')),
        el('table', { class: 'fieldtable' }, el('caption', {}, 'Supersedence and assignment'),
          tr('A new revision', 'A new app that supersedes the last one, as an update'),
          tr('Uninstall previous version', 'No', "Yes runs the old app's uninstall first, which removes Sluse and the boxes."),
          tr('Assignment', 'Required, to a device group')))));
}

function saveProblem() {
  const e = S.save.error;
  if (S.save.state === 'refused') {
    const why = refusal(e);
    return banner('problem', 'Nothing was saved: the box would refuse this configuration.', why.title, { actions: [goBtn('See it in Review', 'review')] });
  }
  if (/Property table|ProductCode|Windows Installer|\.msi/i.test(e)) return banner('problem', 'Sluse.msi could not be read.', 'Nothing was saved. Pick the Sluse.msi you downloaded again, then save again.', { raw: `Saving: ${e}` });
  return banner('problem', 'Saving stopped: the package could not be written.', 'Windows refused a file Sluse Admin writes. Close any program that has it open, then save again. The configuration file was not changed.', { raw: `Saving: ${e}` });
}

const steps = (list) => el('ol', { class: 'steps' }, list.map(([st, text, time, sub]) => el('li', { class: 'step', 'data-step': st },
  el('span', { class: 'step__text' }, text), time ? el('span', { class: 'step__time' }, time) : null, sub ? el('span', { class: 'step__sub' }, sub) : null)));

function drawPublish() {
  const dep = fileDeployment();
  const saved = S.saved && !dirty();
  fill($('pub-facts'),
    el('dl', { class: 'facts' },
      el('div', {}, el('dt', {}, 'Deployment'), el('dd', {}, depName() || dep?.name || 'No name yet')),
      saved ? el('div', {}, el('dt', {}, 'Saved'), el('dd', {}, `Revision ${S.saved.revision}. Saving again makes ${S.saved.revision + 1}.`))
        : el('div', {}, el('dt', {}, 'Saving makes'), el('dd', {}, dep ? `Revision ${dep.revision + 1}, an update of revision ${dep.revision}` : 'Revision 1 of a new deployment')),
      dep ? el('div', {}, el('dt', {}, 'Deployment id'), el('dd', {}, (() => { const c = chip(dep.id, 'Copy the deployment id'); c.classList.add('chip-mono--truncate'); return c; })())) : null),
    dep ? null : el('p', { class: 't-small t-muted', style: 'margin: var(--space-3) 0 0' }, 'To change a deployment you already published, open its saved configuration first, from the file menu at the top.'));

  const m = S.msi;
  fill($('msi-pill'), m?.error ? pill('problem', 'Not an MSI') : m ? pill('ready', 'Picked') : null);
  fill($('msi-file'), m && !m.error ? el('div', { class: 'ad-file-row' }, el('span', { class: 'ad-file-row__icon' }, icon('file')),
    el('div', { class: 'ad-file-row__main' }, b(`Sluse ${m.version}`), chip(m.path, 'Copy the path'), el('p', {}, 'Product code ', mono(m.productCode))))
    : m?.error ? el('p', { class: 'field__msg' }, icon('problem'), el('span', {}, mono(m.path), ` is not an MSI Windows Installer can open (${m.error}). Pick the Sluse.msi you downloaded again.`)) : null);
  const pick = $('pick-msi');
  pick.className = `btn ${m && !m.error ? '' : 'btn--primary'}`;
  fill(pick, icon('folder-open'), m && !m.error ? 'Pick another…' : 'Pick Sluse.msi…');
  $('msi-keep').hidden = !(m && !m.error);
  $('seq-msi').dataset.seq = m && !m.error ? 'done' : '';

  const sv = S.save;
  const ready = m && !m.error;
  $('seq-save').dataset.seq = !ready ? 'waits' : saved ? 'done' : '';
  fill($('save-pill'), saved ? pill('done', 'Saved') : sv.state === 'refused' || sv.state === 'error' ? pill('problem', 'Not saved') : null);
  $('save-lead').hidden = !!saved;
  $('save-row').hidden = sv.state === 'saving' || !!saved;
  fill($('save-state'),
    sv.state === 'saving' ? el('div', { class: 'ad-wait' }, el('div', { class: 'wait' },
      el('div', { class: 'wait__head' }, el('p', { class: 'wait__title' }, 'Saving'), el('p', { class: 'wait__clock', 'data-label': 'Waiting', id: 'save-clock' }, clock(sv.since))),
      steps([['done', 'Checked the configuration'], ['current', ['Writing ', mono(base(sv.path)), `, revision ${sv.revision}, reading Sluse.msi, packing and encrypting `, mono(base(sv.path).replace(/\.json$/i, '.intunewin'))]]]))) : null,
    sv.state === 'refused' || sv.state === 'error' ? saveProblem() : null,
    S.saved ? savedPart() : null,
    S.saved && dirty() ? note('warning', 'You changed the configuration since you saved. Save again to publish the changes.') : null);
  drawPub();
}

function drawPub() {
  const p = S.pub;
  const saved = S.saved && !dirty();
  const pkg = p.what === 'earlier' ? (p.earlier && !p.earlier.error ? p.earlier.path : null) : saved ? S.saved.res.package : null;
  const busy = ['publishing', 'cleaning'].includes(p.state);
  // Never drawn as waiting: "A package saved earlier" needs no save here (Q50).
  $('seq-pub').dataset.seq = p.state === 'published' ? 'done' : '';
  fill($('pub-pill'), busy ? pill('working', 'Publishing') : p.state === 'published' ? pill('published', 'Published') : ['failed', 'failed-kept', 'error'].includes(p.state) ? pill('failed', 'Not published') : null);
  const what = el('fieldset', { class: 'fieldset' }, el('legend', {}, 'What to publish'), el('div', { class: 'choicecards' },
    el('label', { class: 'choicecard' }, el('input', { type: 'radio', name: 'what', checked: p.what === 'here', onchange: () => { p.what = 'here'; drawPub(); } }), b('What you saved here'),
      el('span', {}, saved ? `Revision ${S.saved.revision}, saved at ${hhmm(S.saved.at)}` : 'Nothing saved in this window yet')),
    el('label', { class: 'choicecard' }, el('input', { type: 'radio', name: 'what', checked: p.what === 'earlier', onchange: () => { p.what = 'earlier'; drawPub(); } }), b('A package saved earlier'),
      el('span', {}, 'Publishes it as it is, with no new revision'))));
  const e = p.earlier;
  const earlier = p.what === 'earlier' ? el('div', { class: 'stack', style: '--stack-gap: var(--space-3)' },
    e && !e.error ? el('div', { class: 'ad-file-row' }, el('span', { class: 'ad-file-row__icon' }, icon('folder')), el('div', { class: 'ad-file-row__main' },
      b(`${e.deployment.name || e.deployment.id}, revision ${e.deployment.revision}, with Sluse ${e.msiVersion}`), chip(e.path, 'Copy the path of the package'),
      el('p', {}, 'Intune gets it exactly as it was saved; nothing in it changes, and no revision is made here.'),
      S.saved && S.file.authored.deployment.id === e.deployment.id && e.deployment.revision < S.saved.revision
        ? el('p', {}, b('Older than what this window saved:'), ` this is revision ${e.deployment.revision}; you saved revision ${S.saved.revision} at ${hhmm(S.saved.at)}. To publish revision ${S.saved.revision}, choose What you saved here.`) : null)) : null,
    e?.error ? el('p', { class: 'field__msg' }, icon('problem'), el('span', {}, mono(e.path), ' holds no Sluse package. Pick the ', mono('.package'), ' folder that was saved beside the ', mono('.intunewin'), '.')) : null,
    el('div', { class: 'btn-row' }, btn(e && !e.error ? 'Pick another…' : 'Pick a .package folder…', pickPackage, { ico: 'folder-open' }),
      el('span', { class: 't-small t-muted' }, 'The folder named after the configuration, ending in ', mono('.package'), '.'))) : null;

  const groups = p.groups;
  const picker = el('div', { class: 'stack', style: '--stack-gap: var(--space-3)' },
    el('div', { class: 'ad-search' }, el('label', { class: 'field' }, el('span', { class: 'field__label' }, "Start of the device group's name"),
      el('input', { class: 'input', type: 'search', id: 'device-query', value: p.query ?? '', placeholder: 'Finance', 'data-enter': 'device-find' })),
    el('button', { class: 'btn', type: 'button', id: 'device-find', 'aria-busy': p.finding ? 'true' : null, onclick: findDevices }, icon('search'), 'Find')),
    el('div', { class: 'picklist' },
      groups?.length ? el('ul', { class: 'rows', role: 'radiogroup', 'aria-label': 'Device groups' }, groups.slice(0, p.shown).map((g) => el('li', { class: 'row' },
        el('label', { class: 'radio' }, el('input', { type: 'radio', name: 'dg', checked: p.group?.id === g.id, onchange: () => { p.group = g; drawPub(); } }), el('span', { class: 'radio__dot' }), icon('group'), g.name)))) : null,
      groups && !groups.length ? el('div', { class: 'empty', style: 'padding: var(--space-4)' }, el('p', { class: 'empty__title' }, `No group's name starts with "${p.query}".`),
        el('p', { class: 'empty__text' }, 'Search matches the start of the display name only. Check the spelling, or type less of it.')) : null,
      p.findError ? el('div', { class: 'picklist__state' }, banner('problem', 'Microsoft Graph did not list the groups.', 'Your sign-in may have expired. Sign in again, then find again.', { raw: `Finding groups: ${p.findError}` })) : null,
      el('div', { class: 'picklist__foot' }, el('span', { class: 'spacer' }, groups?.length ? (groups.length > p.shown ? `The first ${p.shown} groups. Type more of the name to narrow it.` : 'A device group is the documented choice.') : 'Find a device group to publish to.'),
        groups?.length > p.shown ? btn('Show 50 more', () => { p.shown += 50; drawPub(); }, { cls: 'btn--sm btn--quiet' }) : null,
        btn('Publish to Intune', publish, { cls: 'btn--primary', ico: 'upload', disabled: !(pkg && p.group && S.who) }))));

  const fail = p.state === 'failed' || p.state === 'failed-kept' || p.state === 'error';
  fill($('pub-body'),
    busy || p.state === 'published' || fail ? null : what,
    busy || p.state === 'published' ? null : earlier,
    !S.who ? note('warning', 'Sign in to publish straight to Intune. Uploading the .intunewin by hand needs no sign-in. ', el('button', { class: 'btn--link', type: 'button', 'data-go': 'start' }, 'Go to Start')) : null,
    S.who && !busy && p.state !== 'published' ? picker : null,
    p.state === 'publishing' ? publishingWait() : null,
    p.state === 'cleaning' ? el('div', { class: 'ad-wait' }, el('div', { class: 'wait' },
      el('div', { class: 'wait__head' }, el('p', { class: 'wait__title' }, 'The upload failed: deleting the app Sluse Admin made'), el('p', { class: 'wait__clock', 'data-label': 'Waiting', id: 'pub-clock' }, clock(p.since))),
      steps([['done', `Made the app "${p.appName}"`], ['failed', 'Uploading the package'], ['current', 'Deleting the app it made, so none is left without its package']]),
      el('p', { class: 'wait__meta' }, p.previous ? `Revision ${p.previous} stays assigned whatever happens here.` : 'Nothing else in Intune changes here.'))) : null,
    p.state === 'failed' ? banner('problem', "Intune's upload failed, so Sluse Admin deleted the app it had made.",
      `"${p.appName}" was in Intune without its package for ${clock(p.since)}, assigned to no one, and is gone again. Nothing new is in Intune${p.previous ? `, and revision ${p.previous} is still assigned` : ''}. Publish again when you are ready.`,
      { raw: p.raw, more: el('ul', { class: 'diff' }, diffLine('+', `Made the app "${p.appName}"`, pill('plain', 'Made')), diffLine('−', 'Deleted it again after the upload failed', pill('changed', 'Deleted'))) }) : null,
    p.state === 'failed-kept' ? banner('problem', "Intune's upload failed, and the app Sluse Admin made could not be deleted.",
      `Intune still holds "${p.appName}" without its package, assigned to no one. Delete it in the Intune admin center under Apps, Windows, before you publish again: publishing again makes a second app.${p.previous ? ` Revision ${p.previous} is still assigned.` : ''}`,
      { raw: p.raw, actions: [btn('Try deleting it again', deleteAgain, { cls: 'btn--sm', ico: 'refresh' })] }) : null,
    p.state === 'error' ? (/: 403\b/.test(p.raw) && !p.appId
      ? banner('problem', 'Intune refused: your account cannot add apps.', 'Publishing needs an Intune Administrator or a Global Administrator. Hand the .intunewin and the settings above to someone with one of those roles. Nothing was made in Intune.', { raw: p.raw })
      : banner('problem', 'Publishing to Intune did not finish.', p.appId ? 'The app was made and its package uploaded; a later step stopped. Look in the Intune admin center under Apps, Windows; the details say where it stopped.' : 'Nothing was made in Intune. Publish again when you are ready; if it repeats, copy the details for whoever supports Sluse.', { raw: p.raw })) : null,
    p.state === 'published' ? publishedPart() : null);
}

async function pickPackage() {
  const path = await dialog.open([], true).catch(() => null);
  if (!path) return;
  try { S.pub.earlier = { path, ...(await invoke('admin_package', { package: path })) }; } catch (e) { S.pub.earlier = { path, error: String(e) }; }
  drawPub();
}
async function findDevices() {
  const p = S.pub;
  p.query = $('device-query').value.trim();
  p.finding = true; p.findError = null;
  drawPub();
  try { p.groups = await invoke('admin_groups', { query: p.query }); p.shown = 50; } catch (e) { p.groups = null; p.findError = String(e); sawError(e); }
  p.finding = false;
  drawPub();
}

let publishing = null;
async function publish() {
  const p = S.pub;
  const pkg = p.what === 'earlier' ? p.earlier.path : S.saved.res.package;
  const dep = p.what === 'earlier' ? p.earlier.deployment : S.file.authored.deployment;
  Object.assign(p, { state: 'publishing', since: Date.now(), events: [], appName: `Sluse: ${dep.name || dep.id}, revision ${dep.revision}`, revision: dep.revision, previous: null, appId: null, raw: null });
  changed(); drawPub();
  publishing = invoke('admin_publish', { package: pkg, group: p.group.id });
  try {
    const r = await publishing;
    Object.assign(p, { state: 'published', result: r, at: new Date() });
  } catch (e) {
    const raw = `Publishing to Intune: ${e}`;
    const m = /\nthe app (\S+) Sluse Admin made (was deleted|could not be deleted)/.exec(String(e));
    p.raw = raw;
    if (m) Object.assign(p, { state: m[2] === 'was deleted' ? 'failed' : 'failed-kept', appId: m[1] });
    else Object.assign(p, { state: 'error', appId: p.events.some((x) => x.step === 'made') ? 'made' : null });
    sawError(e);
  }
  publishing = null;
  changed(); drawPub();
}
listen('publish-step', (e) => {
  const p = S.pub;
  if (p.state !== 'publishing') return;
  const v = e.payload;
  if (v.step === 'found') p.previous = v.revision;
  if (v.step === 'made') p.appName = v.app;
  const last = p.events[p.events.length - 1];
  if (v.step === 'block' && last?.step === 'block') p.events[p.events.length - 1] = { ...v, at: last.at };
  else p.events.push({ ...v, at: Date.now() });
  drawPub();
});
async function deleteAgain() {
  const p = S.pub;
  p.state = 'cleaning';
  drawPub();
  try { await invoke('admin_delete_app', { id: p.appId }); p.state = 'failed'; } catch (e) { p.state = 'failed-kept'; p.raw = `${p.raw}\ndeleting the app again: ${e}`; sawError(e); }
  drawPub();
}

function publishingWait() {
  const p = S.pub;
  const seen = new Set(p.events.map((x) => x.step));
  const at = (s) => p.events.find((x) => x.step === s);
  const order = [p.previous ? 'found' : null, 'made', 'room', 'block', 'checking', p.previous ? 'superseding' : null, 'assigning'].filter(Boolean);
  const lastIdx = Math.max(-1, ...order.map((s, i) => (seen.has(s) ? i : -1)));
  const text = { found: `Found revision ${p.previous} in Intune`, made: `Made the app "${p.appName}"`, room: 'Intune made room for the package', block: 'Uploading the package',
    checking: 'Intune checks the upload', superseding: `Superseding revision ${p.previous}, as an update`, assigning: `Assigning, required, to ${p.group.name}` };
  const blk = at('block');
  return el('div', { class: 'ad-wait' }, el('div', { class: 'wait' },
    el('div', { class: 'wait__head' }, el('p', { class: 'wait__title' }, 'Publishing to Intune'), el('p', { class: 'wait__clock', 'data-label': 'Waiting', id: 'pub-clock' }, clock(p.since))),
    steps(order.map((s, i) => [i < lastIdx ? 'done' : i === lastIdx ? 'current' : 'next', text[s], at(s) ? mmss(at(s).at - p.since) : null,
      s === 'block' && blk && i === lastIdx ? [el('span', { class: 'progress', role: 'progressbar', 'aria-label': 'Upload', 'aria-valuemin': 0, 'aria-valuemax': blk.of, 'aria-valuenow': blk.n, style: `--value: ${Math.round((100 * blk.n) / blk.of)}%; display: block; margin: 6px 0 4px` }, el('span', { class: 'progress__fill', style: 'display:block' })),
        `Block ${blk.n} of ${blk.of}: ${Math.round(blk.bytes / 1048576)} of ${Math.round(blk.total / 1048576)} MB`] : null])),
    el('p', { class: 'wait__meta' }, 'Each wait for Intune gives up after 4 minutes.'),
    el('p', { class: 'wait__meta' }, 'Closing this window now stops the upload and deletes the app Sluse Admin made for it. Sluse Admin asks before it closes.')));
}

function publishedPart() {
  const p = S.pub;
  const usersWarning = (w) => w.replace(/^The group has users in it\./, `${p.group.name} has users in it.`);
  return el('div', { class: 'stack', style: '--stack-gap: var(--space-3)' },
    el('ul', { class: 'diff' }, diffLine('+', `"${p.appName}"`, pill('published', 'Published')),
      p.previous ? diffLine('±', `Supersedes revision ${p.previous}, as an update`, pill('done', 'Superseding')) : null,
      diffLine('+', ['Required, for ', b(p.group.name)], pill('done', 'Assigned'))),
    el('p', { class: 't-small t-muted' }, `Devices in ${p.group.name} take it at their next Intune check-in.`, S.file ? [' Keep ', mono(base(S.file.path)), `: it is how you make revision ${p.revision + 1}.`] : null),
    el('p', { class: 't-small t-muted' }, `In Intune, its publisher and developer are SerenIT and Prompted, version ${p.what === 'earlier' ? p.earlier.msiVersion : S.saved.res.msiVersion}.`),
    p.result.warnings.map((w) => note('warning', usersWarning(w))));
}

// ---- Closing the window (D-034 point 5) ---------------------------------------------
listen('close-requested', async () => {
  const t = S.who?.tenantName ?? 'your tenant';
  if (S.pub.state === 'publishing') {
    const p = S.pub;
    const blk = p.events.filter((x) => x.step === 'block').pop();
    const answer = await ask({ ico: 'warning', destructive: true, title: 'Close Sluse Admin while it publishes to Intune?',
      body: [el('p', {}, `The upload is under way${blk ? `, at block ${blk.n} of ${blk.of}` : ''}. Closing now stops it, deletes the app "${p.appName}" Sluse Admin made for it, then closes.`),
        goesStays(['The upload to Intune', `The app "${p.appName}", deleted again`, `Sluse Admin's token for ${t}`],
          [S.saved ? [mono(base(S.file.path)), ` and its package, saved as revision ${S.saved.revision}`] : 'The package you picked, as it was', p.previous ? `Revision ${p.previous} in Intune, still assigned` : 'Everything else in Intune'])],
      actions: [['cancel', 'Cancel'], ['ok', 'Stop, delete the app and close', 'btn--destructive', 'close']] });
    if (answer !== 'ok') return;
    await invoke('admin_stop_publish');
    await publishing?.catch(() => {});
    invoke('admin_close');
    return;
  }
  if (!dirty()) { invoke('admin_close'); return; }
  const name = fileDeployment()?.name || (S.file ? base(S.file.path) : 'the new configuration');
  const answer = await ask({ ico: 'warning', destructive: true, title: 'Close Sluse Admin with unsaved changes?',
    body: [el('p', {}, `You changed ${changedSteps().join(' and ')} since ${S.file ? `${name} was ${S.saved ? 'saved' : 'opened'}` : 'you started'}. Closing now loses those changes${S.who ? `, and Sluse Admin drops its token for ${t}` : ''}. Nothing has gone to Intune or to any device.`),
      goesStays([`Your changes since ${hhmm(S.baselineAt)}`, S.who ? `Sluse Admin's token for ${t}` : null].filter(Boolean),
        [S.file ? [mono(base(S.file.path)), ` as last saved${fileDeployment() ? `, revision ${fileDeployment().revision}` : ''}`] : null, `Sluse's app and its consent in ${t}`, 'What is already in Intune'].filter(Boolean))],
    actions: [['cancel', 'Cancel'], ['publish', 'Go to Publish to save'], ['ok', 'Close and lose the changes', 'btn--destructive', 'close']] });
  if (answer === 'ok') invoke('admin_close');
  else if (answer === 'publish') go('publish');
});

// ---- Sign out ---------------------------------------------------------------------
async function signOut() {
  const t = S.who?.tenantName ?? 'your tenant';
  const answer = await ask({ ico: 'sign-out', title: `Sign out of ${t}?`,
    body: [el('p', {}, `Sluse Admin drops its token for ${t}. Browsing for sources, the consent check and publishing straight to Intune stop until you sign in again.`),
      el('p', {}, 'Your choices in this window are kept, and so is anything you saved.'),
      el('p', { class: 't-small t-muted' }, "Microsoft's sign-in page may still remember you on this PC. The next sign-in in this window asks Microsoft which account to use, so you can pick another.")],
    actions: [['cancel', 'Cancel'], ['ok', 'Sign out', 'btn--primary']] });
  if (answer !== 'ok') return;
  await invoke('admin_sign_out');
  S.who = null; S.expiredAt = null; S.picked = true; S.roles = null;
  S.app = { state: 'none' }; stopConsent(); S.consent = { state: 'idle' }; S.assigned = { state: 'before', list: [] };
  toast(`Signed out of ${t}. Your choices are kept.`);
  draw();
}

// ---- Wiring -------------------------------------------------------------------------
function draw() {
  drawTop(); drawRail(); drawFoot(); drawStart();
  if (S.step === 'tenant') drawTenant();
  if (S.step === 'sources') drawSources();
  if (S.step === 'egress') drawEgress();
  if (S.step === 'advanced') drawAdvanced();
  if (S.step === 'review') drawReview();
  if (S.step === 'publish') drawPublish();
}

document.addEventListener('click', async (e) => {
  const t = e.target.closest('[data-act], [data-go], [data-copy]');
  if (!t) return;
  if (t.dataset.go) { for (const d of document.querySelectorAll('dialog[open]')) d.close(); go(t.dataset.go); return; }
  if (t.dataset.copy != null) {
    const text = t.dataset.copy || t.closest('.chip-mono')?.querySelector('code')?.textContent || '';
    try { await clip(text); if (t.classList.contains('btn')) { const was = t.textContent; t.textContent = 'Copied'; setTimeout(() => { t.textContent = was; }, 2000); } else toast('Copied.'); } catch { /* the text is on screen to select */ }
    return;
  }
  for (const m of document.querySelectorAll('details.menu[open]')) m.open = false;
  switch (t.dataset.act) {
    case 'sign-in': return signIn(S.picked);
    case 'sign-in-other': return signIn(true);
    case 'sign-out': return signOut();
    case 'open-file': return openFile();
    case 'new-file': if (await loseChanges('new')) { startNew(); go('start'); toast('Every step is back to its defaults.'); } return;
    case 'add-source': return openAdd('sp');
    default:
  }
});
// Enter in a search field runs its search.
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const f = e.target.closest?.('[data-enter]');
  if (f) { e.preventDefault(); $(f.dataset.enter)?.click(); }
});
$('back').onclick = () => { const i = STEPS.findIndex(([id]) => id === S.step); if (i > 0) go(STEPS[i - 1][0]); };
$('next').onclick = () => { const i = STEPS.findIndex(([id]) => id === S.step); if (i < STEPS.length - 1) go(STEPS[i + 1][0]); };
$('register').onclick = register;
$('open-portal').onclick = () => invoke('admin_open_portal', { appId: S.app.result.appId }).catch(() => {});
$('assigned-again').onclick = readAssigned;
$('people-find').onclick = findPeople;
$('pick-msi').onclick = pickMsi;
$('save').onclick = save;
listen('signin-window', (e) => { if (S.signing && e.payload && !S.signing.window) { S.signing.window = Date.now(); drawStart(); } });

// The clocks count by themselves.
setInterval(() => {
  if (S.signing) drawSigning();
  if ($('consent-clock') && S.consent.since) $('consent-clock').textContent = clock(S.consent.since);
  if ($('tm-clock') && ADD.tm.since) $('tm-clock').textContent = clock(ADD.tm.since);
  if ($('pub-clock') && S.pub.since) $('pub-clock').textContent = clock(S.pub.since);
  if ($('save-clock') && S.save.since) $('save-clock').textContent = clock(S.save.since);
}, 1000);

drawCards(6, 40);
try {
  S.catalog = await invoke('admin_catalog');
} catch (e) {
  S.catalogError = String(e);
}
startNew();
go('start');
