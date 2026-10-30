// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// The likely cause behind a box that did not start, read from Hyper-V's own
// text, so the person reads "not enough memory" rather than a Hyper-V error
// string (L1, 2026-10-07: a 6 GB box on a 10 GB host). The raw text stays
// under Details. Each entry: a pattern, then what the error page says: the
// headline, the sentence, the failed step's line in the ledger, and whether
// resetting is the thing to do (the mock-ups' errors.html, D-062). The
// HRESULTs hold on a Windows in another language.
// ponytail: the sentences match English Windows only; the codes are what
// a localized one shows.
// Advice ends at "send the details to your IT department": the person
// asks, and IT, who sized the box, decides what changes (jok, 2026-10-08).
export const CAUSES = [
  [/not enough memory|ran out of memory|insufficient system resources|0x8007000E|0x800705AA/i, {
    head: 'Not enough free memory for your box',
    body: 'This computer does not have enough free memory for your box. Close other programs and try again. If it keeps happening, send the details to your IT department.',
    sub: 'Not enough free memory' }],
  [/not enough space on the disk|0x80070070/i, {
    head: 'This computer\'s disk is full', body: 'Free some space and try again.', sub: 'The disk is full' }],
  [/hypervisor is not running/i, {
    head: 'Virtualization is not running',
    body: 'Sluse needs virtualization, and it is not running on this computer. Restart the computer. If that does not help, send the details to your IT department.',
    sub: 'Virtualization is not running' }],
  [/does not have permission to open attachment/i, {
    head: 'Your box\'s disk lost its permissions', body: 'Resetting the box\'s system fixes this, and your files stay.',
    sub: 'The disk\'s permissions', reset: true }],
  // The service saw a login prompt on the box's console: a system without
  // Sluse, whose screen never comes (D-066). A reset puts the base on it.
  [/has no Sluse on it/, {
    head: 'Your box\'s system is incomplete',
    body: 'Resetting the box\'s system fixes this, and your files stay.',
    sub: 'The system is incomplete', reset: true }],
  // The box refused or was refused at enrolment, said on its console
  // (2026-10-30). A config its system cannot read is a system too old for
  // it, which a reset replaces; the service resets a closed one by itself.
  [/could not enrol: the Gate's config/, {
    head: 'Your box\'s system is out of date',
    body: 'Resetting the box\'s system fixes this, and your files stay.',
    sub: 'The system is out of date', reset: true }],
  [/could not enrol/, {
    head: 'Your box could not connect to Sluse',
    body: 'Try again. If it keeps happening, send the details to your IT department.',
    sub: 'The box was not let in' }],
  // Last, so memory and disk above name a build's cause when they are it.
  // The service counts failed builds in a row; IT from the second (D-063).
  [/^preparing the box:/, (m) => ({
    head: 'Your box\'s system could not be installed',
    body: /failed \d+ times in a row/.test(m)
      ? 'Sluse could not finish installing your box\'s system. Try again. If it keeps happening, send the details to your IT department.'
      : 'Sluse could not finish installing your box\'s system. Try again.',
    sub: 'The install did not finish' })],
];

/** `{head, body, sub, reset?}` for a box failure's text, or null when none fits. */
export function cause(message) {
  const c = CAUSES.find(([re]) => re.test(message ?? ''))?.[1] ?? null;
  return typeof c === 'function' ? c(message) : c;
}
