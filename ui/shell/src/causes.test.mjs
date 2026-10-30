// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// node --test ui/shell/src/causes.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cause } from './causes.js';

test('a box failure is read for its likely cause', () => {
  assert.match(cause("'sluse-1' could not initialize memory: Ran out of memory (0x8007000E).").head, /enough free memory/);
  assert.match(cause('Not enough memory in the system to start the virtual machine sluse-1').body, /enough free memory/);
  assert.match(cause('Fehler 0x8007000E').head, /enough free memory/, 'the code, on a German Windows');
  assert.equal(cause('Account does not have permission to open attachment home.vhdx').reset, true, 'reset is the thing to do');
  assert.equal(cause('the box did not answer on 5900 within 300 s'), null);
  assert.equal(cause(undefined), null);
});

test('a build that did not finish is said as such, and IT is asked for from the second', () => {
  const once = cause("preparing the box: the box's system could not be installed (missing: Codex); its console: C:\\ProgramData\\Sluse\\images\\build\\console.log");
  assert.match(once.head, /could not be installed/);
  assert.doesNotMatch(once.body, /IT department/);
  assert.match(cause('preparing the box: https://cloud-images.ubuntu.com/: timed out; failed 2 times in a row').body, /IT department/);
  assert.match(cause('preparing the box: Ran out of memory (0x8007000E)').head, /enough free memory/, 'a named cause wins');
  assert.equal(cause("the box's system has no Sluse on it: its console shows a login prompt").reset, true, 'a reset is offered');
});

test('an enrolment that failed is said once, with a reset only where it helps', () => {
  const old = cause("the box could not enrol: the Gate's config: config does not match schema 3: unknown field `vibe`");
  assert.match(old.head, /out of date/);
  assert.equal(old.reset, true);
  const other = cause('the box could not enrol: https://192.168.77.1:7581: enrolment refused: this open\'s token is already used');
  assert.match(other.body, /IT department/);
  assert.notEqual(other.reset, true);
});
