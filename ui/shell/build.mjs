// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// The frontend is a few files and noVNC, copied as they are: no bundler.
// noVNC ships unmodified under MPL-2.0, its licence texts beside it (D-027).
import { cpSync, mkdirSync, rmSync } from 'node:fs';

const novnc = 'node_modules/@novnc/novnc';
rmSync('dist', { recursive: true, force: true });
mkdirSync('dist/novnc/docs', { recursive: true });
// Sluse Admin's window is three more (D-039 slice 6).
for (const f of ['index.html', 'main.js', 'causes.js', 'theme.js', 'style.css', 'admin.html', 'admin.js', 'admin.css']) cpSync(`src/${f}`, `dist/${f}`);
// Sluse's look, shared with the console (D-062): tokens, components, icons, logo.
cpSync('../console/look', 'dist/look', { recursive: true });
for (const d of ['core', 'vendor']) cpSync(`${novnc}/${d}`, `dist/novnc/${d}`, { recursive: true });
cpSync(`${novnc}/LICENSE.txt`, 'dist/novnc/LICENSE.txt');
cpSync(`${novnc}/AUTHORS`, 'dist/novnc/AUTHORS');
cpSync(`${novnc}/docs/LICENSE.MPL-2.0`, 'dist/novnc/docs/LICENSE.MPL-2.0');
console.log('dist/ written');
