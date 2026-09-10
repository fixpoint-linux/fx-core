#!/usr/bin/env node
/**
 * scripts/ssg.mjs — static-site-generator build step for the fx-core docs site.
 *
 * Pipeline:
 *
 *   1.  Expects the Elm app already compiled to `dist/elm.js`:
 *         elm make site/Main.elm --output=dist/elm.js --optimize
 *      and the command dataset generated from the Dhall schemas:
 *         zig build docs      -> docs/commands.json
 *   2.  Reads `docs/commands.json` and hands it to the Elm app as FLAGS —
 *      `Elm.Main.init({ node, flags: dataset })`. The dataset is the source of
 *      truth for the page; the Elm view derives everything from it, so the
 *      reference cannot drift from the actual CLI.
 *   3.  Boots a happy-dom `Window`, installs its browser globals onto
 *      globalThis, then loads the compiled Elm bundle ONCE with an indirect
 *      eval `(0, eval)(code)` — the bundle is a classic IIFE whose `this` binds
 *      to globalThis, so `Elm` lands on `globalThis.Elm`.
 *   4.  Creates a detached root `<div>`, calls `Elm.Main.init`, waits for the
 *      initial render to flush, and reads back `node.innerHTML` — the
 *      pre-rendered markup.
 *   5.  Wraps that markup in a full HTML document (shell/index.html) and writes
 *      `dist/index.html`.
 *
 * The output page ships with content already present (no-JS / SEO) and all
 * styling inline (the rendered markup carries the `<style>` emitted by
 * `Fixpoint.Style.stylesheet`). Fits Caddy's static hosting — no Node server at
 * request time.
 *
 * Run from the repo root:
 *   node scripts/ssg.mjs
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Window } from 'happy-dom';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const DIST = join(ROOT, 'dist');
const ELM_BUNDLE = join(DIST, 'elm.js');
const DATASET = join(ROOT, 'docs', 'commands.json');
const SHELL_TEMPLATE = join(ROOT, 'shell', 'index.html');
const OUTPUT = join(DIST, 'index.html');

const SLOT_SELECTOR = '[data-fx="commands"]';

function log(msg) {
  console.log(`[ssg] ${msg}`);
}

/**
 * Install happy-dom's window-backed values onto globalThis so the compiled Elm
 * bundle and its runtime see a browser-shaped global object.
 *
 * `navigator` and `location` already exist on Node's globalThis as getter-only
 * properties, so they cannot be plain-assigned — `defineProperty` with
 * `configurable: true` replaces them.
 */
function installGlobals(window) {
  const globals = [
    'window',
    'document',
    'navigator',
    'location',
    'history',
    'customElements',
    'performance',
    'requestAnimationFrame',
    'cancelAnimationFrame',
    'HTMLElement',
    'HTMLDivElement',
    'HTMLSpanElement',
    'HTMLAnchorElement',
    'HTMLButtonElement',
    'HTMLTableElement',
    'Element',
    'Node',
    'Document',
    'DocumentFragment',
    'Text',
    'Comment',
    'NodeList',
    'HTMLCollection',
    'Event',
    'CustomEvent',
    'MouseEvent',
    'KeyboardEvent',
    'UIEvent',
    'EventTarget',
    'MutationObserver',
    'getComputedStyle',
    'matchMedia',
  ];
  for (const name of globals) {
    const value = window[name];
    if (value === undefined) continue;
    Object.defineProperty(globalThis, name, {
      value,
      configurable: true,
      writable: true,
    });
  }
}

/**
 * Load the compiled Elm bundle, mount it with the command dataset as flags and
 * return the pre-rendered HTML.
 */
async function renderSite(window, flags) {
  const code = readFileSync(ELM_BUNDLE, 'utf8');
  // eslint-disable-next-line no-eval -- indirect eval runs in global scope, so
  // the bundle's IIFE `(this)` binds to globalThis and defines globalThis.Elm.
  (0, eval)(code);

  const Elm = globalThis.Elm;
  if (!Elm || !Elm.Main || typeof Elm.Main.init !== 'function') {
    throw new Error('dist/elm.js did not expose Elm.Main.init on globalThis');
  }

  const root = window.document.createElement('div');
  root.setAttribute('id', 'fx-core-root');
  window.document.body.appendChild(root);

  Elm.Main.init({ node: root, flags });

  // Let Elm's initial render flush. Browser.element schedules its first paint
  // through the virtual DOM, which Elm drives with requestAnimationFrame /
  // macrotasks. Flushing happy-dom's async task manager covers both; fall back
  // to a couple of macrotask ticks for robustness.
  const flush =
    window.happyDOM && typeof window.happyDOM.whenAsyncComplete === 'function'
      ? () => window.happyDOM.whenAsyncComplete()
      : () => new Promise((resolve) => setTimeout(resolve, 0));
  await flush();
  await flush();

  return root.innerHTML;
}

/**
 * Inject the pre-rendered markup into the shell template's slot and return the
 * final, complete HTML document.
 */
function injectRendered(shellHtml, rendered) {
  const win = new Window();
  const doc = win.document;
  doc.write(shellHtml);
  doc.close();

  const slot = doc.querySelector(SLOT_SELECTOR);
  if (!slot) {
    throw new Error(
      `shell/index.html has no ${SLOT_SELECTOR} element to inject the rendered page into`,
    );
  }
  slot.innerHTML = rendered;

  return `<!DOCTYPE html>\n${doc.documentElement.outerHTML}\n`;
}

async function main() {
  if (!existsSync(ELM_BUNDLE)) {
    console.error(
      `[ssg] missing ${ELM_BUNDLE}. Build it first:\n` +
        '  node_modules/elm/bin/elm make site/Main.elm --output=dist/elm.js --optimize',
    );
    process.exit(1);
  }
  if (!existsSync(DATASET)) {
    console.error(
      `[ssg] missing ${DATASET}. Generate it first:\n  zig build docs`,
    );
    process.exit(1);
  }

  const flags = JSON.parse(readFileSync(DATASET, 'utf8'));
  log(`dataset: ${Array.isArray(flags.commands) ? flags.commands.length : 0} commands`);

  const window = new Window();
  installGlobals(window);

  log('rendering Elm docs page under happy-dom …');
  const rendered = await renderSite(window, flags);
  log(`rendered ${rendered.length} bytes of markup`);

  const shellHtml = readFileSync(SHELL_TEMPLATE, 'utf8');
  const finalHtml = injectRendered(shellHtml, rendered);

  mkdirSync(DIST, { recursive: true });
  writeFileSync(OUTPUT, finalHtml);
  log(`wrote ${OUTPUT} (${finalHtml.length} bytes)`);
}

main().catch((err) => {
  console.error('[ssg] failed:', err);
  process.exit(1);
});
