#!/usr/bin/env node
/**
 * scripts/ssg.mjs — static-site-generator build step for the fx-core docs site.
 *
 * Multi-route SSG: pre-renders EACH page (the index + one page per command) to
 * its own dist/<dir>/index.html so deep-links + no-JS/SEO work under Caddy
 * static hosting.
 *
 * Pipeline:
 *
 *   1.  Expects the Elm app already compiled to `dist/elm.js`:
 *         elm make site/Main.elm --output=dist/elm.js --optimize
 *      and the command dataset generated from the Dhall schemas:
 *         zig build docs      -> docs/commands.json
 *      and the shell artifacts generated from that dataset:
 *         node scripts/gen-shell.mjs   -> shell/pages.js + shell/templates/
 *   2.  Boots a happy-dom `Window`, installs its browser globals onto
 *      globalThis, then loads the compiled Elm bundle ONCE with an indirect eval
 *      `(0, eval)(code)` — the bundle is a classic IIFE whose `this` binds to
 *      globalThis, so `Elm` lands on `globalThis.Elm`.
 *   3.  For each page (from PAGES, generated from the schemas):
 *         - Creates a detached root `<div>`
 *         - Calls `Elm.Main.init({ node, flags: { pathname, commands } })`
 *         - Waits for the initial render to flush
 *         - Reads back `node.innerHTML` — the pre-rendered page markup
 *   4.  Wraps the rendered markup in a full HTML document (import map + the
 *      page's unique data-mfe slot) and writes dist/<dir>/index.html.
 *   5.  Copies shell/ and the dataset into dist/.
 *
 * The output pages ship with content already present (no-JS / SEO) and all
 * styling inline (the rendered markup carries the `<style>` emitted by
 * `Fixpoint.Style.stylesheet`). Client-side, the shell rehydrates the
 * pre-rendered DOM and the MFE takes over navigation — see
 * shell/mfe/fx-core-page.js.
 *
 * Run from the repo root:
 *   node scripts/ssg.mjs
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, cpSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Window } from 'happy-dom';
import { PAGES, BASE_PATH, MFE_MODULE } from '../shell/pages.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const DIST = join(ROOT, 'dist');
const ELM_BUNDLE = join(DIST, 'elm.js');
const DATASET = join(ROOT, 'docs', 'commands.json');

// Every slot resolves to the single MFE module. Slots are unique per page (see
// gen-shell.mjs for why that matters to @mfe/core's reconcile).
const IMPORT_MAP = `{
  "imports": {
    "@mfe/core": "${BASE_PATH}/vendor/@mfe/core/index.js",
    "@mfe/framework": "${BASE_PATH}/vendor/@mfe/framework/index.js",
${PAGES.map((p) => `    "${p.slot}": "${MFE_MODULE}"`).join(',\n')}
  }
}`;

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
    'window', 'document', 'navigator', 'location', 'history', 'customElements',
    'performance', 'requestAnimationFrame', 'cancelAnimationFrame',
    'HTMLElement', 'HTMLDivElement', 'HTMLSpanElement', 'HTMLAnchorElement',
    'HTMLButtonElement', 'HTMLTableElement', 'Element', 'Node', 'Document',
    'DocumentFragment', 'Text', 'Comment', 'NodeList', 'HTMLCollection',
    'Event', 'CustomEvent', 'MouseEvent', 'KeyboardEvent', 'UIEvent',
    'EventTarget', 'MutationObserver', 'getComputedStyle', 'matchMedia',
  ];
  for (const name of globals) {
    const value = window[name];
    if (value === undefined) continue;
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
}

/**
 * Load the compiled Elm bundle ONCE into globalThis.Elm. Must not be called
 * twice — a second indirect eval re-runs the IIFE and Elm's prod export merge
 * crashes with "name clash".
 */
function loadElmOnce() {
  if (globalThis.__fxCoreElmLoaded) return;
  const code = readFileSync(ELM_BUNDLE, 'utf8');
  // eslint-disable-next-line no-eval -- indirect eval runs in global scope.
  (0, eval)(code);
  globalThis.__fxCoreElmLoaded = true;
}

/** Mount the Elm app with the page flags and return the rendered HTML. */
async function renderPage(window, pathname, commands) {
  const Elm = globalThis.Elm;
  if (!Elm || !Elm.Main || typeof Elm.Main.init !== 'function') {
    throw new Error('dist/elm.js did not expose Elm.Main.init on globalThis');
  }

  const root = window.document.createElement('div');
  root.setAttribute('id', 'docs-root');
  window.document.body.appendChild(root);

  Elm.Main.init({ node: root, flags: { pathname, commands } });

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

function slotHtml(slotName, inner) {
  const rendered = inner === undefined ? '' : `\n${inner}\n    `;
  return `    <div data-mfe="${slotName}">${rendered}</div>`;
}

function wrapDocument(title, description, slotHtmlMarkup) {
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><rect width='16' height='16' rx='3' fill='%230b0e11'/><text x='8' y='12' font-size='11' text-anchor='middle' fill='%236ad6a1' font-family='monospace'>f</text></svg>">
<script type="importmap">
${IMPORT_MAP}
</script>
</head>
<body>
<div id="app" ssr>
  <div class="fixpoint-root">
${slotHtmlMarkup}
  </div>
</div>
<script type="module" src="${BASE_PATH}/shell/shell.js"></script>
</body>
</html>
`;
}

/** Copy a file or directory tree from src to dest. */
function copyRecursive(src, dest) {
  const stats = statSync(src);
  if (stats.isDirectory()) {
    mkdirSync(dest, { recursive: true });
    for (const entry of readdirSync(src)) {
      copyRecursive(join(src, entry), join(dest, entry));
    }
  } else {
    mkdirSync(dirname(dest), { recursive: true });
    cpSync(src, dest);
  }
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
    console.error(`[ssg] missing ${DATASET}. Generate it first:\n  zig build docs`);
    process.exit(1);
  }

  const dataset = JSON.parse(readFileSync(DATASET, 'utf8'));
  const commands = dataset.commands;
  log(`dataset: ${commands.length} commands, ${PAGES.length} routes`);

  const window = new Window();
  installGlobals(window);
  loadElmOnce();

  for (const page of PAGES) {
    const rendered = await renderPage(window, page.path, commands);
    const outputDir = page.dir === '' ? DIST : join(DIST, page.dir);
    const outputPath = join(outputDir, 'index.html');
    const html = wrapDocument(page.title, page.description, slotHtml(page.slot, rendered));
    mkdirSync(outputDir, { recursive: true });
    writeFileSync(outputPath, html);
    log(`  ${page.path} -> ${outputPath} (${html.length} bytes)`);
  }

  // Copy shell/ (templates + the MFE module + pages.js + shell.js) into dist/.
  log('copying shell/ to dist/ ...');
  copyRecursive(join(ROOT, 'shell'), join(DIST, 'shell'));

  // The dataset is fetched at runtime by the MFE module, so it must be served.
  cpSync(DATASET, join(DIST, 'commands.json'));
  log('copied commands.json to dist/');

  // Copy vendor/@mfe (the built framework) to dist/vendor/@mfe.
  const vendorMfeSrc = join(ROOT, 'vendor', '@mfe');
  if (existsSync(vendorMfeSrc)) {
    log('copying vendor/@mfe to dist/vendor/@mfe ...');
    copyRecursive(vendorMfeSrc, join(DIST, 'vendor', '@mfe'));
  } else {
    log('WARNING: vendor/@mfe missing — the runtime MFE nav will not work.');
    log('  build it: ( cd vendor/mfe-framework && npm ci && npm run build )');
    log('  then:     node scripts/copy-mfe.mjs  (or the dhake vendor-mfe target)');
  }

  log('SSG complete.');
}

main().catch((err) => {
  console.error('[ssg] failed:', err);
  process.exit(1);
});
