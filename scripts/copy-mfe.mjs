#!/usr/bin/env node
/**
 * scripts/copy-mfe.mjs — stage the built @mfe framework into vendor/@mfe so the
 * docs site can serve it.
 *
 * `vendor/mfe-framework` is a git submodule of TypeScript sources; its build
 * (`npm ci && npm run build` inside it) emits `packages/{core,framework}/dist/`.
 * The site's import map resolves `@mfe/core` and `@mfe/framework` to
 * `<base>/vendor/@mfe/<pkg>/index.js`, so those dist trees must be copied here
 * (and then into dist/ by scripts/ssg.mjs).
 *
 * Run from the repo root:
 *   ( cd vendor/mfe-framework && npm ci && npm run build )
 *   node scripts/copy-mfe.mjs
 */

import { existsSync, rmSync, mkdirSync, cpSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const SRC = join(ROOT, 'vendor', 'mfe-framework', 'packages');
const OUT = join(ROOT, 'vendor', '@mfe');

const PACKAGES = ['core', 'framework'];

for (const pkg of PACKAGES) {
  const dist = join(SRC, pkg, 'dist');
  if (!existsSync(dist)) {
    console.error(
      `[copy-mfe] missing ${dist}\n` +
        '  build it first:\n' +
        '    ( cd vendor/mfe-framework && npm ci && npm run build )',
    );
    process.exit(1);
  }
  const dest = join(OUT, pkg);
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  // Copy the module graph (.js + source maps). Skip .d.ts (types only).
  for (const entry of readdirSync(dist)) {
    if (entry.endsWith('.d.ts') || entry.endsWith('.d.ts.map')) continue;
    cpSync(join(dist, entry), join(dest, entry), { recursive: true });
  }
  console.log(`[copy-mfe] ${pkg}: ${dist} -> ${dest}`);
}

console.log('[copy-mfe] done');
