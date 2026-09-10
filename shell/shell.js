// shell/shell.js — @mfe/framework thin-shell entry for the fx-core docs site.
//
// Boots the docs app with one route per page: the index (`/fx-core/`) and one
// page per command (`/fx-core/<name>`), derived from shell/pages.js — which is
// itself generated from the Dhall schemas via docs/commands.json.
//
// The pages ship statically pre-rendered (see scripts/ssg.mjs): the #app root
// carries an `ssr` attribute, so createApp rehydrates the existing DOM in place
// instead of wiping it and re-fetching the template on first paint.
//
// Every slot resolves to the one MFE module (shell/mfe/fx-core-page.js) through
// the import map, so a single Elm bundle backs all pages.

import { createApp } from '@mfe/framework';
import { PAGES, BASE_PATH } from './pages.js';

const app = await createApp({
  root: document.getElementById('app'),
  routes: PAGES.map((p, i) => ({ path: p.path, template: p.slot, name: p.slug || 'index' })),
  // Routes carry the FULL path (including the /fx-core prefix), so the router
  // must NOT strip a prefix before matching — basePath stays '/'. (`baseURL`
  // below is the separate concern: where templates are fetched from.)
  basePath: '/',
  // The site's templates are served from /fx-core/shell/templates (it is a
  // standalone docs site; the routes are absolute so deep links resolve).
  baseURL: `${BASE_PATH}/shell/templates`,
  // The SSG output pre-renders every content page, so rehydrate in place.
  ssr: true,
});

// Keep document.title in step with client-side navigation. The framework's
// router swaps the slot but does not touch the title (it exposes no nav hook),
// so the shell tracks it: the SSG already set the correct title for the initial
// page; here we update it for every in-page navigation and history traversal.
function syncTitle() {
  const path = location.pathname.replace(/\/+$/, '');
  const slug = path.slice(path.lastIndexOf('/') + 1);
  const isIndex = slug === BASE_PATH.slice(BASE_PATH.lastIndexOf('/') + 1);
  const page = PAGES.find((p) => p.slug === (isIndex ? '' : slug));
  if (page) document.title = page.title;
}

const pushState = history.pushState.bind(history);
history.pushState = (...args) => {
  pushState(...args);
  queueMicrotask(syncTitle);
};
window.addEventListener('popstate', syncTitle);

export default app;
