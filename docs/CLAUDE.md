# Documentation Site

Custom zero-framework static site generator (no React/Docusaurus) plus an interactive
in-browser RFC 9421 playground.

## Build and Preview

```bash
cd docs
npm install
npm start            # build (no base path) + serve at http://localhost:8080
npm run build        # production build into dist/ (base path /httpsig)
npm run serve        # serve dist/ locally
```

There is no hot-reload — re-run `npm start` after edits. The build is fast.

## How it works

- `build.mjs` renders `content/*.md` through `unified`/`remark`/`rehype` into HTML, wraps it
  in `templates/*.html` via `{{var}}` substitution, copies `static/`, and esbuild-bundles the
  playground tool.
- The docs tree, routing, and left sidebar are all driven by the `DOC_TREE` manifest in
  `build.mjs` — add a page there, not in a separate sidebar file.
- Page titles come from the first Markdown `# H1` (or frontmatter `title`).

## Conventions

- Vanilla CSS with HSL custom-property tokens in `static/styles.css`; light/dark via
  `prefers-color-scheme`. Warm editorial palette; fonts are system sans / serif display / mono.
- No client framework. The only JavaScript is the canvas diagrams (`static/viz/*.html`) and
  the playground bundle (`static/playground/app.ts` → `dist/playground/app.js`).
- Base path: `BASE_PATH=/httpsig` for GitHub Pages (set by the `build` script); empty for local.
  Templates use `{{base}}`; hand-written static HTML/CSS use the `%BASE%` token.
- Syntax highlighting is auto-detected by `rehype-highlight` (no per-language config needed).
- Cross-links: relative `./x.md` or the page URL `/docs/.../`; legacy `/section/name` paths are
  rewritten by `rewriteLinks()` in `build.mjs`.

## Key Files

| File | Purpose |
|---|---|
| `build.mjs` | Generator: `DOC_TREE` manifest, markdown pipeline, sidebar/TOC, esbuild bundle |
| `templates/layout.html` | Page shell (header nav, footer) |
| `templates/home.html` | Landing page body |
| `templates/doc.html` | Docs three-column shell (sidebar / content / TOC) |
| `templates/playground.html` | Sign / Verify / Inspect tool body |
| `static/styles.css` | Design system tokens + all page styles |
| `static/viz/*.html` | Standalone canvas diagrams (`?embed=1` drops chrome for iframes) |
| `static/playground/app.ts` | Tool logic; imports the local `../typescript/src` library |
| `static/playground/crypto-shim.js` | `node:crypto` browser shim (esbuild alias) |
| `static/playground/buffer-shim.js` | `Buffer` browser shim (esbuild inject) |

## Playground notes

- Runs entirely client-side over Web Crypto (`crypto.subtle`). Keys never leave the page.
- The library is async-first; the tool uses `newWebCryptoSigningKey` / `newWebCryptoVerifyingKey`.
- Supports ed25519, ecdsa-p256-sha256, rsa-pss-sha512 (generate or paste PEM) and hmac-sha256
  (shared secret). Content-Digest is computed with `crypto.subtle.digest` (the library's own
  digest helper uses Node `node:crypto` and is not used in-browser).
- The Verify tab independently rebuilds the signature base and calls `key.verify()` to show
  per-check results, because `verifyMessage()` only returns/throws a single verdict.

## Deployment

`.github/workflows/docs.yml` runs `npm ci && npm run build` and publishes `docs/dist` to GitHub
Pages on pushes to `main` touching `docs/**` or `typescript/**`.
