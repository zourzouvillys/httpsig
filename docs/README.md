# httpsig Documentation Site

A small zero-framework static site for the httpsig project, plus an interactive
in-browser **RFC 9421 playground** (sign / verify / inspect). Built with a custom
`unified`/`remark`/`rehype` generator — no React, no client framework. Deployed to
GitHub Pages at https://zrz.io/httpsig/.

## Prerequisites

- Node.js 20+
- npm

## Development

```bash
cd docs
npm install
npm start            # builds with no base path, then serves at http://localhost:8080/
```

`npm start` runs `node build.mjs && node serve.mjs`. Re-run it after edits (there is no
hot-reload — the build is fast).

## Build

```bash
npm run build        # production build into dist/ (base path /httpsig for GitHub Pages)
npm run build:local  # build with no base path (for local serving)
npm run serve        # serve dist/ at http://localhost:8080
```

## How it works

`build.mjs`:

1. Renders Markdown in `content/` through a `unified` pipeline (`remark-gfm`,
   `rehype-slug`, `rehype-autolink-headings`, `rehype-highlight`) into HTML.
2. Wraps it in `templates/` (`layout.html`, `doc.html`) with `{{var}}` substitution,
   building the left sidebar from the `DOC_TREE` manifest and the right-hand TOC from
   the rendered headings.
3. Renders the landing page (`templates/home.html`) and the playground page
   (`templates/playground.html`).
4. Copies `static/` to `dist/`, substituting the `%BASE%` token for the deploy base path.
5. Bundles the playground tool with **esbuild**: `static/playground/app.ts` plus the
   local TypeScript library (`../typescript/src`), using a `node:crypto` browser shim and
   an injected `Buffer` shim so the Web Crypto code paths bundle cleanly.

## Project structure

```
docs/
  build.mjs                   Static site generator (DOC_TREE manifest + pipeline + esbuild)
  serve.mjs                   Tiny static dev server (pretty URLs, optional BASE_PATH)
  templates/
    layout.html               Page shell: header nav + footer  ({{title}}{{nav}}{{head}}{{body}}{{base}})
    home.html                 Landing page body
    doc.html                  Docs shell: sidebar | content | TOC
    playground.html           The Sign / Verify / Inspect tool body
  content/
    intro.md                  Docs landing (/docs/)
    getting-started/*.md      Per-language quick starts
    concepts/*.md             RFC 9421/9530 explainers
    guides/*.md               Signing, verifying, response binding, proxy, integrations
  static/
    styles.css                Warm design system (HSL tokens, light/dark)
    viz/                       Standalone <canvas> diagrams (viz.css + *.html)
    playground/
      playground.css          Tool styles
      app.ts                  Tool logic (bundled -> dist/playground/app.js)
      crypto-shim.js          node:crypto browser shim (esbuild alias)
      buffer-shim.js          Buffer browser shim (esbuild inject)
  dist/                       Build output (gitignored)
```

## Adding content

- **New doc page**: add a Markdown file under `content/`, then add an entry to the
  `DOC_TREE` manifest in `build.mjs` (file path, URL, sidebar label). The page title comes
  from the first `# H1`.
- **Cross-links**: link with either a relative `./other.md` path or the page's URL
  (`/docs/concepts/security/`). Legacy `/section/name` links are rewritten automatically.
- **Code blocks**: fenced blocks with a language tag; highlighting is auto-detected by
  `rehype-highlight`.
- **New diagram**: add a `static/viz/<name>.html` using `viz.css`; it supports `?embed=1`
  to drop page chrome when iframed. List it in `static/viz/index.html`.

## Deployment

Built and deployed by `.github/workflows/docs.yml` on pushes to `main` touching `docs/**`
or `typescript/**` (the playground bundles the library source). The workflow runs
`npm ci && npm run build` and publishes `docs/dist` to GitHub Pages.

## License

Apache License 2.0.
