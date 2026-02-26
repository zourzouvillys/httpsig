# httpsig Documentation Site

Docusaurus 3.x site for the httpsig project. Deployed to GitHub Pages at https://zourzouvillys.github.io/httpsig/.

## Prerequisites

- Node.js 20+
- npm

## Development

```bash
cd docs
npm install
npm run start        # dev server at http://localhost:3000/httpsig/
```

The dev server hot-reloads on changes to docs, pages, and config.

## Build

```bash
npm run build        # production build into build/
npm run serve        # serve the production build locally
npm run typecheck    # check TypeScript types
```

## Project Structure

```
docs/
  docusaurus.config.ts          Site config (URL, navbar, footer, Prism languages)
  sidebars.ts                   Sidebar navigation structure
  package.json
  tsconfig.json
  src/
    pages/
      index.tsx                 Landing page
      index.module.css          Landing page styles
    css/
      custom.css                Global theme overrides
  docs/
    intro.md                    Overview / what is RFC 9421
    getting-started/
      go.md                     Per-language quick start guides
      typescript.md
      java.md
      swift.md
      kotlin.md
    concepts/
      how-it-works.md           RFC 9421 flow
      components.md             Derived components (@method, @path, etc.)
      algorithms.md             Supported algorithms
      key-management.md         Key types and providers
      content-digest.md         RFC 9530
    guides/
      signing.md                Signing walkthrough
      verifying.md              Verification walkthrough
      integrations.md           HTTP client integrations
  static/
    img/                        Favicon, logos
```

## Adding Content

- **New doc page**: Create a `.md` file in the appropriate `docs/` subdirectory. Add it to `sidebars.ts` if it shouldn't be auto-discovered.
- **New top-level page**: Create a `.tsx` file in `src/pages/`.
- **Code blocks**: Use fenced code blocks with language tags. Supported syntax highlighting: `go`, `typescript`, `java`, `kotlin`, `swift`, `bash`, `json` (configured in `docusaurus.config.ts` under `prism.additionalLanguages`).
- **Tabs**: Use Docusaurus `<Tabs>` component for multi-language examples with `groupId="language"` for synced tab state.

## Deployment

Deployed automatically via `.github/workflows/docs.yml` on pushes to `main` that touch `docs/**`. Can also be triggered manually from the Actions tab.

## License

Apache License 2.0.
