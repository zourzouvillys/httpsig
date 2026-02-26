# Documentation Site

## Build and Preview

```bash
cd docs
npm install
npm run start     # dev server with hot-reload
npm run build     # production build
npm run serve     # serve production build locally
```

## Conventions

- Docusaurus 3.x with `v4: true` future flag
- TypeScript config (`docusaurus.config.ts`, `sidebars.ts`)
- No blog (disabled in preset config)
- `onBrokenLinks: 'throw'` means builds fail on dead internal links
- Prism syntax highlighting for: go, typescript, java, kotlin, swift, bash, json
- Base URL is `/httpsig/` (GitHub Pages project site)
- Sidebar is manually defined in `sidebars.ts`, not auto-generated

## Content Structure

| Directory | Content |
|---|---|
| `docs/getting-started/` | Per-language install + quick start |
| `docs/concepts/` | RFC 9421 explainers (components, algorithms, key management, content-digest) |
| `docs/guides/` | Signing, verifying, HTTP client integrations |
| `src/pages/index.tsx` | Landing page with hero + feature cards |

## Key Files

| File | Purpose |
|---|---|
| `docusaurus.config.ts` | Site URL, navbar, footer links, Prism config |
| `sidebars.ts` | Sidebar nav with 3 categories |
| `src/css/custom.css` | CSS variable overrides for light/dark themes |
| `src/pages/index.tsx` | React landing page |

## Deployment

GitHub Actions workflow at `.github/workflows/docs.yml` builds and deploys to GitHub Pages on pushes to `main` that change `docs/**`.
