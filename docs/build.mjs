#!/usr/bin/env node
// Zero-framework static site generator for the httpsig docs + interactive tool.
// Markdown (unified/remark/rehype) -> HTML templates with {{var}} substitution,
// a single warm stylesheet, standalone <canvas> diagrams, and an esbuild-bundled
// in-browser RFC 9421 playground. No React, no client framework.

import { readdir, readFile, writeFile, mkdir, rm, cp, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, relative, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import matter from 'gray-matter';
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import remarkRehype from 'remark-rehype';
import rehypeSlug from 'rehype-slug';
import rehypeAutolinkHeadings from 'rehype-autolink-headings';
import rehypeHighlight from 'rehype-highlight';
import rehypeStringify from 'rehype-stringify';
import * as esbuild from 'esbuild';

const SITE_DIR = dirname(fileURLToPath(import.meta.url));
const CONTENT_DIR = join(SITE_DIR, 'content');
const TEMPLATES_DIR = join(SITE_DIR, 'templates');
const STATIC_DIR = join(SITE_DIR, 'static');
const DIST_DIR = join(SITE_DIR, 'dist');
const LIB_ENTRY = join(SITE_DIR, '..', 'typescript', 'src', 'index.ts');

// Base path the site is published under. Empty for local dev; "/httpsig" on
// GitHub Pages (set by the `build` npm script / CI).
const BASE = (process.env.BASE_PATH || '').replace(/\/$/, '');
const GITHUB = 'https://github.com/zourzouvillys/httpsig';

// ---- Top navigation (site header) ----
const NAV = [
  { key: 'overview', label: 'Overview', href: '/' },
  { key: 'docs', label: 'Docs', href: '/docs/' },
  { key: 'playground', label: 'Playground', href: '/playground/' },
  { key: 'diagrams', label: 'Diagrams', href: '/viz/' },
  { key: 'github', label: 'GitHub ↗', href: GITHUB, external: true },
];

// ---- Documentation tree (drives sidebar + routing) ----
// Each item: { file (relative to content/), url, label }. `section: null` = top-level.
const DOC_TREE = [
  {
    section: null,
    items: [{ file: 'intro.md', url: '/docs/', label: 'Introduction' }],
  },
  {
    section: 'Getting Started',
    items: [
      { file: 'getting-started/go.md', url: '/docs/getting-started/go/', label: 'Go' },
      { file: 'getting-started/typescript.md', url: '/docs/getting-started/typescript/', label: 'TypeScript' },
      { file: 'getting-started/java.md', url: '/docs/getting-started/java/', label: 'Java' },
      { file: 'getting-started/swift.md', url: '/docs/getting-started/swift/', label: 'Swift' },
      { file: 'getting-started/kotlin.md', url: '/docs/getting-started/kotlin/', label: 'Kotlin' },
    ],
  },
  {
    section: 'Concepts',
    items: [
      { file: 'concepts/how-it-works.md', url: '/docs/concepts/how-it-works/', label: 'How it works' },
      { file: 'concepts/components.md', url: '/docs/concepts/components/', label: 'Components' },
      { file: 'concepts/algorithms.md', url: '/docs/concepts/algorithms/', label: 'Algorithms' },
      { file: 'concepts/key-management.md', url: '/docs/concepts/key-management/', label: 'Key management' },
      { file: 'concepts/content-digest.md', url: '/docs/concepts/content-digest/', label: 'Content-Digest' },
      { file: 'concepts/security.md', url: '/docs/concepts/security/', label: 'Security' },
    ],
  },
  {
    section: 'Guides',
    items: [
      { file: 'guides/signing.md', url: '/docs/guides/signing/', label: 'Signing requests' },
      { file: 'guides/verifying.md', url: '/docs/guides/verifying/', label: 'Verifying signatures' },
      { file: 'guides/signing-responses.md', url: '/docs/guides/signing-responses/', label: 'Signing responses' },
      { file: 'guides/accept-signature.md', url: '/docs/guides/accept-signature/', label: 'Signature negotiation' },
      { file: 'guides/integrations.md', url: '/docs/guides/integrations/', label: 'Client integrations' },
      { file: 'guides/proxy-forwarding.md', url: '/docs/guides/proxy-forwarding/', label: 'Proxy forwarding' },
    ],
  },
];

// Flat list of all docs + lookup maps.
const ALL_DOCS = DOC_TREE.flatMap((g) => g.items);
const DOC_BY_FILE = new Map(ALL_DOCS.map((d) => [d.file, d]));
// Map the docs' previous (Docusaurus-style) absolute paths to the new pretty
// URLs, so the existing in-content links keep resolving. intro.md was served
// at "/"; every other file at "/<section>/<name>".
const LEGACY_PATH_TO_URL = new Map(
  ALL_DOCS.map((d) => [
    d.file === 'intro.md' ? '/' : '/' + d.file.replace(/\.md$/, ''),
    d.url,
  ]),
);

// ---- Markdown pipeline ----
const processor = unified()
  .use(remarkParse)
  .use(remarkGfm)
  .use(remarkRehype, { allowDangerousHtml: true })
  .use(rehypeSlug)
  .use(rehypeAutolinkHeadings, {
    behavior: 'wrap',
    properties: { className: ['heading-link'] },
  })
  .use(rehypeHighlight, { detect: true, ignoreMissing: true })
  .use(rehypeStringify, { allowDangerousHtml: true });

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Prefix an internal absolute path with BASE. External URLs pass through.
function url(href) {
  if (/^(https?:)?\/\//.test(href) || href.startsWith('#') || href.startsWith('mailto:')) {
    return href;
  }
  return BASE + href;
}

function renderTemplate(tpl, vars) {
  return tpl.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (_, k) => (k in vars ? vars[k] : ''));
}

function renderNav(activeKey) {
  return NAV.map((n) => {
    const cls = n.key === activeKey ? ' class="active"' : '';
    const ext = n.external ? ' target="_blank" rel="noopener"' : '';
    return `<a href="${url(n.href)}"${cls}${ext}>${escapeHtml(n.label)}</a>`;
  }).join('\n        ');
}

// Render the docs sidebar, marking the current page active.
function renderSidebar(activeUrl) {
  const parts = [];
  for (const group of DOC_TREE) {
    if (group.section) {
      parts.push(`<p class="doc-side-label">${escapeHtml(group.section)}</p>`);
    }
    parts.push('<ul class="doc-side-list">');
    for (const item of group.items) {
      const active = item.url === activeUrl ? ' class="active"' : '';
      parts.push(`<li><a href="${url(item.url)}"${active}>${escapeHtml(item.label)}</a></li>`);
    }
    parts.push('</ul>');
  }
  return parts.join('\n');
}

// Pull h2/h3 headings (with ids emitted by rehype-slug) for the on-this-page TOC.
function extractToc(html) {
  const items = [];
  const re = /<h([23])[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const level = Number(m[1]);
    const id = m[2];
    const text = m[3].replace(/<[^>]+>/g, '').trim();
    items.push({ level, id, text });
  }
  return items;
}

function renderToc(items) {
  if (!items.length) return '';
  return items
    .map(
      (i) =>
        `<li class="level-${i.level}"><a href="#${escapeHtml(i.id)}">${escapeHtml(i.text)}</a></li>`,
    )
    .join('\n');
}

// The source docs use Docusaurus MDX `<Tabs>`/`<TabItem>` for multi-language
// examples. The plain markdown pipeline doesn't understand those, so transform
// them (at the source level) into raw-HTML tab widgets. Crucially, each tab's
// body is left as markdown — separated by blank lines from the wrapper divs — so
// the fenced code blocks inside still get parsed and syntax-highlighted. The
// little tab-switching script lives in templates/doc.html.
let tabSeq = 0;
function transformTabs(md) {
  // Drop the MDX import lines (`import Tabs from '@theme/Tabs';` etc.).
  md = md.replace(/^[ \t]*import\s+\w+\s+from\s+['"]@theme\/Tabs?(?:Item)?['"];?[ \t]*$/gm, "");

  return md.replace(/<Tabs\b([^>]*)>([\s\S]*?)<\/Tabs>/g, (whole, attrs, inner) => {
    const groupMatch = attrs.match(/groupId="([^"]*)"/);
    const group = groupMatch ? groupMatch[1] : "";

    const items = [];
    const re = /<TabItem\b([^>]*)>([\s\S]*?)(?=<TabItem\b|$)/g;
    let m;
    while ((m = re.exec(inner)) !== null) {
      const a = m[1];
      const body = m[2].replace(/<\/TabItem>\s*$/, "").trim();
      const val = (a.match(/value="([^"]*)"/) || [])[1] || `tab${items.length}`;
      const label = (a.match(/label="([^"]*)"/) || [])[1] || val;
      items.push({ val, label, body });
    }
    if (!items.length) return whole;

    tabSeq += 1;
    const groupAttr = group ? ` data-group="${escapeHtml(group)}"` : "";
    const nav =
      `<div class="httabs-nav" role="tablist">` +
      items
        .map(
          (it, i) =>
            `<button type="button" class="httab${i === 0 ? " active" : ""}" data-tab="${escapeHtml(it.val)}">${escapeHtml(it.label)}</button>`,
        )
        .join("") +
      `</div>`;
    const panels = items
      .map(
        (it, i) =>
          `\n<div class="httabs-panel${i === 0 ? " active" : ""}" data-tab="${escapeHtml(it.val)}">\n\n${it.body}\n\n</div>`,
      )
      .join("");
    return `<div class="httabs"${groupAttr}>\n${nav}${panels}\n</div>`;
  });
}

// Markdown cross-links use relative `.md` paths (so they also work on GitHub).
// Rewrite each to the published pretty URL. `srcFile` is the content-relative
// path of the doc currently being rendered (e.g. "guides/signing.md").
function rewriteLinks(html, srcFile) {
  const srcDir = posix.dirname(srcFile);
  // 1. Relative `.md` links (GitHub-style): resolve against the current doc.
  html = html.replace(
    /href="([^"#?]+?)\.md([#?][^"]*)?"/g,
    (match, path, suffix = '') => {
      if (/^(https?:)?\/\//.test(path)) return match;
      const resolved = posix.normalize(posix.join(srcDir, `${path}.md`));
      const target = DOC_BY_FILE.get(resolved);
      if (target) return `href="${url(target.url)}${suffix}"`;
      return `href="${GITHUB}/blob/main/docs/content/${resolved}${suffix}"`;
    },
  );
  // 2. Legacy absolute doc paths (e.g. /guides/integrations, /concepts/x#y, /).
  html = html.replace(
    /href="(\/[^"#?]*)([#?][^"]*)?"/g,
    (match, path, suffix = '') => {
      const target = LEGACY_PATH_TO_URL.get(path);
      if (target) return `href="${url(target)}${suffix}"`;
      return match;
    },
  );
  return html;
}

// Resolve a page title: frontmatter `title`, else first markdown H1, else label.
function pageTitle(fm, markdown, fallback) {
  if (fm.title) return String(fm.title);
  const m = markdown.match(/^#\s+(.+)$/m);
  if (m) return m[1].trim();
  return fallback;
}

async function writePageAt(relPath, content) {
  const full = join(DIST_DIR, relPath, 'index.html');
  await mkdir(dirname(full), { recursive: true });
  await writeFile(full, content);
}

// Convert a site URL like "/docs/guides/signing/" to a dist directory path.
function distDirForUrl(u) {
  return u.replace(/^\//, '').replace(/\/$/, '');
}

async function buildDocPage(doc, layout, docTpl) {
  const raw = await readFile(join(CONTENT_DIR, doc.file), 'utf8');
  const { data: fm, content } = matter(raw);
  let html = String(await processor.process(transformTabs(content)));
  html = rewriteLinks(html, doc.file);
  const toc = renderToc(extractToc(html));
  const title = pageTitle(fm, content, doc.label);

  const body = renderTemplate(docTpl, {
    sidebar: renderSidebar(doc.url),
    content: html,
    toc,
    toc_wrap: toc ? '' : 'doc-toc-empty',
    source_path: `docs/content/${doc.file}`,
    github: GITHUB,
  });

  const page = renderTemplate(layout, {
    title: `${escapeHtml(title)} · httpsig`,
    nav: renderNav('docs'),
    base: BASE,
    body,
  });
  await writePageAt(distDirForUrl(doc.url), page);
}

async function buildHome(layout) {
  const homeRaw = await readFile(join(TEMPLATES_DIR, 'home.html'), 'utf8');
  const body = substituteAssets(homeRaw);
  const page = renderTemplate(layout, {
    title: 'httpsig · HTTP Message Signatures for every platform',
    nav: renderNav('overview'),
    base: BASE,
    body,
  });
  await writeFile(join(DIST_DIR, 'index.html'), page);
}

// Replace %BASE% tokens and {{base}} in raw HTML/CSS bodies (used by templates'
// hand-written content and copied static files).
function substituteAssets(text) {
  return text.replaceAll('%BASE%', BASE).replaceAll('{{base}}', BASE);
}

// Recursively copy static/ to dist/, substituting %BASE% in text assets.
async function copyStaticTree(srcDir, destDir) {
  const entries = await readdir(srcDir, { withFileTypes: true });
  await mkdir(destDir, { recursive: true });
  for (const e of entries) {
    const src = join(srcDir, e.name);
    const dest = join(destDir, e.name);
    // Tool source (bundled separately by esbuild) is not published as-is.
    if (e.name.endsWith('.ts') || e.name === 'crypto-shim.js' || e.name === 'buffer-shim.js') continue;
    if (e.isDirectory()) {
      await copyStaticTree(src, dest);
    } else if (/\.(html|css|svg|json|txt|webmanifest)$/.test(e.name)) {
      const txt = await readFile(src, 'utf8');
      await writeFile(dest, substituteAssets(txt));
    } else {
      await cp(src, dest);
    }
  }
}

async function copyStatic() {
  if (!existsSync(STATIC_DIR)) return;
  await copyStaticTree(STATIC_DIR, DIST_DIR);
}

// Render the playground page through the site layout so it shares the header,
// nav, and footer. The tool body lives in templates/playground.html; its CSS and
// the esbuild-bundled app.js are loaded as page assets.
async function buildPlaygroundPage(layout) {
  const tplPath = join(TEMPLATES_DIR, 'playground.html');
  if (!existsSync(tplPath)) return;
  const body = substituteAssets(await readFile(tplPath, 'utf8'));
  const head = `<link rel="stylesheet" href="${BASE}/playground/playground.css" />`;
  const page = renderTemplate(layout, {
    title: 'Playground · httpsig — sign, verify & inspect RFC 9421',
    nav: renderNav('playground'),
    base: BASE,
    head,
    body,
  });
  await writePageAt('playground', page);
}

// Bundle the interactive tool: tool glue (app.ts) + the local TS library, with a
// node:crypto browser shim so the WebCrypto code paths bundle cleanly.
async function bundlePlayground() {
  const entry = join(STATIC_DIR, 'playground', 'app.ts');
  if (!existsSync(entry)) return;
  await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    outfile: join(DIST_DIR, 'playground', 'app.js'),
    alias: { 'node:crypto': join(STATIC_DIR, 'playground', 'crypto-shim.js') },
    // The library uses the Node `Buffer` global for base64; inject a browser shim.
    inject: [join(STATIC_DIR, 'playground', 'buffer-shim.js')],
    legalComments: 'none',
    logLevel: 'warning',
  });
}

async function main() {
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(DIST_DIR, { recursive: true });

  const layout = await readFile(join(TEMPLATES_DIR, 'layout.html'), 'utf8');
  const docTpl = await readFile(join(TEMPLATES_DIR, 'doc.html'), 'utf8');

  for (const doc of ALL_DOCS) {
    await buildDocPage(doc, layout, docTpl);
  }
  await buildHome(layout);
  await buildPlaygroundPage(layout);
  await copyStatic();
  await bundlePlayground();

  console.log(
    `Built landing + ${ALL_DOCS.length} docs + diagrams + playground → ${relative(SITE_DIR, DIST_DIR)}${BASE ? ` (base ${BASE})` : ''}`,
  );
}

main().catch((err) => {
  console.error(`\nBuild failed:\n${err.stack || err.message}\n`);
  process.exit(1);
});
