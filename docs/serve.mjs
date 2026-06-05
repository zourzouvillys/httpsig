import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./dist/', import.meta.url));
const port = Number(process.env.PORT) || 8080;
// If the site was built with a BASE_PATH (e.g. /httpsig for GitHub Pages),
// strip it from incoming request paths so the local server still resolves.
const base = (process.env.BASE_PATH || '').replace(/\/$/, '');

const types = {
  '.html': 'text/html;charset=utf-8',
  '.css': 'text/css;charset=utf-8',
  '.js': 'application/javascript;charset=utf-8',
  '.mjs': 'application/javascript;charset=utf-8',
  '.json': 'application/json;charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.woff2': 'font/woff2',
};

createServer((req, res) => {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (base && urlPath.startsWith(base)) urlPath = urlPath.slice(base.length) || '/';
  let p = join(root, urlPath);
  if (existsSync(p) && statSync(p).isDirectory()) p = join(p, 'index.html');
  if (!existsSync(p)) {
    res.statusCode = 404;
    res.setHeader('content-type', 'text/html;charset=utf-8');
    res.end('<h1>404</h1><p>not found</p>');
    return;
  }
  res.setHeader('content-type', types[extname(p)] || 'application/octet-stream');
  res.end(readFileSync(p));
}).listen(port, () => {
  console.log(`Serving ${root} at http://localhost:${port}${base}/`);
});
