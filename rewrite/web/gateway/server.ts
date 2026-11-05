import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer, request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import path from 'node:path';

export interface GatewayOptions { upstreamPort: number; staticDir: string }

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

function filtered(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const connection = headers.connection;
  const dynamic = new Set((Array.isArray(connection) ? connection.join(',') : connection ?? '').toLowerCase().split(',').map(v => v.trim()));
  return Object.fromEntries(Object.entries(headers).filter(([key, value]) => value !== undefined && !hopHeaders.has(key.toLowerCase()) && !dynamic.has(key.toLowerCase())));
}

function security(response: ServerResponse): void {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Security-Policy', csp);
}

function proxy(req: IncomingMessage, res: ServerResponse, upstreamPort: number): void {
  const restore = req.method === 'POST' && req.url?.split('?', 1)[0] === '/api/backups/restore';
  const upstream = httpRequest({ hostname: '127.0.0.1', port: upstreamPort, method: req.method,
    path: req.url, headers: filtered(req.headers), timeout: restore ? 115_000 : 15_000 }, response => {
    res.statusCode = response.statusCode ?? 502;
    for (const [key, value] of Object.entries(filtered(response.headers))) if (value !== undefined) res.setHeader(key, value);
    security(res);
    response.on('error', () => res.destroy());
    response.pipe(res);
  });
  upstream.on('timeout', () => upstream.destroy());
  upstream.on('error', () => {
    if (res.headersSent) { res.destroy(); return; }
    res.statusCode = 502; security(res);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end('{"detail":"后端服务暂不可用"}');
  });
  req.on('error', () => upstream.destroy());
  req.on('aborted', () => upstream.destroy());
  res.on('close', () => { if (!res.writableFinished) upstream.destroy(); });
  req.pipe(upstream);
}

async function serve(req: IncomingMessage, res: ServerResponse, options: GatewayOptions): Promise<void> {
  security(res);
  const raw = req.url ?? '/';
  const route = raw.split('?', 1)[0] ?? '';
  if (!route.startsWith('/') || route.startsWith('//') || route.includes('\\') || /[\x00-\x1f\x7f]/.test(route)) {
    res.statusCode = 400; res.end(); return;
  }
  if (route === '/healthz' || route === '/shadowrocket-dns.sgmodule'
      || route.startsWith('/api/') || route.startsWith('/s/')) {
    proxy(req, res, options.upstreamPort); return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.statusCode = 405; res.setHeader('Allow', 'GET, HEAD'); res.end(); return; }
  const file = route === '/' || route === '/client/shadowrocket' ? 'index.html' : /^\/assets\/[A-Za-z0-9._-]+$/.test(route) ? route.slice(1) : '';
  if (!file) { res.statusCode = 404; res.end(); return; }
  const target = path.join(options.staticDir, file);
  try {
    const info = await stat(target);
    if (!info.isFile()) throw new Error('not a file');
    const extension = path.extname(file);
    const types: Record<string,string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png' };
    res.setHeader('Content-Type', types[extension] ?? 'application/octet-stream');
    res.setHeader('Content-Length', info.size);
    if (req.method === 'HEAD') { res.end(); return; }
    const stream = createReadStream(target);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  } catch {
    res.statusCode = 404; res.end();
  }
}

/** The caller must listen on loopback; Xray and the upstream are not exposed here. */
export function createGateway(options: GatewayOptions) {
  if (!Number.isInteger(options.upstreamPort) || options.upstreamPort < 1 || options.upstreamPort > 65535)
    throw new Error('Invalid upstream port');
  return createServer((req, res) => {
    void serve(req, res, options).catch(() => { if (!res.headersSent) { res.statusCode = 500; security(res); res.end(); } else res.destroy(); });
  });
}
