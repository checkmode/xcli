import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { createGateway } from '../dist/gateway/server.js';

let upstream, gateway, base, folder, seen;
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const stop = server => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));

before(async () => {
  folder = await mkdtemp(path.join(os.tmpdir(), 'xcli-gateway-'));
  await mkdir(path.join(folder, 'assets'));
  await writeFile(path.join(folder, 'index.html'), '<main>fixture</main>');
  await writeFile(path.join(folder, 'assets', 'app.js'), 'export {};');
  upstream = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      seen = { path: req.url, method: req.method, headers: req.headers, body };
      res.setHeader('Set-Cookie', ['xg_session=fixture; HttpOnly; Secure; SameSite=Strict']);
      res.setHeader('subscription-userinfo', 'upload=1; download=2; total=3; expire=0');
      res.end('upstream fixture');
    });
  });
  const upstreamPort = await listen(upstream);
  gateway = createGateway({ upstreamPort, staticDir: folder });
  base = 'http://127.0.0.1:' + await listen(gateway);
});
after(async () => { await stop(gateway); await stop(upstream); await rm(folder, { recursive: true, force: true }); });

test('serves only known static files with security headers', async () => {
  const index = await fetch(base + '/');
  assert.equal(index.status, 200); assert.match(await index.text(), /fixture/);
  const client = await fetch(base + '/client/shadowrocket#synthetic-token');
  assert.equal(client.status, 200); assert.match(await client.text(), /fixture/);
  assert.equal(index.headers.get('cache-control'), 'no-store');
  assert.match(index.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal((await fetch(base + '/assets/app.js')).status, 200);
  assert.equal((await fetch(base + '/assets/%2e%2e%2findex.html')).status, 404);
  assert.equal((await fetch(base + '/', { method: 'POST' })).status, 405);
  assert.equal((await fetch(base + '/client/shadowrocket', { method: 'POST' })).status, 405);
});

test('forwards the original path, body, authentication and response metadata', async () => {
  const response = await fetch(base + '/api/users?format=json', {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: 'xg_session=fixture',
      origin: 'https://panel.example', 'x-csrf-token': 'fixture-csrf' }, body: '{"name":"fixture"}'
  });
  assert.equal(response.status, 200); assert.equal(await response.text(), 'upstream fixture');
  assert.equal(seen.path, '/api/users?format=json'); assert.equal(seen.method, 'POST');
  assert.equal(seen.headers.cookie, 'xg_session=fixture'); assert.equal(seen.headers.origin, 'https://panel.example');
  assert.equal(seen.headers['x-csrf-token'], 'fixture-csrf'); assert.equal(seen.body, '{"name":"fixture"}');
  assert.match(response.headers.get('set-cookie'), /HttpOnly/);
  assert.equal(response.headers.get('subscription-userinfo'), 'upload=1; download=2; total=3; expire=0');
});

test('forwards subscription paths unchanged and reports backend failure without leaking paths', async () => {
  const response = await fetch(base + '/s/test-token/clash.yaml');
  assert.equal(response.status, 200); assert.equal(seen.path, '/s/test-token/clash.yaml');
  const failing = createGateway({ upstreamPort: 1, staticDir: folder });
  const port = await listen(failing);
  try {
    const result = await fetch(`http://127.0.0.1:${port}/s/test-token/clash.yaml`);
    assert.equal(result.status, 502); assert.doesNotMatch(await result.text(), /test-token/);
  } finally { await stop(failing); }
});

test('removes hop-by-hop and connection-nominated headers', async () => {
  const request = http.request(base + '/api/example', { headers: { connection: 'close, x-internal-hop',
    'x-internal-hop': 'must-not-forward', 'x-csrf-token': 'unchanged' } });
  const response = await new Promise((resolve, reject) => {
    request.on('response', resolve); request.on('error', reject); request.end();
  });
  response.resume();
  await new Promise(resolve => response.on('end', resolve));
  assert.equal(seen.headers['x-internal-hop'], undefined);
  assert.equal(seen.headers['x-csrf-token'], 'unchanged');
});
