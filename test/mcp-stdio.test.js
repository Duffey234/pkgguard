// Adapted from the hosted service's stdio.test.js (x402-pkgguard). The stdio binary talks to a local stand-in for the
// free preview API that replays responses recorded from the real PkgGuard app (test/fixtures/preview-responses.json),
// so the test needs no network. The paid end-to-end test (local Worker app + fake facilitator) stays in the hosted repo.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createPaidClient, PAY_TO as CLIENT_PAY_TO } from '../src/paid.js';
import { toPackages, preview } from '../src/lite.js';

const BIN = fileURLToPath(new URL('../src/mcp-stdio.js', import.meta.url));
const MANIFEST = JSON.stringify({ dependencies: { lodash: '4.17.15', 'flatmap-stream': '0.1.1' } });
const RECORDED = JSON.parse(readFileSync(new URL('./fixtures/preview-responses.json', import.meta.url), 'utf8'));
const PKGGUARD_PAY_TO = '0x3c1A1E01e790Cd326495631B3b38Bd7068F08d6F';

function localApi() {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      const hit = req.method === 'POST' && req.url === '/v1/preview' && RECORDED.find((r) => JSON.stringify(r.packages) === JSON.stringify(JSON.parse(body || '{}').packages));
      res.writeHead(hit ? 200 : 404, { 'content-type': 'application/json' });
      res.end(JSON.stringify(hit ? hit.response : { error: 'not_recorded' }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}
function session(messages, env) {
  return new Promise((resolve, reject) => {
    const e = { ...process.env, ...env }; delete e.PKGGUARD_X402_PRIVATE_KEY; delete e.X402_PRIVATE_KEY;
    const p = spawn(process.execPath, [BIN], { stdio: ['pipe', 'pipe', 'inherit'], env: e });
    const out = []; let buf = '';
    const want = messages.filter((m) => m.id !== undefined).length;
    const timer = setTimeout(() => { p.kill(); reject(new Error('timeout: ' + buf)); }, 10000);
    p.stdout.on('data', (d) => {
      buf += d; let i;
      while ((i = buf.indexOf('\n')) >= 0) { out.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); }
      if (out.length >= want) { clearTimeout(timer); p.kill(); resolve(out.sort((a, b) => a.id - b.id)); }
    });
    for (const m of messages) p.stdin.write(JSON.stringify(m) + '\n');
  });
}

test('stdio MCP binary against a local API: initialize, tools/list, scan_dependencies (path + contents), check_package, unknown method', async () => {
  const api = await localApi();
  const dir = mkdtempSync(join(tmpdir(), 'pkgg-')); const file = join(dir, 'package.json'); writeFileSync(file, MANIFEST);
  try {
    const [init, list, byPath, byText, one, bad] = await session([
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scan_dependencies', arguments: { path: file } } },
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'scan_dependencies', arguments: { manifest: 'requests==2.19.0' } } },
      { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'check_package', arguments: { name: 'left-pad', version: '1.3.0' } } },
      { jsonrpc: '2.0', id: 6, method: 'nope' },
    ], { PKGGUARD_API_URL: api.url });
    assert.equal(init.result.serverInfo.name, 'pkgguard');
    assert.deepEqual(list.result.tools.map((t) => t.name), ['scan_dependencies', 'check_package']);
    assert.match(byPath.result.content[0].text, /MALICIOUS/); assert.equal(byPath.result.structuredContent.malicious_count, 1);
    assert.match(byText.result.content[0].text, /VULNERABLE/);
    assert.match(one.result.content[0].text, /CLEAN/);
    assert.equal(bad.error.code, -32601);
  } finally { api.close(); }
});

test('toPackages: manifest / packages / single, errors; preview caps at 25 locally (no request)', async () => {
  assert.equal(toPackages({ manifest: MANIFEST }).packages.length, 2);
  assert.equal(toPackages({ name: 'lodash', version: '4.17.15' }).single, true);
  assert.match(toPackages({ name: 'lodash' }).error, /version/);
  assert.match(toPackages({}).error, /provide/);
  let called = false;
  const r = await preview(Array(26).fill({ ecosystem: 'npm', name: 'a', version: '1.0.0' }), { fetchImpl: async () => { called = true; } });
  assert.equal(r.error, 'too_many'); assert.equal(called, false);
});

test('paid client: no key -> null; bad key -> error (key never echoed); pay-to pinned to PkgGuard; valid key needs the optional deps', async () => {
  assert.equal(await createPaidClient({ env: {} }), null);
  const bad = await createPaidClient({ env: { PKGGUARD_X402_PRIVATE_KEY: 'not-a-key-secret123' } });
  assert.match(bad.error, /not a 32-byte hex/); assert.doesNotMatch(bad.error, /secret123/);
  assert.equal(CLIENT_PAY_TO, PKGGUARD_PAY_TO);
  const key = `0x${randomBytes(32).toString('hex')}`; // throwaway, never funded
  const c = await createPaidClient({ env: { PKGGUARD_X402_PRIVATE_KEY: key } });
  if (c.error) { assert.match(c.error, /npm install @x402\/fetch @x402\/evm viem/); assert.ok(!c.error.includes(key.slice(2))); } // default: optional deps not installed
  else { assert.match(c.payer, /^0x[0-9a-fA-F]{40}$/); assert.equal(c.apiBase, 'https://api.youraitools.co/pkgguard'); }
});
