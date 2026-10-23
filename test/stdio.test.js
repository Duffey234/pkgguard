import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const entry = fileURLToPath(new URL('../src/mcp-stdio.js', import.meta.url));
const TOOLS = ["scan_dependencies", "check_package"];
const CALL = null;

function rpc(messages) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (/PRIVATE_KEY/.test(k)) delete env[k]; // free mode: no key
    const child = spawn(process.execPath, [entry], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    const want = messages.filter((m) => m.id !== undefined).length;
    const timer = setTimeout(() => { child.kill(); reject(new Error('timeout; got: ' + out)); }, 15000);
    child.stdout.on('data', (d) => {
      out += d;
      const lines = out.split('\n').filter(Boolean);
      if (lines.length >= want) { clearTimeout(timer); child.kill(); resolve(lines.map((l) => JSON.parse(l)).sort((x, y) => x.id - y.id)); }
    });
    child.on('error', reject);
    for (const m of messages) child.stdin.write(JSON.stringify(m) + '\n');
  });
}

test('starts with no key and answers initialize + tools/list', async () => {
  const msgs = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ];
  const [init, list] = await rpc(msgs);
  assert.equal(init.id, 1);
  assert.ok(init.result.serverInfo.name);
  assert.ok(init.result.capabilities.tools);
  assert.equal(list.id, 2);
  assert.deepEqual(list.result.tools.map((t) => t.name).sort(), [...TOOLS].sort());
  for (const t of list.result.tools) assert.equal(t.inputSchema.type, 'object');
});

test('offline tool call in free mode', { skip: !CALL }, async () => {
  const [, res] = await rpc([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: CALL?.[0], arguments: CALL?.[1] } },
  ]);
  assert.equal(res.id, 2);
  assert.ok(!res.error, JSON.stringify(res.error));
  assert.ok(res.result.content[0].text.length > 0);
});
