const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const { createStubUpstream } = require('./helpers/stub-upstream');

// Spawn the real proxy.js as a subprocess with a temp config + keys file, so
// we exercise the actual server (not just required functions). Returns a handle
// with a .kill() and a base URL.
//
// Harness notes (deviations from the original brief, all test-only):
//  - cwd is the TEMP dir (not the repo root) so proxy.js reads the temp
//    config.json and the configured `routes` actually reach the proxy. The repo
//    root has no config.json, so the brief's repo-root cwd would silently fall
//    back to defaults with an empty routes Map.
//  - proxy.js is launched by absolute path (cwd is no longer the repo root).
//  - OAUTH_TOKEN is injected so loadConfig() does not process.exit(1) on
//    missing credentials and /health can respond. The prefix path itself never
//    touches oauth; this only lets the server start self-contained (no reliance
//    on the host's ~/.claude/.credentials.json).
function startProxyOnPort(config, port, env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-test-'));
  const PROXY_KEY = 'test-proxy-key';
  const keyHash = require('crypto').createHash('sha256').update(PROXY_KEY).digest('hex');
  fs.writeFileSync(path.join(dir, 'keys.json'), JSON.stringify([{ name: 'test', key_hash: keyHash }]));
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config));
  const child = spawn(process.execPath, [path.resolve(__dirname, '..', 'proxy.js')], {
    cwd: dir,
    env: { ...process.env, OAUTH_TOKEN: 'test-oauth-token', KEYS_FILE: path.join(dir, 'keys.json'), PROXY_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  // Drain child stdio so the pipe never blocks the process, and surface
  // unexpected proxy exits for easier debugging.
  child.stdout.on('data', () => {});
  child.stderr.on('data', (d) => { process.stderr.write(`[proxy stderr] ${d}`); });
  child.on('error', (e) => { throw new Error(`proxy spawn failed: ${e.message}`); });
  const base = `http://127.0.0.1:${port}`;
  return { dir, child, PROXY_KEY, base };
}

async function waitForHealth(base, ms = 5000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(base + '/health');
      if (r.ok) return true;
    } catch (_) {}
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error('proxy did not become healthy');
}

async function kill(child) {
  if (!child.killed) { child.kill('SIGTERM'); }
}

test('prefix route: plain JSON pass-through rewrites model and swaps auth', async () => {
  const upstream = createStubUpstream({
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ok: true })
  });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;

  const proxyPort = 18811;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { t9s: { baseUrl: `http://127.0.0.1:${upPort}`, token: 't9s-secret' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: JSON.stringify({ model: 't9s/MODEL_A', max_tokens: 10, messages: [{ role: 'user', content: 'hi' }] })
    });
    assert.strictEqual(resp.status, 200);
    const json = await resp.json();
    assert.deepStrictEqual(json, { ok: true });

    // Upstream saw the model with prefix stripped:
    assert.strictEqual(upstream.requests.length, 1);
    const upReq = upstream.requests[0];
    const upBody = JSON.parse(upReq.body);
    assert.strictEqual(upBody.model, 'MODEL_A', 'model prefix must be stripped');
    // Auth swapped to route token, client key stripped:
    assert.strictEqual(upReq.headers['authorization'], 'Bearer t9s-secret');
    assert.strictEqual(upReq.headers['x-api-key'], undefined, 'client x-api-key must be stripped');
    // Path transparent:
    assert.strictEqual(upReq.url, '/v1/messages');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});

test('prefix route: authHeader x-api-key sends bare token', async () => {
  const upstream = createStubUpstream({ status: 200, headers: { 'content-type': 'application/json' }, body: '{}' });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxyPort = 18812;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { ea: { baseUrl: `http://127.0.0.1:${upPort}`, token: 'ea-secret', authHeader: 'x-api-key' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: JSON.stringify({ model: 'ea/MODEL_B', messages: [] })
    });
    const upReq = upstream.requests[0];
    assert.strictEqual(upReq.headers['x-api-key'], 'ea-secret', 'bare token via x-api-key');
    assert.strictEqual(upReq.headers['authorization'], undefined, 'no authorization header when authHeader is custom');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});

test('prefix route: SSE response is piped byte-for-byte', async () => {
  const sseChunks = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const upstream = createStubUpstream({
    status: 200,
    headers: { 'content-type': 'text/event-stream' },
    sse: sseChunks
  });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxyPort = 18813;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { t9s: { baseUrl: `http://127.0.0.1:${upPort}`, token: 't9s-secret' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: JSON.stringify({ model: 't9s/MODEL_A', stream: true, messages: [] })
    });
    assert.strictEqual(resp.headers.get('content-type'), 'text/event-stream');
    const text = await resp.text();
    assert.strictEqual(text, sseChunks.join(''), 'SSE bytes must pass through unchanged');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});

test('prefix route: basePath is prepended to the request path', async () => {
  const upstream = createStubUpstream({ status: 200, headers: { 'content-type': 'application/json' }, body: '{}' });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxyPort = 18814;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { t9s: { baseUrl: `http://127.0.0.1:${upPort}/internal/v1`, token: 't9s-secret' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    await fetch(proxy.base + '/v1/messages?beta=true', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: JSON.stringify({ model: 't9s/MODEL_A', messages: [] })
    });
    assert.strictEqual(upstream.requests[0].url, '/internal/v1/v1/messages?beta=true');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});

test('prefix route: unknown prefix falls through (does not hit upstream stub)', async () => {
  const upstream = createStubUpstream({ status: 200, headers: { 'content-type': 'application/json' }, body: '{}' });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxyPort = 18815;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { t9s: { baseUrl: `http://127.0.0.1:${upPort}`, token: 't9s-secret' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    // model "unknown/foo" has no matching route. It would fall to the Anthropic
    // default path and fail at the network/credentials layer (no creds in test).
    // We assert that the upstream stub was NOT contacted (no prefix dispatch).
    await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: JSON.stringify({ model: 'unknown/foo', messages: [] })
    }).catch(() => {});
    await new Promise((res) => setTimeout(res, 100));
    assert.strictEqual(upstream.requests.length, 0, 'unknown prefix must not dispatch to a route');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});

// Spec edge case: a request that classifies as real Claude Code (body
// fingerprint + CC header profile) MUST still take the prefix path when the
// model is prefixed — it must NOT fall through to the Anthropic pass-through.
// The prefix branch runs before any clientProfile-driven logic, so CC
// characteristics never bypass prefix routing.
test('prefix route: Claude-Code-characteristic request with prefixed model still takes the prefix path', async () => {
  const upstream = createStubUpstream({
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ok: true })
  });
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxyPort = 18816;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: { t9s: { baseUrl: `http://127.0.0.1:${upPort}`, token: 't9s-secret' } }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': proxy.PROXY_KEY,
        'user-agent': 'claude-cli/1.0.0 (external, cli)',
        'x-app': 'cli',
        'x-stainless-lang': 'js',
        'x-stainless-runtime': 'node',
        'x-stainless-package-version': '0.1.0',
        'x-claude-code-session-id': 'test-session'
      },
      body: JSON.stringify({
        model: 't9s/MODEL_A',
        max_tokens: 10,
        system: 'x-anthropic-billing-header: cc_version=1.0.0; cc_entrypoint=cli;',
        messages: [{ role: 'user', content: 'hi' }]
      })
    });
    assert.strictEqual(resp.status, 200);
    // The prefix path took over: the stub was contacted with the stripped model
    // and the route token, NOT the Anthropic path.
    assert.strictEqual(upstream.requests.length, 1, 'CC request must dispatch via prefix route, not Anthropic');
    const upReq = upstream.requests[0];
    assert.strictEqual(JSON.parse(upReq.body).model, 'MODEL_A', 'model prefix must be stripped even for CC requests');
    assert.strictEqual(upReq.headers['authorization'], 'Bearer t9s-secret', 'route token must be used');
    assert.strictEqual(upReq.headers['x-api-key'], undefined, 'client x-api-key must be stripped');
  } finally {
    await kill(proxy.child);
    upstream.server.close();
  }
});
