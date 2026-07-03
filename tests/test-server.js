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

// Send SIGTERM and await the child's actual 'exit' event. Awaiting exit (rather
// than fire-and-forget) guarantees the port is released before the next test
// binds it, so a stale proxy can't answer a later test's waitForHealth or trip
// EADDRINUSE. A 3s fallback resolves the promise if exit never fires, so a
// wedged child can never stall the suite.
async function kill(child) {
  // Already exited: no 'exit' event will ever fire, so don't wait on it.
  if (child.exitCode !== null || child.signalCode !== null) return;
  let timer;
  const exited = new Promise((resolve) => {
    timer = setTimeout(resolve, 3000);
    if (typeof timer.unref === 'function') timer.unref();
    child.once('exit', () => { clearTimeout(timer); resolve(); });
  });
  if (!child.killed) child.kill('SIGTERM');
  await exited;
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
  }
});

test('prefix route: SSE response is piped byte-for-byte', async () => {
  const sseChunks = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"pong"}}\n\n',
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
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
    fs.rmSync(proxy.dir, { recursive: true, force: true });
  }
});

test('/health reports configured routes', async () => {
  const proxyPort = 18817;
  const proxy = startProxyOnPort({
    port: proxyPort,
    routes: {
      t9s: { baseUrl: 'http://127.0.0.1:9999', token: 't9s-secret' },
      endpoint_a: { baseUrl: 'https://api.example.com/v1', token: 'ea-secret', authHeader: 'x-api-key' }
    }
  }, proxyPort, {});
  try {
    await waitForHealth(proxy.base);
    const r = await fetch(proxy.base + '/health');
    const json = await r.json();
    assert.ok(Array.isArray(json.routes), 'routes is an array');
    assert.deepStrictEqual(json.routes.sort(), ['endpoint_a', 't9s']);
  } finally {
    await kill(proxy.child);
    fs.rmSync(proxy.dir, { recursive: true, force: true });
  }
});

// ─── Disguise path: upstream response decompression (gzip/br/zstd/identity) ─
// These tests point the disguise path at a local stub upstream by overriding
// UPSTREAM_HOST/PORT/SCHEME, so the disguise transform runs against a
// controllable compressed response. Requests are crafted to classify as
// openclaw-disguise (no CC body fingerprint, no CC headers, no route prefix).

const zlib = require('zlib');

// A disguise-classified request body: no x-anthropic-billing-header, model has
// no route prefix. stream:true for SSE tests.
function disguiseBody(stream) {
  // Include an OpenClaw tool named "exec" so buildScopedToolRenamePlan establishes
  // the exec<->Bash rename; otherwise reverseMap has no mapping to apply to the
  // response (the real disguise body always carries the tool set).
  const b = {
    model: 'claude-sonnet-4-5-20250929', max_tokens: 16,
    tools: [{ name: 'exec', description: 'run a shell command', input_schema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } }],
    messages: [{ role: 'user', content: 'hi' }]
  };
  if (stream) b.stream = true;
  return JSON.stringify(b);
}

async function startStubAndProxy(stubOpts, proxyPort) {
  const upstream = createStubUpstream(stubOpts);
  await new Promise((res) => upstream.server.listen(0, '127.0.0.1', res));
  const upPort = upstream.server.address().port;
  const proxy = startProxyOnPort(
    { port: proxyPort }, // no routes -> prefix routing won't intercept
    proxyPort,
    { UPSTREAM_HOST: '127.0.0.1', UPSTREAM_PORT: String(upPort), UPSTREAM_SCHEME: 'http' }
  );
  return { upstream, proxy, upPort };
}

// Extract concatenated text from all text_delta events in an SSE stream.
// The proxy's StreamingReverseMapper may legitimately split one logical text
// across multiple text_delta events (it buffers pattern-suffix candidates);
// the concatenation is what the client renders, so that's what we assert on.
function extractDeltasText(sseText) {
  const out = [];
  const re = /"type":"text_delta","text":"((?:\\.|[^"\\])*)"/g;
  let m;
  while ((m = re.exec(sseText)) !== null) {
    out.push(m[1].replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\"/g,'"').replace(/\\\\/g,'\\'));
  }
  return out.join('');
}
async function teardown(proxy, upstream) {
  await kill(proxy.child);
  await new Promise((res) => upstream.server.close(res));
  fs.rmSync(proxy.dir, { recursive: true, force: true });
}

test('disguise: advertises gzip,deflate,br,zstd upstream and decompresses gzip SSE', async () => {
  const sse = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"pong"}}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const { upstream, proxy } = await startStubAndProxy({ headers: { 'content-type': 'text/event-stream' }, sse, encoding: 'gzip' }, 19010);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(true)
    });
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.headers.get('content-encoding'), null, 'client must receive identity (no content-encoding)');
    const text = await resp.text();
    // transform is a no-op for these events; assert the concatenated delta text
    assert.strictEqual(extractDeltasText(text), 'pong', 'text_delta concatenation after decompress');
    // The proxy advertised gzip to the stub upstream:
    assert.strictEqual(upstream.requests[0].headers['accept-encoding'], 'gzip, deflate, br, zstd');
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: gzip SSE with reverseMap transform on a tool name', async () => {
  // A text_delta containing a disguised (CC-style) tool name that the reverseMap
  // should restore to the OpenClaw original. "Bash" is the CC name for "exec".
  // input_json_delta carries a tool_call input with a quoted "Bash" tool name;
  // reverseMap (quoted form "Bash"->"exec") restores it to the OpenClaw name.
  const sse = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","name":"Bash"}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const { upstream, proxy } = await startStubAndProxy({ headers: { 'content-type': 'text/event-stream' }, sse, encoding: 'gzip' }, 19011);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(true)
    });
    const text = await resp.text();
    assert.ok(text.includes('"name":"exec"'), `reverseMap should restore "Bash"->"exec"; got: ${text.slice(0,300)}`);
    assert.strictEqual(resp.headers.get('content-encoding'), null);
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: chunked gzip SSE (one member per event) reassembles in order', async () => {
  const sse = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"AAA"}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"BBB"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const { upstream, proxy } = await startStubAndProxy({ headers: { 'content-type': 'text/event-stream' }, sse, encoding: 'gzip' }, 19012);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(true)
    });
    const text = await resp.text();
    assert.strictEqual(extractDeltasText(text), 'AAABBB', 'chunked gzip reassembles to ordered delta text');
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: brotli non-SSE JSON is decompressed then reverseMapped', async () => {
  // Non-SSE JSON body containing a disguised tool name "Bash" that reverseMap
  // turns back into "exec".
  // A tool_use block whose name "Bash" reverseMap restores to "exec".
  const payload = JSON.stringify({ id: 'msg_1', content: [{ type: 'tool_use', name: 'Bash', input: { command: 'ls' } }] });
  const { upstream, proxy } = await startStubAndProxy({ status: 200, headers: { 'content-type': 'application/json' }, body: payload, encoding: 'br' }, 19013);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(false)
    });
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.headers.get('content-encoding'), null, 'client gets identity');
    const json = await resp.json();
    assert.strictEqual(json.content[0].name, 'exec', 'reverseMap ran on decompressed body');
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: gzip error response is decompressed then reverseMapped', async () => {
  // error body with a quoted "Bash" tool name reverseMap restores to "exec".
  const payload = JSON.stringify({ type: 'error', error: { type: 'bad_request', message: 'tool "Bash" failed' } });
  const { upstream, proxy } = await startStubAndProxy({ status: 400, headers: { 'content-type': 'application/json' }, body: payload, encoding: 'gzip' }, 19014);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(false)
    });
    assert.strictEqual(resp.status, 400);
    assert.strictEqual(resp.headers.get('content-encoding'), null, 'client gets identity even on error');
    const json = await resp.json();
    assert.strictEqual(json.error.message, 'tool "exec" failed', 'reverseMap ran on decompressed error body');
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: identity (no content-encoding) SSE still works — regression guard', async () => {
  const sse = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const { upstream, proxy } = await startStubAndProxy({ headers: { 'content-type': 'text/event-stream' }, sse }, 19015);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(true)
    });
    const text = await resp.text();
    assert.strictEqual(extractDeltasText(text), 'hi', 'identity SSE delta text unchanged');
    assert.strictEqual(upstream.requests[0].headers['accept-encoding'], 'gzip, deflate, br, zstd');
  } finally {
    await teardown(proxy, upstream);
  }
});

test('disguise: zstd SSE (Node 22+ only)', { skip: typeof zlib.zstdCompressSync !== 'function' }, async () => {
  const sse = [
    'event: message_start\ndata: {"type":"message_start"}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pong"}}\n\n',
    'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
    'event: message_stop\ndata: {"type":"message_stop"}\n\n'
  ];
  const { upstream, proxy } = await startStubAndProxy({ headers: { 'content-type': 'text/event-stream' }, sse, encoding: 'zstd' }, 19016);
  try {
    await waitForHealth(proxy.base);
    const resp = await fetch(proxy.base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': proxy.PROXY_KEY },
      body: disguiseBody(true)
    });
    const text = await resp.text();
    assert.strictEqual(extractDeltasText(text), 'pong', 'zstd SSE decompresses to ordered delta text');
    assert.strictEqual(resp.headers.get('content-encoding'), null);
  } finally {
    await teardown(proxy, upstream);
  }
});
