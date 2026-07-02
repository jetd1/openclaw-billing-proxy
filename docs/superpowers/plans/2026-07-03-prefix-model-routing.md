# Prefix Model Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a single proxy instance forward model-prefixed requests (e.g. `t9s/MODEL_A`) to a configured upstream endpoint with pure pass-through, while non-prefixed models keep the existing Anthropic disguise path.

**Architecture:** A new `routes` config table + a `resolveRoute` dispatcher that inspects the top-level `model` field. On a prefix hit, a self-contained pass-through branch strips the prefix, swaps auth, recomputes `content-length`, and pipes the request/response verbatim (no disguise, no ultra rewrite, no reverse-map). The entire existing Anthropic code path is untouched.

**Tech Stack:** Node.js 18+ standard library only (`http`, `https`, `crypto`, `fs`, `path`, `os`). Zero npm dependencies. Tests use the built-in `node:test` runner + `node:assert` (no test framework install needed).

## Global Constraints

- **Zero npm dependencies.** Do not add a `package.json` or any `require()` of an npm package. Tests use `node --test` (built into Node 18+).
- **No `JSON.parse` on request bodies.** All body inspection/rewriting uses string scanning, matching the existing `findTopLevelKey` idiom in `proxy.js`. This preserves body integrity and the file's established style.
- **Single-file project.** All production logic stays in `proxy.js`. Tests live in `tests/`.
- **Pure pass-through on prefix routes.** The prefix path does ONLY: strip prefix from `model`, swap the auth header to the route's token, recompute `content-length`, and pipe. It does NOT run `rewriteUltraModel`, `classifyClientRequest`, `processBody`, `reverseMap`, or inject stainless/CC/anthropic-version headers.
- **Additive only.** When `config.routes` is absent or empty, behavior must be byte-identical to the current `master`/`dev/jet` HEAD. Do not alter the Anthropic path.
- **Config validation is fail-fast at startup.** Invalid `routes` structure exits with a clear `[ERROR] route "<prefix>": <reason>` message, matching the existing credential-missing pattern.
- **Token rotation.** `tokenEnv` tokens are read fresh on each request (env re-read), matching the existing `OAUTH_TOKEN` per-request behavior. An unset `tokenEnv` at startup only warns, does not exit.

---

## File Structure

- **Modify:** `proxy.js` — add `parseBaseUrl`, `resolveRoute`, route validation in `loadConfig`, a prefix-dispatch branch in the request handler, `/health` + startup banner additions.
- **Create:** `tests/test-routing.js` — unit tests for `resolveRoute` + route validation (pure functions, no server).
- **Create:** `tests/test-server.js` — integration tests spawning the real `proxy.js` against local upstream stubs (plain JSON + SSE + path transparency + auth swap).
- **Create:** `tests/helpers/stub-upstream.js` — a tiny `http.createServer` stub that echoes request method/path/headers/body and can emit a fixed SSE stream. Reused across integration tests.

`proxy.js` exports its internals for testing via `module.exports` guarded by `require.main === module` at the bottom (the file already runs `startServer` unconditionally at load — Task 1 refactors that to the `require.main` guard so tests can `require('./proxy.js')` without binding a port).

---

## Task 1: Make proxy.js requireable + add test scaffolding

**Files:**
- Modify: `proxy.js` (bottom of file, the `// ─── Main` section at ~line 1843)
- Create: `tests/helpers/stub-upstream.js`
- Create: `tests/test-routing.js` (smoke test only, expanded in later tasks)

**Interfaces:**
- Produces: `module.exports = { resolveRoute }` from `proxy.js` (resolveRoute is a stub returning `null` for now; later tasks implement it). Guards server startup behind `if (require.main === module)`.

- [ ] **Step 1: Refactor the entry point so proxy.js is requireable**

At the bottom of `proxy.js`, replace:

```js
// ─── Main ───────────────────────────────────────────────────────────────────
const config = loadConfig();
startServer(config);
```

with:

```js
// ─── Main ───────────────────────────────────────────────────────────────────
// Guard server startup so tests can require('./proxy.js') for the pure helpers
// without binding a port. `loadConfig` is side-effectful (it can process.exit
// on missing credentials), so it only runs when started as the main module.
function main() {
  const config = loadConfig();
  startServer(config);
}

// Stub: implemented in Task 3. Exported now so the test harness can wire up.
function resolveRoute(_bodyStr, _config) {
  return null;
}

module.exports = { resolveRoute, main, loadConfig, startServer };

if (require.main === module) {
  main();
}
```

- [ ] **Step 2: Create the stub upstream helper**

Create `tests/helpers/stub-upstream.js`:

```js
const http = require('http');

// A minimal upstream stub for integration tests. Captures the inbound request
// (method, url, headers, body) and responds with a configurable payload.
//
// opts:
//   status   - HTTP status (default 200)
//   headers  - response headers object (default { 'content-type': 'application/json' })
//   body     - a string to send as the response body (mutually exclusive with sse)
//   sse      - an array of raw SSE chunk strings to write in sequence, then end
//
// Returns { server, requests } where requests is an array of captured requests:
//   { method, url, headers, body }
function createStubUpstream(opts = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8')
      });
      const status = opts.status || 200;
      const headers = opts.headers || { 'content-type': 'application/json' };
      res.writeHead(status, headers);
      if (opts.sse) {
        for (const chunk of opts.sse) res.write(chunk);
        res.end();
      } else {
        res.end(opts.body || '');
      }
    });
  });
  return { server, requests };
}

module.exports = { createStubUpstream };
```

- [ ] **Step 3: Write a smoke test proving proxy.js is requireable and exports resolveRoute**

Create `tests/test-routing.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { resolveRoute } = require('../proxy.js');

test('proxy.js is requireable and exports a resolveRoute function', () => {
  assert.strictEqual(typeof resolveRoute, 'function');
  assert.strictEqual(resolveRoute('{}', { routes: {} }), null);
});
```

- [ ] **Step 4: Run the smoke test**

Run: `node --test tests/test-routing.js`
Expected: PASS (1 test, 0 failures). Confirms `proxy.js` can be required without binding a port and `resolveRoute` is exported.

- [ ] **Step 5: Verify the server still starts normally (manual regression)**

Run: `timeout 3 node proxy.js` (it will exit on timeout; that's fine — we just want to see the startup banner with no require errors).
Expected: the `OpenClaw Billing Proxy v2.2.3` banner prints and it listens on port 18801 (then the timeout kills it). No `Error: Cannot find module` or require-time exceptions.

- [ ] **Step 6: Commit**

```bash
git add proxy.js tests/helpers/stub-upstream.js tests/test-routing.js
git commit -m "test: make proxy.js requireable; add test scaffolding for routing"
```

---

## Task 2: Parse and validate the routes config in loadConfig

**Files:**
- Modify: `proxy.js` — `loadConfig` function (add route parsing/validation), and the returned config object (add `routes`).

**Interfaces:**
- Consumes: `config.routes` from `config.json` (user-provided object).
- Produces: `config.routes` — a `Map` of `prefix -> normalizedRoute` where `normalizedRoute = { scheme, host, port, basePath, token, tokenEnv, authHeader }`. `scheme` is `'http'` or `'https'`; `port` is an integer; `basePath` is a string (possibly `''`); `authHeader` defaults to `'authorization'`; exactly one of `token`/`tokenEnv` is set. The returned config object gains `routes` (the Map).

- [ ] **Step 1: Write the failing tests for route parsing**

Append to `tests/test-routing.js` (keep the existing smoke test):

```js
const { loadConfig } = require('../proxy.js');

// loadConfig reads process.argv and config.json from cwd; for unit tests we
// exercise the pure validator by calling it with a controlled cwd. We instead
// test the validation logic indirectly through a thin helper exported below.
const { validateRoutes } = require('../proxy.js');

test('validateRoutes: empty/absent routes yields empty Map', () => {
  assert.strictEqual(validateRoutes(undefined).size, 0);
  assert.strictEqual(validateRoutes({}).size, 0);
});

test('validateRoutes: valid route with tokenEnv', () => {
  const routes = validateRoutes({
    t9s: { baseUrl: 'http://t9s-router.internal:8000', tokenEnv: 'T9S_TOKEN' }
  });
  const r = routes.get('t9s');
  assert.ok(r, 't9s route present');
  assert.strictEqual(r.scheme, 'http');
  assert.strictEqual(r.host, 't9s-router.internal');
  assert.strictEqual(r.port, 8000);
  assert.strictEqual(r.basePath, '');
  assert.strictEqual(r.token, undefined);
  assert.strictEqual(r.tokenEnv, 'T9S_TOKEN');
  assert.strictEqual(r.authHeader, 'authorization');
});

test('validateRoutes: https with basePath and x-api-key authHeader', () => {
  const routes = validateRoutes({
    endpoint_a: {
      baseUrl: 'https://api.example.com/v1',
      token: 'sk-static',
      authHeader: 'x-api-key'
    }
  });
  const r = routes.get('endpoint_a');
  assert.strictEqual(r.scheme, 'https');
  assert.strictEqual(r.host, 'api.example.com');
  assert.strictEqual(r.port, 443);
  assert.strictEqual(r.basePath, '/v1');
  assert.strictEqual(r.token, 'sk-static');
  assert.strictEqual(r.authHeader, 'x-api-key');
});

test('validateRoutes: default port for http when omitted', () => {
  const routes = validateRoutes({ a: { baseUrl: 'http://h', token: 't' } });
  assert.strictEqual(routes.get('a').port, 80);
});

test('validateRoutes: default port for https when omitted', () => {
  const routes = validateRoutes({ a: { baseUrl: 'https://h', token: 't' } });
  assert.strictEqual(routes.get('a').port, 443);
});

test('validateRoutes: rejects route missing baseUrl', () => {
  assert.throws(
    () => validateRoutes({ bad: { token: 't' } }),
    /bad.*baseUrl/i
  );
});

test('validateRoutes: rejects route with neither token nor tokenEnv', () => {
  assert.throws(
    () => validateRoutes({ bad: { baseUrl: 'http://h' } }),
    /bad.*(token|auth)/i
  );
});

test('validateRoutes: rejects route with both token and tokenEnv', () => {
  assert.throws(
    () => validateRoutes({ bad: { baseUrl: 'http://h', token: 't', tokenEnv: 'X' } }),
    /bad.*(token|one)/i
  );
});

test('validateRoutes: rejects unparseable baseUrl (no scheme)', () => {
  assert.throws(
    () => validateRoutes({ bad: { baseUrl: 't9s-router:8000', token: 't' } }),
    /bad.*baseUrl/i
  );
});

test('validateRoutes: rejects unsupported scheme', () => {
  assert.throws(
    () => validateRoutes({ bad: { baseUrl: 'ftp://h', token: 't' } }),
    /bad.*(scheme|baseUrl)/i
  );
});

test('validateRoutes: rejects routes that is not an object', () => {
  assert.throws(() => validateRoutes('nope'), /routes.*object/i);
  assert.throws(() => validateRoutes([]), /routes.*object/i);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-routing.js`
Expected: FAIL — `validateRoutes is not a function` (not yet exported from `proxy.js`).

- [ ] **Step 3: Implement parseBaseUrl and validateRoutes in proxy.js**

Add these near the top of `proxy.js`, after the `// ─── Defaults` block (after line ~61, after `REQUIRED_BETAS` / `CC_TOOL_STUBS`):

```js
// ─── Route Config (prefix model routing) ────────────────────────────────────
// Parse a baseUrl like "https://api.example.com:8443/v1" into
// { scheme, host, port, basePath }. Throws on anything we can't use.
function parseBaseUrl(baseUrl, prefixName) {
  const m = /^(https?):\/\/([^/:?#]+)(?::(\d+))?(\/[^?#]*)?/i.exec(String(baseUrl || ''));
  if (!m) {
    throw new Error(`route "${prefixName}": baseUrl "${baseUrl}" is not a valid http(s) URL`);
  }
  const scheme = m[1].toLowerCase();
  const host = m[2];
  const port = m[3] ? parseInt(m[3], 10) : (scheme === 'https' ? 443 : 80);
  const basePath = m[4] || '';
  return { scheme, host, port, basePath };
}

// Validate the user's `routes` object into a Map<prefix, normalizedRoute>.
// Throws (with the offending prefix in the message) on any structural error.
// A route with tokenEnv set but the env var currently empty does NOT throw —
// the token is read per-request (rotation-friendly), so we only warn at startup.
function validateRoutes(routes) {
  const out = new Map();
  if (routes == null) return out;
  if (typeof routes !== 'object' || Array.isArray(routes)) {
    throw new Error('routes must be a JSON object of prefix -> route');
  }
  for (const [prefix, route] of Object.entries(routes)) {
    if (!route || typeof route !== 'object') {
      throw new Error(`route "${prefix}": must be an object`);
    }
    if (!route.baseUrl) {
      throw new Error(`route "${prefix}": missing required field "baseUrl"`);
    }
    const { scheme, host, port, basePath } = parseBaseUrl(route.baseUrl, prefix);

    const hasToken = typeof route.token === 'string' && route.token.length > 0;
    const hasTokenEnv = typeof route.tokenEnv === 'string' && route.tokenEnv.length > 0;
    if (hasToken && hasTokenEnv) {
      throw new Error(`route "${prefix}": set either "token" or "tokenEnv", not both`);
    }
    if (!hasToken && !hasTokenEnv) {
      throw new Error(`route "${prefix}": missing auth — set "token" or "tokenEnv"`);
    }

    const authHeader = typeof route.authHeader === 'string' && route.authHeader.length > 0
      ? route.authHeader.toLowerCase()
      : 'authorization';

    if (authHeader !== 'authorization' && !hasToken && !hasTokenEnv) {
      // unreachable given the check above, kept for clarity
      throw new Error(`route "${prefix}": authHeader set but no token source`);
    }

    out.set(prefix, {
      scheme,
      host,
      port,
      basePath,
      token: hasToken ? route.token : undefined,
      tokenEnv: hasTokenEnv ? route.tokenEnv : undefined,
      authHeader
    });
  }
  return out;
}
```

- [ ] **Step 4: Wire validateRoutes into loadConfig and export it**

In `loadConfig`, after the `mergePatterns`/`useDefaults` block (around line ~468, just before the final `return { ... }`), add:

```js
  // Prefix model routing (additive; absent/empty routes = no-op, current behavior).
  const routeMap = validateRoutes(config.routes);
  if (routeMap.size > 0) {
    for (const [prefix, route] of routeMap) {
      if (route.tokenEnv && !process.env[route.tokenEnv]) {
        console.log(`[WARN] route "${prefix}": tokenEnv "${route.tokenEnv}" is unset at startup (will be read per-request)`);
      }
    }
  }
```

Then add `routes: routeMap,` to the returned config object (the `return { port, keysFile, credsPath, replacements, ... }` block).

Finally, update the `module.exports` at the bottom of the file to include `validateRoutes` and `parseBaseUrl`:

```js
module.exports = { resolveRoute, main, loadConfig, startServer, validateRoutes, parseBaseUrl };
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test tests/test-routing.js`
Expected: PASS (all tests, 0 failures).

- [ ] **Step 6: Commit**

```bash
git add proxy.js tests/test-routing.js
git commit -m "feat: parse and validate prefix route config in loadConfig"
```

---

## Task 3: Implement resolveRoute (prefix detection on the model field)

**Files:**
- Modify: `proxy.js` — replace the `resolveRoute` stub (bottom of file) with the real implementation.

**Interfaces:**
- Consumes: `config.routes` (the `Map` from Task 2).
- Produces: `resolveRoute(bodyStr, config)` → `{ route, prefix, outModel }` or `null`. Uses string scanning (no JSON.parse) to read the top-level `model` value. `route` is the normalized route object from the Map.

- [ ] **Step 1: Write the failing tests for resolveRoute**

Append to `tests/test-routing.js`:

```js
const ROUTES = new Map([
  ['t9s', { scheme: 'http', host: 'h', port: 8000, basePath: '', token: 'tok', authHeader: 'authorization' }],
  ['endpoint_a', { scheme: 'https', host: 'h', port: 443, basePath: '/v1', token: 'tok', authHeader: 'x-api-key' }]
]);

function bodyWithModel(model) {
  // A minimal but realistic Messages API body. model is the top-level field.
  return JSON.stringify({ model, max_tokens: 100, messages: [{ role: 'user', content: 'hi' }] });
}

test('resolveRoute: prefixed model hits the route', () => {
  const r = resolveRoute(bodyWithModel('t9s/MODEL_A'), { routes: ROUTES });
  assert.ok(r, 'should resolve');
  assert.strictEqual(r.prefix, 't9s');
  assert.strictEqual(r.outModel, 'MODEL_A');
  assert.strictEqual(r.route, ROUTES.get('t9s'));
});

test('resolveRoute: prefix with rest containing slashes keeps full rest', () => {
  const r = resolveRoute(bodyWithModel('t9s/org/model-a'), { routes: ROUTES });
  assert.strictEqual(r.outModel, 'org/model-a');
});

test('resolveRoute: model without slash returns null', () => {
  assert.strictEqual(resolveRoute(bodyWithModel('claude-opus-4-8'), { routes: ROUTES }), null);
});

test('resolveRoute: prefix not in routes returns null', () => {
  assert.strictEqual(resolveRoute(bodyWithModel('unknown/foo'), { routes: ROUTES }), null);
});

test('resolveRoute: empty config.routes returns null', () => {
  assert.strictEqual(resolveRoute(bodyWithModel('t9s/MODEL_A'), { routes: new Map() }), null);
});

test('resolveRoute: trailing slash prefix (t9s/) resolves with empty outModel', () => {
  const r = resolveRoute(bodyWithModel('t9s/'), { routes: ROUTES });
  assert.strictEqual(r.prefix, 't9s');
  assert.strictEqual(r.outModel, '');
});

test('resolveRoute: model field absent returns null', () => {
  assert.strictEqual(resolveRoute('{"max_tokens":1,"messages":[]}', { routes: ROUTES }), null);
});

test('resolveRoute: does not match model name nested in messages history', () => {
  // A model-like string inside message content must NOT trigger routing.
  const body = JSON.stringify({
    model: 'claude-opus-4-8',
    messages: [{ role: 'user', content: 'please use t9s/MODEL_A for this' }]
  });
  assert.strictEqual(resolveRoute(body, { routes: ROUTES }), null);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-routing.js`
Expected: FAIL — the `prefixed model hits the route` test fails because the stub returns `null`.

- [ ] **Step 3: Implement resolveRoute**

Replace the `resolveRoute` stub at the bottom of `proxy.js` with the real implementation. Place the function above `module.exports`:

```js
// ─── Route Resolution ───────────────────────────────────────────────────────
// Inspect the top-level `model` field via string scanning (no JSON.parse) and,
// if it is "<prefix>/<rest>" where <prefix> is a configured route, return the
// matching route + the stripped model name. Otherwise null (fall through to the
// Anthropic default path). Scans ONLY the top-level model key so model-like
// strings nested in message history never trigger routing.
function resolveRoute(bodyStr, config) {
  const routes = config && config.routes;
  if (!routes || (routes.size !== undefined ? routes.size === 0 : Object.keys(routes).length === 0)) {
    return null;
  }
  const modelKeyIdx = findTopLevelKey(bodyStr, 'model');
  if (modelKeyIdx === -1) return null;
  let colonIdx = modelKeyIdx + '"model"'.length;
  while (colonIdx < bodyStr.length && ' \t\n\r'.includes(bodyStr[colonIdx])) colonIdx++;
  if (bodyStr[colonIdx] !== ':') return null;
  let valStart = colonIdx + 1;
  while (valStart < bodyStr.length && ' \t\n\r'.includes(bodyStr[valStart])) valStart++;
  if (bodyStr[valStart] !== '"') return null;
  let valEnd = valStart + 1;
  while (valEnd < bodyStr.length) {
    if (bodyStr[valEnd] === '\\') { valEnd += 2; continue; }
    if (bodyStr[valEnd] === '"') break;
    valEnd++;
  }
  const modelVal = bodyStr.slice(valStart + 1, valEnd);
  const slashIdx = modelVal.indexOf('/');
  if (slashIdx === -1) return null;
  const prefix = modelVal.slice(0, slashIdx);
  const outModel = modelVal.slice(slashIdx + 1);
  const route = routes instanceof Map ? routes.get(prefix) : routes[prefix];
  if (!route) return null;
  return { route, prefix, outModel, modelStart: valStart + 1, modelEnd: valEnd };
}
```

Note: `modelStart`/`modelEnd` are returned so the dispatcher (Task 4) can do one targeted slice to rewrite the model value without re-scanning.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-routing.js`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add proxy.js tests/test-routing.js
git commit -m "feat: implement resolveRoute prefix detection on the model field"
```

---

## Task 4: Implement the prefix pass-through dispatch branch

**Files:**
- Modify: `proxy.js` — `startServer` request handler (the `req.on('end', ...)` block, ~lines 1503-1530). Add the prefix-dispatch branch right after `clientProfile = classifyClientRequest(...)` is computed but BEFORE `rewriteUltraModel`/`processBody`.

**Interfaces:**
- Consumes: `resolveRoute` (Task 3), normalized route objects (Task 2), the existing `req`/`res`/`bodyStr` in the handler.
- Produces: a complete request→response pass-through for prefixed models. No return value used by callers (it writes to `res` and ends the response).

- [ ] **Step 1: Write the failing integration tests**

Create `tests/test-server.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');
const { createStubUpstream } = require('./helpers/stub-upstream');

// Spawn the real proxy.js as a subprocess with a temp config + keys file, so
// we exercise the actual server (not just required functions). Returns a handle
// with a .kill() and a base URL.
function startProxy(config, env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-test-'));
  // Write a keys file with a known SHA256 so the client can auth.
  const PROXY_KEY = 'test-proxy-key';
  const keyHash = require('crypto').createHash('sha256').update(PROXY_KEY).digest('hex');
  fs.writeFileSync(path.join(dir, 'keys.json'), JSON.stringify([{ name: 'test', key_hash: keyHash }]));
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config));
  const child = require('child_process').spawn(process.execPath, ['proxy.js'], {
    cwd: dir,
    env: { ...process.env, KEYS_FILE: path.join(dir, 'keys.json'), PROXY_PORT: '0', ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let port = null;
  let ready = false;
  child.stdout.on('data', (d) => {
    const s = d.toString();
    const m = s.match(/listening on .*?:(\d+)/) || s.match(/port[: ]+(\d+)/i);
    // The banner prints the configured port; we read it from /health below.
    if (!ready) ready = s.includes('Ready') || s.includes('listening');
  });
  // Poll /health once the process is up to learn the real ephemeral port.
  // We can't read port 0 easily from stdout, so instead bind a fixed port.
  return { dir, child, PROXY_KEY, configPath: path.join(dir, 'config.json') };
}

// Simpler harness: fixed port, wait for /health.
function startProxyOnPort(config, port, env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obp-test-'));
  const PROXY_KEY = 'test-proxy-key';
  const keyHash = require('crypto').createHash('sha256').update(PROXY_KEY).digest('hex');
  fs.writeFileSync(path.join(dir, 'keys.json'), JSON.stringify([{ name: 'test', key_hash: keyHash }]));
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config));
  const child = require('child_process').spawn(process.execPath, ['proxy.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, KEYS_FILE: path.join(dir, 'keys.json'), PROXY_PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const base = `http://127.0.0.1:${port}`;
  return { dir, child, PROXY_KEY, base };
}

async function waitForHealth(base, ms = 3000) {
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-server.js`
Expected: FAIL — the prefix route tests fail because prefixed models currently fall through to the Anthropic path (which has no credentials in the test env → 500, and the upstream stub is never contacted).

- [ ] **Step 3: Implement the prefix dispatch branch in the request handler**

In `startServer`'s `req.on('end', () => { ... })` block, find this section (around line 1507-1517):

```js
      let body = Buffer.concat(chunks);
      let bodyStr = body.toString('utf8');
      const originalSize = bodyStr.length;
      const clientProfile = classifyClientRequest(req, bodyStr);

      let oauth;
      try { oauth = getToken(config.credsPath); } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        return;
      }
```

Insert the prefix-dispatch branch **immediately after** `const clientProfile = classifyClientRequest(req, bodyStr);` and **before** the `let oauth;` block:

```js
      // ── Prefix model routing: pure pass-through to a configured endpoint ──
      // Checked BEFORE ultra/classify/disguise so a configured prefix is an
      // explicit override. Strips the prefix from `model`, swaps auth to the
      // route's token, recomputes content-length, and pipes verbatim. No
      // disguise, no ultra, no reverse-map, no anthropic/stainless/CC headers.
      const routeHit = resolveRoute(bodyStr, config);
      if (routeHit) {
        try {
          // Rewrite the model value: "prefix/rest" -> "rest" (one targeted slice).
          const newBodyStr = bodyStr.slice(0, routeHit.modelStart)
            + routeHit.outModel
            + bodyStr.slice(routeHit.modelEnd);
          const newBody = Buffer.from(newBodyStr, 'utf8');

          // Resolve the token now (per-request so tokenEnv rotation works).
          let token;
          if (routeHit.route.tokenEnv) {
            token = process.env[routeHit.route.tokenEnv];
            if (!token) throw new Error(`route "${routeHit.prefix}": tokenEnv "${routeHit.route.tokenEnv}" is unset`);
          } else {
            token = routeHit.route.token;
          }

          // Build outbound headers: copy client headers, strip the universal set.
          const outHeaders = {};
          for (const [key, value] of Object.entries(req.headers)) {
            const lk = key.toLowerCase();
            if (lk === 'host' || lk === 'connection' || lk === 'authorization' ||
                lk === 'x-api-key' || lk === 'content-length' || lk === 'x-session-affinity') continue;
            outHeaders[key] = value;
          }
          // Inject route auth.
          if (routeHit.route.authHeader === 'authorization') {
            outHeaders['authorization'] = `Bearer ${token}`;
          } else {
            outHeaders[routeHit.route.authHeader] = token;
          }
          outHeaders['content-length'] = newBody.length;

          const ts = new Date().toISOString().substring(11, 19);
          console.log(`[${ts}] #${reqNum} ${req.method} ${req.url} ROUTE ${routeHit.prefix} -> ${routeHit.route.scheme}://${routeHit.route.host}:${routeHit.route.port}${routeHit.route.basePath} (model=${routeHit.outModel || '<empty>'})`);

          const reqLib = routeHit.route.scheme === 'https' ? https : http;
          const upstreamPath = routeHit.route.basePath + req.url;
          const upstream = reqLib.request({
            hostname: routeHit.route.host,
            port: routeHit.route.port,
            path: upstreamPath,
            method: req.method,
            headers: outHeaders
          }, (upRes) => {
            // Pure pipe: status + headers + body, SSE and JSON alike.
            res.writeHead(upRes.statusCode, upRes.headers);
            upRes.pipe(res);
          });
          upstream.on('error', (e) => {
            console.error(`[${ts}] #${reqNum} ROUTE-ERR ${routeHit.prefix}: ${e.message}`);
            if (!res.headersSent) {
              res.writeHead(502, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
            } else {
              res.end();
            }
          });
          upstream.write(newBody);
          upstream.end();
        } catch (e) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { message: e.message } }));
        }
        return; // prefix path fully handled; do NOT fall through to Anthropic logic
      }
```

- [ ] **Step 4: Run the integration tests to verify they pass**

Run: `node --test tests/test-server.js`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Run the full test suite to confirm no regression**

Run: `node --test tests/`
Expected: PASS (all tests in test-routing.js + test-server.js).

- [ ] **Step 6: Commit**

```bash
git add proxy.js tests/test-server.js
git commit -m "feat: prefix model routing pass-through dispatch branch"
```

---

## Task 5: Surface routes in /health and the startup banner

**Files:**
- Modify: `proxy.js` — `/health` handler (~line 1462) and the startup banner (~lines 1817-1833).

**Interfaces:**
- Consumes: `config.routes` (Map from Task 2).
- Produces: `/health` JSON gains `routes: ["t9s", ...]`; the startup banner gains a `Routes:` line when routes are configured.

- [ ] **Step 1: Write the failing test for the /health routes field**

Append to `tests/test-server.js`:

```js
test('/health reports configured routes', async () => {
  const proxyPort = 18816;
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
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/test-server.js`
Expected: FAIL — `json.routes` is undefined.

- [ ] **Step 3: Add routes to the /health response**

In the `/health` handler (the `res.end(JSON.stringify({ status, proxy, version, ... layers: {...} }))` block), add a `routes` field. Insert right after the `layers` object closes:

```js
          routes: config.routes instanceof Map ? [...config.routes.keys()] : [],
```

So the object becomes (showing context):

```js
        res.end(JSON.stringify({
          status: expiresIn > 0 ? 'ok' : 'token_expired',
          proxy: 'openclaw-billing-proxy',
          version: VERSION,
          requestsServed: requestCount,
          uptime: Math.floor((Date.now() - startedAt) / 1000) + 's',
          tokenExpiresInHours: isFinite(expiresIn) ? expiresIn.toFixed(1) : 'n/a',
          subscriptionType: oauth.subscriptionType,
          layers: {
            stringReplacements: config.replacements.length,
            toolNameRenames: config.toolRenames.length,
            propertyRenames: config.propRenames.length,
            ccToolStubs: config.injectCCStubs ? CC_TOOL_STUBS.length : 0,
            systemStripEnabled: config.stripSystemConfig,
            descriptionStripEnabled: config.stripToolDescriptions
          },
          routes: config.routes instanceof Map ? [...config.routes.keys()] : []
        }));
```

- [ ] **Step 4: Add a Routes line to the startup banner**

In `server.listen(...)`'s callback, after the `console.log('  Credentials:       ' + config.credsPath);` line and before the `console.log('\n  Ready. ...')` line, add:

```js
      if (config.routes instanceof Map && config.routes.size > 0) {
        console.log(`  Routes:`);
        for (const [prefix, route] of config.routes) {
          const auth = route.authHeader === 'authorization' ? 'Bearer' : route.authHeader;
          console.log(`    ${prefix} -> ${route.scheme}://${route.host}:${route.port}${route.basePath} (${auth})`);
        }
      }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test tests/test-server.js`
Expected: PASS.

- [ ] **Step 6: Run the full suite**

Run: `node --test tests/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add proxy.js tests/test-server.js
git commit -m "feat: surface configured routes in /health and startup banner"
```

---

## Task 6: Documentation + final verification

**Files:**
- Modify: `README.md` — add a "Prefix Model Routing" section after "Ultra Model Aliases".
- Modify: `config.example.json` — add a commented `routes` example.

- [ ] **Step 1: Add the README section**

In `README.md`, after the "### Ultra Model Aliases" section (which ends around line 239 with "The rewrite scans only the top-level `model` key..."), insert a new section:

```markdown
### Prefix Model Routing

The proxy can forward requests to additional upstream endpoints based on a
**model-name prefix**. A request whose `model` is `<prefix>/<rest>` is forwarded
to the configured `<prefix>` endpoint with the model rewritten to `<rest>`; the
rest of the request and the full response (SSE or plain JSON) pass through
byte-for-byte. No payload translation, no disguise, no reverse mapping.

Add a `routes` object to `config.json`. Each key is a prefix; each value names
an endpoint:

```json
{
  "routes": {
    "t9s": {
      "baseUrl": "http://t9s-router.internal:8000",
      "tokenEnv": "T9S_TOKEN"
    },
    "endpoint_a": {
      "baseUrl": "https://api.example.com/v1",
      "token": "sk-static-literal",
      "authHeader": "x-api-key"
    }
  }
}
```

| field        | required | default        | meaning |
|--------------|----------|----------------|---------|
| `baseUrl`    | yes      | —              | scheme+host(+port)(+basePath) of the upstream |
| `token`      | one of   | —              | literal token |
| `tokenEnv`   | one of   | —              | env var name holding the token (read per-request, supports rotation) |
| `authHeader` | no       | `authorization`| header for the token. `authorization` sends `Bearer <token>`; any other name sends the bare token |

Routing resolution:

- `model` with no `/` (e.g. `claude-opus-4-8`, or native Claude Code traffic) →
  Anthropic default path (existing disguise / pass-through), unchanged.
- `model` with a `/` whose prefix matches a route → prefix pass-through path.
- `model` with a `/` whose prefix is **not** a route → Anthropic default path.
- Prefix resolution happens **before** Claude Code classification, so a Claude
  Code client can use `t9s/model_a` to reach the `t9s` endpoint. The client's
  Anthropic-specific headers and body blocks pass through verbatim; only the
  auth header is swapped to the route's token (the Claude Code OAuth token never
  reaches the alternative endpoint).

The proxy's `KEYS_FILE` client authentication applies to all routes, including
prefix routes. `curl http://127.0.0.1:18801/health` lists configured routes.
```

- [ ] **Step 2: Add a commented routes example to config.example.json**

Append to `config.example.json` (before the final closing `}`), keeping valid JSON — since the existing file uses `_comment_*` keys, add a `_comment_routes` key plus a commented-out `routes` is not possible in JSON. Instead, document via a `_comment_routes` string and leave `routes` out (matches the file's existing "defaults shown as comments" approach). Add:

```json
  ,
  "_comment_routes": "Prefix model routing (optional). Add a 'routes' object to forward '<prefix>/<model>' requests to a custom endpoint with pure pass-through. Example: {\"routes\":{\"t9s\":{\"baseUrl\":\"http://t9s-router:8000\",\"tokenEnv\":\"T9S_TOKEN\"},\"endpoint_a\":{\"baseUrl\":\"https://api.example.com/v1\",\"token\":\"sk-...\",\"authHeader\":\"x-api-key\"}}}. Absent/empty = no change to existing behavior."
```

- [ ] **Step 3: Verify config.example.json is still valid JSON**

Run: `node -e "JSON.parse(require('fs').readFileSync('config.example.json','utf8')); console.log('valid')"`
Expected: prints `valid`.

- [ ] **Step 4: Run the full test suite one final time**

Run: `node --test tests/`
Expected: PASS (all tests).

- [ ] **Step 5: Manual smoke test of the server banner**

Run: `timeout 3 node proxy.js`
Expected: the banner prints, and if no `config.json` with routes is present, no `Routes:` line appears (confirming the additive/zero-config behavior). No errors.

- [ ] **Step 6: Commit**

```bash
git add README.md config.example.json
git commit -m "docs: document prefix model routing"
```

---

## Self-Review Notes

**Spec coverage:**
- Config schema (`routes`, `baseUrl`/`token`/`tokenEnv`/`authHeader`, defaults) → Task 2 ✓
- `resolveRoute` (string scan, no JSON.parse, edge cases) → Task 3 ✓
- Prefix pass-through path (strip prefix, swap auth, recompute content-length, pipe, no disguise/ultra/reverse-map) → Task 4 ✓
- Backward compat (absent/empty routes = byte-identical) → Task 4 unknown-prefix test + Task 6 smoke test ✓
- `/health` + startup banner → Task 5 ✓
- Error handling (502 on dispatch error, 502 on empty tokenEnv, verbatim upstream non-2xx via pipe) → Task 4 ✓
- Documentation → Task 6 ✓

**Type consistency:** `resolveRoute` returns `{ route, prefix, outModel, modelStart, modelEnd }` in Task 3, and Task 4 consumes exactly those fields. `validateRoutes` returns `Map<prefix, { scheme, host, port, basePath, token, tokenEnv, authHeader }>`; Tasks 4/5 consume those exact fields. `config.routes` is the Map in all tasks. Consistent.

**Placeholders:** none — every step has concrete code or an exact command.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-03-prefix-model-routing.md`.
