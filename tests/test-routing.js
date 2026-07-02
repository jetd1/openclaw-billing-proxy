const test = require('node:test');
const assert = require('node:assert');
const { resolveRoute } = require('../proxy.js');

test('proxy.js is requireable and exports a resolveRoute function', () => {
  assert.strictEqual(typeof resolveRoute, 'function');
  assert.strictEqual(resolveRoute('{}', { routes: {} }), null);
});

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
