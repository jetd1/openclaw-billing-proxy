const test = require('node:test');
const assert = require('node:assert');
const { resolveRoute } = require('../proxy.js');

test('proxy.js is requireable and exports a resolveRoute function', () => {
  assert.strictEqual(typeof resolveRoute, 'function');
  assert.strictEqual(resolveRoute('{}', { routes: {} }), null);
});
