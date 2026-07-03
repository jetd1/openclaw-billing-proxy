const test = require('node:test');
const assert = require('node:assert');
const zlib = require('zlib');
const { decompressionMode, createDecompressor, decompressBuffer } = require('../proxy.js');

const SAMPLE = Buffer.from('event: message_start\ndata: {"type":"message_start"}\n\nevent: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}\n\n', 'utf8');

// ── decompressionMode ───────────────────────────────────────────────────────

test('decompressionMode: absent / empty / identity → identity', () => {
  assert.strictEqual(decompressionMode(undefined), 'identity');
  assert.strictEqual(decompressionMode(''), 'identity');
  assert.strictEqual(decompressionMode('identity'), 'identity');
  assert.strictEqual(decompressionMode('IDENTITY'), 'identity');
});

test('decompressionMode: gzip/deflate/br recognized', () => {
  assert.strictEqual(decompressionMode('gzip'), 'gzip');
  assert.strictEqual(decompressionMode('GZIP'), 'gzip');
  assert.strictEqual(decompressionMode('deflate'), 'deflate');
  assert.strictEqual(decompressionMode('br'), 'br');
});

test('decompressionMode: zstd only when the runtime supports it', () => {
  const expected = typeof zlib.createZstdDecompress === 'function' ? 'zstd' : 'unsupported';
  assert.strictEqual(decompressionMode('zstd'), expected);
});

test('decompressionMode: unknown encoding → unsupported', () => {
  assert.strictEqual(decompressionMode('snappy'), 'unsupported');
  assert.strictEqual(decompressionMode('x-custom'), 'unsupported');
});

test('decompressionMode: chained encodings → unsupported (no comma split)', () => {
  assert.strictEqual(decompressionMode('gzip, deflate'), 'unsupported');
});

// ── decompressBuffer round-trips ────────────────────────────────────────────

test('decompressBuffer: identity is a no-op', () => {
  assert.strictEqual(decompressBuffer(SAMPLE, 'identity'), SAMPLE);
});

test('decompressBuffer: gzip round-trip', () => {
  const compressed = zlib.gzipSync(SAMPLE);
  assert.deepStrictEqual(decompressBuffer(compressed, 'gzip'), SAMPLE);
});

test('decompressBuffer: brotli round-trip', () => {
  const compressed = zlib.brotliCompressSync(SAMPLE);
  assert.deepStrictEqual(decompressBuffer(compressed, 'br'), SAMPLE);
});

test('decompressBuffer: deflate (zlib-wrapped) round-trip', () => {
  const compressed = zlib.deflateSync(SAMPLE); // zlib-wrapped (RFC 1950)
  assert.deepStrictEqual(decompressBuffer(compressed, 'deflate'), SAMPLE);
});

test('decompressBuffer: deflate (raw RFC 1951) round-trip via fallback', () => {
  const compressed = zlib.deflateRawSync(SAMPLE); // raw
  assert.deepStrictEqual(decompressBuffer(compressed, 'deflate'), SAMPLE);
});

test('decompressBuffer: zstd round-trip (Node 22+ only)', { skip: typeof zlib.zstdCompressSync !== 'function' }, () => {
  const compressed = zlib.zstdCompressSync(SAMPLE);
  assert.deepStrictEqual(decompressBuffer(compressed, 'zstd'), SAMPLE);
});

test('decompressBuffer: corrupt gzip throws', () => {
  assert.throws(() => decompressBuffer(Buffer.from('not gzip'), 'gzip'));
});

// ── createDecompressor streaming round-trip ─────────────────────────────────

function drainStream(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', c => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

test('createDecompressor: streaming gzip round-trip', async () => {
  const compressed = zlib.gzipSync(SAMPLE);
  const dec = createDecompressor('gzip');
  dec.end(compressed);
  assert.deepStrictEqual(await drainStream(dec), SAMPLE);
});

test('createDecompressor: streaming brotli round-trip', async () => {
  const compressed = zlib.brotliCompressSync(SAMPLE);
  const dec = createDecompressor('br');
  dec.end(compressed);
  assert.deepStrictEqual(await drainStream(dec), SAMPLE);
});

test('createDecompressor: concatenated gzip members decompress to separate chunks', async () => {
  // Two gzip members back-to-back is a valid single gzip stream; createGunzip
  // emits a decompressed chunk per member. This mirrors how the SSE test stub
  // compresses each event separately.
  const part1 = Buffer.from('AAA', 'utf8');
  const part2 = Buffer.from('BBB', 'utf8');
  const compressed = Buffer.concat([zlib.gzipSync(part1), zlib.gzipSync(part2)]);
  const dec = createDecompressor('gzip');
  dec.end(compressed);
  const out = await drainStream(dec);
  assert.deepStrictEqual(out, Buffer.concat([part1, part2]));
});

test('createDecompressor: identity/unsupported returns null', () => {
  assert.strictEqual(createDecompressor('identity'), null);
  assert.strictEqual(createDecompressor('unsupported'), null);
});
