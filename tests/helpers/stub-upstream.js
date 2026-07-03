const http = require('http');
const zlib = require('zlib');

// A minimal upstream stub for integration tests. Captures the inbound request
// (method, url, headers, body) and responds with a configurable payload.
//
// opts:
//   status   - HTTP status (default 200)
//   headers  - response headers object (default { 'content-type': 'application/json' })
//   body     - a string to send as the response body (mutually exclusive with sse)
//   sse      - an array of raw SSE chunk strings to write in sequence, then end
//   encoding - 'gzip' | 'deflate' | 'br' | 'zstd': compress each written payload
//              chunk and set content-encoding. For SSE, each chunk string is
//              compressed separately (producing concatenated gzip/brotli members
//              in a single valid stream — ideal for testing chunk-boundary
//              reassembly through the proxy's pending buffer).
//   raw      - a Buffer sent verbatim (overrides body/sse); used to feed the
//              proxy a pre-built compressed blob exactly as given.
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
      const headers = { ...(opts.headers || { 'content-type': 'application/json' }) };
      if (opts.encoding) headers['content-encoding'] = opts.encoding;
      res.writeHead(status, headers);
      if (opts.raw !== undefined) { res.end(opts.raw); return; }
      const enc = opts.encoding;
      if (opts.sse) {
        for (const chunk of opts.sse) {
          const b = Buffer.from(chunk, 'utf8');
          res.write(enc ? compressOne(b, enc) : b);
        }
        res.end();
      } else {
        const b = Buffer.from(opts.body || '', 'utf8');
        res.end(enc ? compressOne(b, enc) : b);
      }
    });
  });
  return { server, requests };
}

function compressOne(buf, enc) {
  if (enc === 'gzip') return zlib.gzipSync(buf);
  if (enc === 'deflate') return zlib.deflateSync(buf);
  if (enc === 'br') return zlib.brotliCompressSync(buf);
  if (enc === 'zstd') return zlib.zstdCompressSync(buf);
  return buf;
}

module.exports = { createStubUpstream };
