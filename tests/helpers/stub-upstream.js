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
