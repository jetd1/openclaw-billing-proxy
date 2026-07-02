# Prefix Model Routing — Design Spec

Date: 2026-07-03
Status: Design approved, pending implementation plan
Branch target: dev/jet → implementation worktree

## Goal

Extend the billing proxy so a single running instance can forward requests to
multiple upstream endpoints based on a **model-name prefix**, in addition to the
existing single-upstream Anthropic behavior.

Request model `t9s/MODEL_A` → forwarded to the configured `t9s` endpoint with
the model rewritten to `MODEL_A`; the rest of the request (and the full
response, SSE or plain) is passed through byte-for-byte. No payload translation,
no disguise, no reverse mapping. "Request whatever endpoint path came in, forward
to the matching endpoint" — path-transparent.

## Confirmed Decisions

1. **Default route = Anthropic retained.** Models with no `/` prefix (e.g.
   `claude-opus-4-8`), and native Claude Code traffic, continue to hit
   `api.anthropic.com` with the existing disguise + Claude Code pass-through
   logic unchanged. Prefix routing is purely additive.
2. **Endpoint auth = Bearer by default, per-route overridable.** Each route
   sends `Authorization: Bearer <token>` by default; a route may set
   `authHeader` (e.g. `x-api-key`) in which case the value is the bare token.
   Token source is `token` (literal) or `tokenEnv` (env var, recommended for
   secrets).
3. **Client auth = unchanged and universal.** `KEYS_FILE` validation applies to
   every route, including prefix routes. The proxy strips client auth headers and
   injects the route's endpoint token upstream — identical trust model to today.

## Non-Goals (YAGNI)

- No Anthropic↔OpenAI / Anthropic↔GLM API translation. Prefix routes are pure
  pass-through.
- No per-route client-auth toggle (decision 3 makes it universal).
- No per-route port listeners (single port, prefix-based dispatch).
- No load balancing, retries, or circuit breaking across endpoints.
- No streaming transformations on prefix routes — not even the existing
  reverse-map / dedup pipeline.
- No change to the Anthropic default path's behavior.

## Architecture

Three request paths, dispatched after the body is read and after the universal
`KEYS_FILE` gate:

```
                        ┌─ resolveRoute(model) ─────────────────────┐
  client ── req ──►  KEYS_FILE gate ──► read body ──►  prefix?      │
                        └─────────────┬─────────────────────────────┘
                                      │
            ┌─────────────────────────┼───────────────────────────────┐
            ▼ no prefix / unknown       ▼ prefix hit                   (no third path)
   Anthropic default path       Prefix pass-through path
   (existing: classifyClient    (new: strip prefix, swap auth,
    → disguise OR CC passthrough  recompute content-length, pipe)
    → ultra rewrite → upstream)
   → api.anthropic.com:443      → route.baseUrl (http or https)
```

The Anthropic default path is the existing code in `startServer`'s request
handler, untouched. The prefix path is a new branch that returns before any of
`rewriteUltraModel` / `classifyClientRequest` / `processBody` run.

### Routing resolution

New function `resolveRoute(bodyStr, config)`:

- Locate the top-level `model` value via string scanning (reuse the
  `findTopLevelKey` pattern; do **not** `JSON.parse` — preserves body integrity
  and matches existing code style).
- If the value contains `/`, split on the first `/`: `prefix = before`,
  `rest = after`.
- If `prefix` is a key in `config.routes`, return `{ route: config.routes[prefix], prefix, outModel: rest }`.
- Otherwise return `null` → caller falls through to the Anthropic default path.

Edge cases (all explicit, no surprises):
- Model with no `/` → `null` → Anthropic default.
- Model with `/` but prefix not in `routes` → `null` → Anthropic default.
- `t9s/` (rest empty) → route hit, model rewritten to empty string; upstream
  rejects. No special handling — pass-through is literal.
- Native Claude Code traffic whose model happens to carry a configured prefix →
  prefix route wins (prefix is checked before classification). This is
  intentional and documented: a configured prefix is an explicit override.

### Prefix pass-through path

When `resolveRoute` returns a route:

1. **Model rewrite.** Replace the top-level `model` value `prefix/rest` with
   `rest`. One targeted string edit; no other body mutation.
2. **Outbound headers.** Copy client headers. Strip: `host`, `connection`,
   `authorization`, `x-api-key`, `content-length`, `x-session-affinity`
   (same strip set as today). Then inject the route's auth header:
   - default → `authorization: Bearer <token>`
   - `authHeader` set (e.g. `x-api-key`) → that header with the bare token as
     value (and the route no longer sends `authorization`).
   Set `content-length` to the rewritten body's byte length.
   Do **not** force `anthropic-version`, `anthropic-beta`, stainless, or CC
   identity headers. The client's own remaining headers pass through.
3. **Upstream dispatch.** Parse `route.baseUrl` into scheme (`http`/`https`),
   host, port (default per scheme), and optional base path. The upstream path is
   `basePath + req.url` (raw `req.url` appended verbatim). Use `http.request` or
   `https.request` per scheme. This is the "request whatever path came in,
   forward to whatever endpoint" semantics — the proxy does not interpret the
   path.
4. **Response.** `res.writeHead(upRes.statusCode, upRes.headers); upRes.pipe(res)`.
   SSE and plain JSON are identical — a raw pipe with no transformation. The
   existing SSE event parser, field buffers, deduper, and `reverseMap` are all
   bypassed.
5. **Errors.** Upstream connection errors → `502` JSON error (same shape as
   today). Upstream non-2xx responses are passed through verbatim (status,
   headers, body) — the proxy does not re-interpret them.

### What the prefix path deliberately does NOT do

- No `rewriteUltraModel` (ultra aliases are Anthropic-only).
- No `classifyClientRequest` / disguise / tool rename / system strip / billing
  header / metadata / prefill strip.
- No response `reverseMap`, no SSE transformation, no dedup.
- No stainless / CC identity header injection.
- No forced `anthropic-version` / `anthropic-beta`.

The prefix path's contract: strip the prefix, swap auth, recompute
`content-length`, pipe. Everything else is the client's and the upstream's
problem.

## Configuration

`config.json` gains an optional top-level `routes` object. It is **user-only** —
not merged with any defaults (there are none). Absent or empty `routes` →
behavior identical to today.

```json
{
  "port": 18801,
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

### Route object fields

| field        | required | default        | meaning |
|--------------|----------|----------------|---------|
| `baseUrl`    | yes      | —              | scheme+host(+port)(+basePath) of the upstream |
| `token`      | one of   | —              | literal token (static) |
| `tokenEnv`   | one of   | —              | env var name holding the token (recommended; read fresh per-request so rotation works, matching the existing `OAUTH_TOKEN` behavior) |
| `authHeader` | no       | `authorization`| header name for the token. When `authorization`, value is `Bearer <token>`; for any other name, value is the bare token |

Validation at `loadConfig` time (fail fast, loud):
- `routes` present but not an object → error + exit.
- A route missing `baseUrl` → error + exit with the offending prefix name.
- A route with neither `token` nor `tokenEnv` → error + exit (a route must name
  its token source).
- A route with `tokenEnv` set but the env var currently unset/empty at startup
  → log a `[WARN] route "<prefix>": tokenEnv "<VAR>" is unset` warning and
  continue (the var may be populated before the first request, and may rotate
  later). The token is read fresh on each request; if still empty at request
  time, that request returns `502`.
- `baseUrl` not parseable into a valid scheme+host → error + exit.

### Env-var precedence

`config.routes` is read from `config.json` only. There is no env-var way to
define routes (routes are structural config, not a secret). Secrets
(`tokenEnv`) are env vars, as above. This keeps the existing `PROXY_PORT` /
`OAUTH_TOKEN` / `KEYS_FILE` / `BILLING_PROXY_*` env contract untouched.

## Backward Compatibility

- `config.json` without `routes` → byte-identical behavior to v2.2.3.
- `config.example.json` unchanged (routes are opt-in user config).
- `/health` gains one new field `routes` (array of configured prefixes); all
  existing fields unchanged.
- Startup banner: if `routes` is non-empty, print a `Routes:` line listing
  `prefix -> baseUrl`. Otherwise no change to the banner.
- `setup.js` and `troubleshoot.js` are out of scope for this change; they
  remain Anthropic-focused. (A future task may extend `troubleshoot.js` to ping
  configured routes — not now.)

## Error Handling

- **Config errors** (missing/invalid route fields, route with neither `token`
  nor `tokenEnv`, unparseable `baseUrl`): `loadConfig` logs
  `[ERROR] route "<prefix>": <reason>` and `process.exit(1)` at startup.
  Matches the existing credential-missing behavior.
- **Per-request**: prefix route dispatch errors (DNS, connection refused, TLS,
  or `tokenEnv` still empty at request time) → `502` with
  `{ type: 'error', error: { message } }`, same shape as the existing
  `upstream.on('error')` handler. No retry.
- **Upstream non-2xx**: passed through verbatim. The proxy does not inspect or
  re-map prefix-route responses.

## Testing

Manual verification (this is a zero-dependency, no-test-harness repo — match the
existing style):

1. **No routes, regression**: start with unchanged `config.json`; send a
   `claude-opus-4-8` request; confirm disguise path + `/health` unchanged.
2. **Prefix route, plain JSON**: configure a `t9s` route pointing at a local
   echo/stub; send `t9s/MODEL_A` to `/v1/messages`; confirm upstream receives
   model `MODEL_A`, auth header set, body otherwise identical; confirm response
   piped back byte-identical.
3. **Prefix route, SSE**: same as above but `stream:true`; confirm SSE chunks
   pipe through unmodified (compare raw bytes client-side).
4. **`authHeader: x-api-key`**: confirm the route sends `x-api-key: <token>` and
   no `authorization`.
5. **`tokenEnv` unset at startup**: confirm `loadConfig` logs a warning naming
   the prefix and continues; a request against that route while the env var is
   still empty returns `502`; after the env var is populated (no restart),
   requests succeed.
6. **Unknown prefix / no prefix**: `claude-opus-4-8` and `unknown/foo` both fall
   to the Anthropic default path.
7. **Path transparency**: request `/v1/messages?beta=true` → upstream path is
   `<basePath>/v1/messages?beta=true`.

## Open Questions

None. All three forks resolved by the user.

## Implementation Notes

- All new logic lives in `proxy.js` (single-file project). New pieces: a
  `resolveRoute` function, a `dispatchPrefixRoute` handler, route validation in
  `loadConfig`, a `routes` line in the startup banner and `/health`.
- Reuse `findTopLevelKey` / the existing top-level-value string-scanning idiom
  for reading and rewriting `model` — do not introduce `JSON.parse` on the body.
- The prefix path is a clean early-return branch inside the existing
  `req.on('end')` handler, placed after the `KEYS_FILE` gate and body read, and
  before `rewriteUltraModel`. Keeping it as one contiguous branch (rather than
  scattering) preserves the file's readability.
