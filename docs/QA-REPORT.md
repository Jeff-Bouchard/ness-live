# Adversarial QA Report — PrivateNess artifacts

Scope: my own deliverables (`nesscollector`, `nessbridge`, `NESS_DASHBOARD.html`,
`NESS_UNIFIED.html`, `ness_redteam.html`). Method: hostile-input fuzzing against
live processes, plus Go unit tests with the race detector. Every defect below was
**found by testing, reproduced, fixed, and re-tested**.

## Defects found and fixed

| # | Component | Severity | Defect | Fix |
|---|-----------|----------|--------|-----|
| 1 | collector | **High** | `ness:rep:` score accepted any type — a `<script>` payload flowed into `state.json` | `validRep()`: finite number in 0..100 only |
| 2 | collector | **High** | nessctl transport status relayed verbatim; `<img src=x onerror=…>` reached the dashboard | allowlist (`online/offline/standby/degraded/unknown`), else `unknown` |
| 3 | dashboard | **High** | 2 live XSS sinks: `stEnt.innerHTML` and `nstat.innerHTML` fed by collector data — proven executable | `esc()`, `safeStatus()`, `safeNum()`; numeric coercion at every sink |
| 4 | collector | Medium | `name_mempool` unbounded — 3000 spam rows passed straight through (state bloat / DoS) | cap 256 rows + `meta.truncated`, per-field length caps, markup stripped |
| 5 | collector | Medium | 2 MB NVS value copied into `state.json` unbounded | `maxBody` 8 MiB `io.LimitReader`, `maxValueLen` 1024 |
| 6 | collector | Medium | Negative `calculated_hours` produced a **negative energy reserve** (`-100 NCH`) | reject non-finite/negative rows, drop row not sum |
| 7 | collector | Medium | Fiber HTTP 500 still reported `live:true, balance 0` — a lie | status-code check on RPC and fiber; `live:false` |
| 8 | collector | Low | `paths: 99999999999999999999`, `entropy: -5` surfaced as-is | `safeNum()` with per-field sane bounds |
| 9 | **bridge** | **High** | `{"type":"tic"}` with no fields relayed as a valid tic — missing fields defaulted to `{src:0,tic:0,input:0}`, **injecting a phantom input into lockstep** | `parseTic()` requires every field explicitly present |
| 10 | bridge | Medium | `src:9` accepted with 2 peers; negative src accepted | range checks (`0 ≤ src < 64`, tic/input bounded) |
| 11 | bridge | Medium | Arbitrary extra fields relayed verbatim; 200 KB frame accepted | canonical re-serialization drops unknown fields; `maxFrame` 4096 |

## Test results after fixes

**nesscollector** — 19/19 adversarial checks pass; `go test` pass; **race detector clean**; `go vet` clean.
Malformed JSON, HTTP 500, RPC errors, XSS payloads, 2 MB values, 3000-row mempool spam,
negative/infinite numbers, binary garbage from nessctl, nessctl crash (exit 3), 60 concurrent
readers, path traversal (`/../../etc/passwd` → 404), malformed POST bodies. **Zero panics.**
Recovery verified: full fidelity restored after every abuse (`nch=12458.39`, `rep=98`, `tor=standby`).

**nessbridge** — 12/12 pass. Phantom/out-of-range/oversize frames dropped; extra fields stripped;
dedup blocks replay; **ed25519 `-verify` regression confirmed intact** (signed delivered,
tampered dropped, unsigned dropped); survives junk and recovers.

**HTML** — all three files: no missing element IDs, script tags balanced, JS syntax valid
(`node --check`), no unescaped dynamic `innerHTML` sinks remaining.

**Portability** — both binaries cross-compile for windows/amd64 and linux/arm64. Dependency
audit: **stdlib only**, no third-party modules.

## Harness faults caught (worth recording)

Three test-harness bugs produced *false* results before I caught them — a reminder that a
green suite means nothing if the harness is broken:
1. `protocol_version='HTTP/1.1'` on a single-threaded `HTTPServer` → keep-alive starved every
   request after the first; every `live:false` in that run was meaningless. → `ThreadingHTTPServer`.
2. A stale mock from an earlier run held the ports (`BINDFAIL: Address already in use`), so three
   "failures" were tested against a server that didn't know the new modes. → unique ports, kill first.
3. Poll interval 5 s vs. 2.2 s sleep → assertions read stale state. → `poll_sec:1`.

One "failure" was also a wrong *expectation*, not a bug: a non-numeric `calculated_hours` fails
JSON decode outright, so fiber is marked **not live**. That is fail-closed and correct — better
than surfacing a partial balance. Documented in `fiber_test.go`.

## Residual risk (not fixed, stated plainly)

- `/state.json` is served with `Access-Control-Allow-Origin: *` and no auth. Bind to localhost
  or put it behind the mesh; do not expose it publicly.
- Actions (`/payout`, `/randpay`) remain **opt-in** and delegate to nessctl. The collector holds
  no keys — by design, not by accident.
- `privacy.*` sub-scores are still unmeasured and reported `live:false` rather than invented.
- Rewards beyond `nchToday` (SKY, 30-day history) are still unimplemented, not faked.
