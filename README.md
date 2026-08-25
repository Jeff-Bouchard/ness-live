# ness-live

Operator observatory for the PrivateNess stack: a headless state daemon, a mesh
tic transport, and a **one-screen** web surface that shows only what was actually
observed.

> **No mocks. No placeholders. No fake verification.**
> `checked:false` is not a pass — it is an admission.

Zero external dependencies. Go standard library only, no cgo, single module.

## What's here

| path | what it is |
|------|------------|
| `cmd/nesscollector` | reads emercoind + fiber node + `nessctl`, serves one CORS `/state.json` |
| `cmd/nessbridge` | WebSocket ⇄ Skywire transport for lockstep input tics (logical `:666`) |
| `web/index.html` | the one-screen observatory (open it in a browser; no build step) |
| `configs/` | example collector config + systemd unit |
| `docs/QA-REPORT.md` | adversarial QA: 11 defects found, fixed and re-tested |

## Quick start

```bash
make                       # vet + test + build
cp configs/collector.json.example collector.json   # edit addresses + RPC auth
./bin/nesscollector        # serves http://127.0.0.1:8787/state.json
```

Then open `web/index.html` in a browser and press **Scan**. Only endpoints that
actually answer appear in the source picker.

## Data sources

| source | port | what it yields |
|--------|------|----------------|
| emercoind (JSON-RPC) | 6662 | chain tip, `ness:id:` identities, `ness:rep:` reputation, NVS records, **pending anchors via `name_mempool`** |
| fiber node (NESS) | 6660 | `GET /api/v1/outputs?addrs=…` → Σ `calculated_hours` = **NCH energy reserve** |
| `nessctl` | — | transport status per layer, peers, paths, packets/s, entropy bits |

NCH is **energy**, not currency: it accrues at 1/hr per whole NESS held. You hold
NESS and consume energy; you do not spend it.

## The screen

One viewport, nothing scrolls. Every panel carries a provenance badge that is a
**separate axis from the check** — `YOUR NODE`, `KEY FILE`, or `NOT OBSERVED`.

- **Identity** — picked from `ness:id:` records observed on-chain, or loaded from
  a key file. `📁 Key file…` reads **public fields only**; if the file contains
  secret material it says so and does not read it into the page.
- **＋ New…** — the PrivateNess Lite wizard. Generates the setup script for
  `keygen` / `key nvs` / `key worm`; **the page never generates or holds a key**.
  You review the script and run it yourself.
- **Live topology** — drawn only from an observed peer set. Packet motion is
  driven by observed packets/s. With no peers it refuses to draw and says so:
  a topology without observed peers would be decoration, not data.
- **Red Team · EmerNVS** — verdicts *are* name records. Unconfirmed mempool
  operations first (seconds, before the block), then confirmed records, classed
  by subtype: `ness:id:` identity, `ness:rep:` reputation, `ness:node:` node,
  `dpo:` ownership. Nothing is scored or invented.

## Safety posture

- The collector is **watch-only**. It holds no spend key and never writes to a chain.
- Actions (`POST /payout`, `/randpay`) are **opt-in** (`COLLECTOR_ENABLE_ACTIONS=1`)
  and delegate to your own `nessctl`. With actions off the buttons return a truthful
  refusal rather than pretending.
- Untrusted input from every source is validated: markup refused, values bounded,
  mempool rows capped, negative/non-finite numbers rejected. See `docs/QA-REPORT.md`.
- `/state.json` is served with `Access-Control-Allow-Origin: *` and **no auth** —
  bind it to localhost or keep it behind the mesh. Do not expose it publicly.

## Identity

The operator identity is real-name and public by design, the Emercoin way:
`ness://jeffbouchard`. Derived pseudonymous personas are a separate mechanism for
automated agents — not a replacement for the accountable operator.

## Known gaps (stated, not faked)

- `keygen node` argument order in the generated script needs confirming against
  your build (`./keygen node --help`).
- `nessctl peers` is parsed as `<pk> <transport> <hops>` per line — confirm format.
- SKY rewards and 30-day NCH history are unimplemented; they render `NOT OBSERVED`.
- Privacy sub-scores are unmeasured and reported `live:false` rather than invented.
- `nvs.ness.cx` and `cantdoevil.com` are reachability-probed only; no read API wired.

## License

Not yet chosen — add one before publishing.
