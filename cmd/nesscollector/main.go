// nesscollector — headless state daemon for the PrivateNess dashboard.
//
// It READS three real sources and serves one CORS-enabled /state.json that the
// NESS_DASHBOARD.html polls. It never holds a spend key and never auto-fires a
// financial op; actions are opt-in and shell out to the operator's own nessctl.
//
//   emercoind  (RPC :6662) — NVS identity/rep, pending anchors (name_mempool),
//                            watch-only balances, chain sync
//   fiber node (NESS :6660) — /api/v1/outputs?addrs=… → calculated_hours = NCH
//   nessctl                 — node status/services/topology (configurable verbs)
//
// Identity is the operator's real handle, the Emercoin way: ness://jeffbouchard.
//
// Zero external dependencies (stdlib only), same philosophy as ness-engine and
// nessbridge. Build: `go build -o nesscollector nesscollector.go`.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── config ───────────────────────────────────────────────────────────────────
type Config struct {
	Listen       string `json:"listen"`
	Identity     string `json:"identity"`
	Ticker       string `json:"ticker"`
	EmercoindRPC string `json:"emercoind_rpc"`
	EmercoindAuth string `json:"emercoind_auth"` // "user:pass"
	FiberNode    string `json:"fiber_node"`
	PaymentAddr  string `json:"payment_addr"`
	HoardAddr    string `json:"hoard_addr"`
	IdentityAddr string `json:"identity_addr"` // extra address to scan for ness:id: names
	NvsPrefix    string `json:"nvs_prefix"`    // namespace to scan, default "ness:"
	Nessctl      string `json:"nessctl"`        // path to nessctl (or empty to skip)
	NessctlStatus string `json:"nessctl_status"` // status subcommand, default "status"
	NessctlPeers  string `json:"nessctl_peers"`  // peers subcommand, default "peers"
	NvsGateway    string `json:"nvs_gateway"`    // e.g. https://nvs.ness.cx
	BenjiGateway  string `json:"benji_gateway"`  // e.g. https://cantdoevil.com
	EnableActions bool   `json:"enable_actions"` // allow POST /payout,/randpay via nessctl
	PollSec      int    `json:"poll_sec"`
}

// ── limits & validation ──────────────────────────────────────────────────────
// Upstream data (emercoind, fiber node, nessctl) is UNTRUSTED input. A hostile
// or buggy source must not be able to inject markup, unbounded payloads, or
// nonsense numbers into state.json — the dashboard renders this.
const (
	maxBody     = 8 << 20 // 8 MiB cap on any upstream response body
	maxPending  = 256     // cap mempool rows exposed in state.json
	maxRecords  = 128     // cap NVS records exposed in state.json
	maxNameLen  = 512     // EmerNVS name limit
	maxValueLen = 1024    // anchors are short; truncate anything longer
	maxStrField = 256     // any scalar string we surface
)

// validStatus is the allowlist for transport state. Anything else -> "unknown".
var validStatus = map[string]bool{
	"online": true, "offline": true, "standby": true, "degraded": true, "unknown": true,
}

// safeStr trims, bounds length, and rejects anything carrying markup or control
// characters. Returns ok=false when the input must be discarded.
func safeStr(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > max { return "", false }
	for _, r := range s {
		if r < 0x20 || r == 0x7f { return "", false }          // control bytes
		if r == '<' || r == '>' || r == '&' || r == '"' || r == '\'' { return "", false } // markup
		if r > 0x7e { return "", false }                        // non-ASCII / binary
	}
	return s, true
}

// validRep enforces that a reputation score is a finite number in 0..100.
// Anything else (string, markup, NaN, out of range) is rejected outright.
func validRep(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 100 { return 0, false }
	return f, true
}

// safeVal validates an NVS *value*. Values are legitimately JSON (WORM records
// carry quotes and braces), so quotes and ampersands are allowed — the renderer
// escapes them. Angle brackets and control/binary bytes are still refused, so
// no markup can ever reach a DOM sink.
func safeVal(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > max { return "", false }
	for _, r := range s {
		if r < 0x20 || r == 0x7f { return "", false }
		if r == '<' || r == '>' { return "", false }
		if r > 0x7e { return "", false }
	}
	return s, true
}

// safeNum parses a bounded, finite, non-negative number from an untrusted string.
func safeNum(s string, max float64) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 32 { return 0, false }
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) { return 0, false }
	if f < 0 || f > max { return 0, false }
	return f, true
}

// probe reports a gateway's real HTTP status. It never infers health.
func (c Config) probe(url string) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return 0, false }
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return 0, false }
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, true
}

func trunc(s string, n int) string { if len(s) > n { return s[:n] + "…" }; return s }

func def(v, d string) string { if v == "" { return d }; return v }

func loadConfig() Config {
	c := Config{}
	// collector.json in cwd (optional), then env overrides
	if b, err := os.ReadFile("collector.json"); err == nil {
		json.Unmarshal(b, &c)
	}
	env := func(k, cur string) string { if v := os.Getenv(k); v != "" { return v }; return cur }
	c.Listen = env("COLLECTOR_LISTEN", def(c.Listen, ":8787"))
	c.Identity = env("IDENTITY", def(c.Identity, "ness://jeffbouchard"))
	c.Ticker = env("NCH_TICKER", def(c.Ticker, "XBTSX.NCH"))
	c.EmercoindRPC = env("EMERCOIND_RPC", def(c.EmercoindRPC, "http://127.0.0.1:6662"))
	c.EmercoindAuth = env("EMERCOIND_AUTH", c.EmercoindAuth)
	c.FiberNode = env("FIBER_NODE", def(c.FiberNode, "http://127.0.0.1:6660"))
	c.PaymentAddr = env("PAYMENT_ADDR", c.PaymentAddr)
	c.HoardAddr = env("HOARD_ADDR", c.HoardAddr)
	c.IdentityAddr = env("IDENTITY_ADDR", c.IdentityAddr)
	c.NvsPrefix = env("NVS_PREFIX", def(c.NvsPrefix, "ness:"))
	c.Nessctl = env("NESSCTL", c.Nessctl)
	c.NessctlStatus = def(c.NessctlStatus, "status")
	c.NessctlPeers = def(c.NessctlPeers, "peers")
	c.NvsGateway = env("NVS_GATEWAY", c.NvsGateway)
	c.BenjiGateway = env("BENJI_GATEWAY", c.BenjiGateway)
	if os.Getenv("COLLECTOR_ENABLE_ACTIONS") == "1" { c.EnableActions = true }
	if c.PollSec == 0 { c.PollSec = 5 }
	return c
}

// ── emercoind JSON-RPC ───────────────────────────────────────────────────────
type rpcReq struct {
	Jsonrpc string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}
type rpcResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c Config) rpc(method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil { params = []interface{}{} }
	body, _ := json.Marshal(rpcReq{"1.0", "collector", method, params})
	req, _ := http.NewRequest("POST", c.EmercoindRPC, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c.EmercoindAuth != "" {
		up := strings.SplitN(c.EmercoindAuth, ":", 2)
		if len(up) == 2 { req.SetBasicAuth(up[0], up[1]) }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("rpc %s: HTTP %d", method, resp.StatusCode)
	}
	var r rpcResp
	// bound the body: a hostile/buggy node must not be able to balloon our memory
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&r); err != nil { return nil, err }
	if r.Error != nil { return nil, fmt.Errorf("rpc %s: %s", method, r.Error.Message) }
	return r.Result, nil
}

// ── fiber node HTTP ──────────────────────────────────────────────────────────
func (c Config) fiberGet(path string, out interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(c.FiberNode, "/")+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("fiber %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// NCH accrual: sum calculated_hours over head_outputs for the given addrs.
type outputsResp struct {
	HeadOutputs []struct {
		Address        string      `json:"address"`
		Coins          string      `json:"coins"`
		CalculatedHours json.Number `json:"calculated_hours"`
	} `json:"head_outputs"`
}
func (c Config) nchAndCoins() (nch float64, coins float64, ok bool) {
	addrs := []string{}
	if c.PaymentAddr != "" { addrs = append(addrs, c.PaymentAddr) }
	if c.HoardAddr != "" { addrs = append(addrs, c.HoardAddr) }
	if len(addrs) == 0 { return 0, 0, false }
	var r outputsResp
	if err := c.fiberGet("/api/v1/outputs?addrs="+strings.Join(addrs, ","), &r); err != nil {
		return 0, 0, false
	}
	for _, o := range r.HeadOutputs {
		// A negative or non-finite balance is never valid; drop the row rather
		// than render a nonsense "energy reserve".
		if h, err := o.CalculatedHours.Float64(); err == nil {
			if math.IsNaN(h) || math.IsInf(h, 0) || h < 0 {
				log.Printf("[reject] fiber calculated_hours out of range: %v", h)
				continue
			}
			nch += h
		}
		if c, ok := safeNum(o.Coins, 1e15); ok { coins += c }
	}
	if nch < 0 || coins < 0 { return 0, 0, false }
	return nch, coins, true
}

// ── nessctl exec (configurable verbs) ────────────────────────────────────────
func (c Config) nessctl(args ...string) (string, bool) {
	if c.Nessctl == "" { return "", false }
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.Nessctl, args...).Output()
	if err != nil { return "", false }
	return string(out), true
}

// parse "key: value" lines from nessctl status into a map
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		if i := strings.Index(ln, ":"); i > 0 {
			m[strings.ToLower(strings.TrimSpace(ln[:i]))] = strings.TrimSpace(ln[i+1:])
		}
	}
	return m
}

// ── state assembly ───────────────────────────────────────────────────────────
type State struct {
	Meta struct {
		Identity string          `json:"identity"`
		TS       int64           `json:"ts"`
		Version  string          `json:"version"`
		Live      map[string]bool `json:"live"`
		Truncated bool            `json:"truncated,omitempty"`
	} `json:"meta"`
	Identity map[string]interface{} `json:"identity"`
	Energy   map[string]interface{} `json:"energy"`
	Rewards  map[string]interface{} `json:"rewards"`
	Privacy  map[string]interface{} `json:"privacy"`
	Status   map[string]string      `json:"status"`
	Stats    map[string]interface{} `json:"stats"`
	Entropy  map[string]interface{} `json:"entropy"`
	Chain    map[string]interface{} `json:"chain,omitempty"`
	Randpay  map[string]interface{} `json:"randpay,omitempty"`
	Gateway  map[string]interface{} `json:"gateway,omitempty"`
	Peers      []map[string]interface{} `json:"peers,omitempty"`
	Identities []map[string]interface{} `json:"identities,omitempty"`
	Records    []map[string]interface{} `json:"records,omitempty"`
	Pending  []map[string]interface{} `json:"pending"`
}

var (
	cur   State
	curMu sync.RWMutex
	lastNCH float64
	lastNCHDay = time.Now().YearDay()
	nchDayStart float64
)

func shortName(identity string) string {
	n := strings.TrimPrefix(identity, "ness://")
	return n
}

func collect(c Config) State {
	var s State
	s.Meta.Identity = c.Identity
	s.Meta.TS = time.Now().Unix()
	s.Meta.Version = "0.6.2"
	s.Meta.Live = map[string]bool{}
	name := shortName(c.Identity)

	// ── emercoind: sync + rep NVS + pending anchors ──
	emcLive := false
	if raw, err := c.rpc("getblockchaininfo"); err == nil {
		emcLive = true
		var bi struct {
			Blocks  json.Number `json:"blocks"`
			Headers json.Number `json:"headers"`
		}
		if json.Unmarshal(raw, &bi) == nil {
			ch := map[string]interface{}{}
			if b, e := bi.Blocks.Float64(); e == nil && b >= 0 { ch["blocks"] = b }
			if h, e := bi.Headers.Float64(); e == nil && h >= 0 { ch["headers"] = h }
			if len(ch) > 0 { s.Chain = ch }
		}
	}
	s.Meta.Live["emercoind"] = emcLive

	// identity + reputation (from ness:rep:<name> if present)
	rep := interface{}(nil); repLive := false
	if emcLive {
		if raw, err := c.rpc("name_show", "ness:rep:"+name); err == nil {
			var ns struct{ Value string `json:"value"` }
			if json.Unmarshal(raw, &ns) == nil && ns.Value != "" && len(ns.Value) <= maxValueLen {
				var v map[string]interface{}
				if json.Unmarshal([]byte(ns.Value), &v) == nil {
					// reputation MUST be a finite number in 0..100. A string
					// (including markup) is rejected outright, not surfaced.
					if f, ok := validRep(v["score"]); ok {
						rep = f
						repLive = true
					} else {
						log.Printf("[reject] ness:rep score not a 0..100 number: %T", v["score"])
					}
				}
			}
		}
	}
	s.Identity = map[string]interface{}{"name": name, "rep": rep, "live": repLive}

	// Identities the operator can PICK. Sourced from NVS, never invented:
	// name_scan_address returns names owned by an address in this wallet.
	if emcLive {
		seen := map[string]bool{}
		addIdent := func(name string, mine bool) {
			n, ok := safeStr(name, maxNameLen)
			if !ok || seen[n] || !strings.HasPrefix(n, "ness:id:") { return }
			seen[n] = true
			s.Identities = append(s.Identities, map[string]interface{}{
				"nvs": n, "handle": "ness://" + strings.TrimPrefix(n, "ness:id:"), "mine": mine,
			})
		}
		for _, addr := range []string{c.PaymentAddr, c.HoardAddr, c.IdentityAddr} {
			if addr == "" { continue }
			if raw, err := c.rpc("name_scan_address", addr); err == nil {
				var arr []map[string]interface{}
				if json.Unmarshal(raw, &arr) == nil {
					for _, m := range arr {
						if n, ok := m["name"].(string); ok { addIdent(n, true) }
					}
				}
			}
		}
		// the configured operator identity is always offered, marked by provenance
		if c.Identity != "" {
			h := strings.TrimPrefix(c.Identity, "ness://")
			addIdent("ness:id:"+h, false)
		}
		if len(s.Identities) > 64 { s.Identities = s.Identities[:64] }
	}

	// Red team = EmerNVS. Every verdict, revocation and authority claim is a name
	// record; we read them rather than invent a threat feed.
	if emcLive && c.NvsPrefix != "" {
		if raw, err := c.rpc("name_filter", "^"+c.NvsPrefix, 0, 0, maxRecords); err == nil {
			var arr []map[string]interface{}
			if json.Unmarshal(raw, &arr) == nil {
				for _, m := range arr {
					name, ok := m["name"].(string)
					if !ok { continue }
					n, ok := safeStr(name, maxNameLen)
					if !ok { continue }
					row := map[string]interface{}{"name": n}
					if v, ok := m["value"].(string); ok {
						if len(v) > maxValueLen { v = v[:maxValueLen] }
						if v2, ok2 := safeVal(v, maxValueLen); ok2 { row["value"] = v2 }
					}
					if e, ok := m["expires_in"].(float64); ok && e > -1e9 && e < 1e9 { row["expires_in"] = e }
					s.Records = append(s.Records, row)
					if len(s.Records) >= maxRecords { break }
				}
			}
		}
	}

	// pending NVS anchors from the mempool (near-instant, before confirmation)
	if emcLive {
		if raw, err := c.rpc("name_mempool"); err == nil {
			var arr []map[string]interface{}
			if json.Unmarshal(raw, &arr) == nil {
				truncated := len(arr) > maxPending
				if truncated { arr = arr[:maxPending] } // mempool spam must not balloon state.json
				for _, m := range arr {
					row := map[string]interface{}{}
					if v, ok := m["name"].(string); ok {
						if v2, ok2 := safeStr(v, maxNameLen); ok2 { row["name"] = v2 }
					}
					if v, ok := m["operation"].(string); ok {
						if v2, ok2 := safeStr(v, 32); ok2 { row["operation"] = v2 }
					}
					if v, ok := m["txid"].(string); ok {
						if v2, ok2 := safeStr(v, 64); ok2 { row["txid"] = v2 }
					}
					if v, ok := m["value"].(string); ok {
						if len(v) > maxValueLen { v = v[:maxValueLen] }
						if v2, ok2 := safeVal(v, maxValueLen); ok2 { row["value"] = v2 }
					}
					if len(row) > 0 { s.Pending = append(s.Pending, row) }
				}
				if truncated { s.Meta.Truncated = true }
			}
		}
	}

	// ── fiber node: NCH energy reserve ──
	nch, coins, fiberLive := c.nchAndCoins()
	s.Meta.Live["fiber"] = fiberLive
	energy := map[string]interface{}{"ticker": c.Ticker, "live": fiberLive}
	if fiberLive {
		energy["balance"] = nch
		energy["coins"] = coins
	}
	s.Energy = energy

	// rewards: today's NCH delta (best-effort, resets at local day change)
	rewardsLive := false
	rewards := map[string]interface{}{"live": false}
	if fiberLive {
		if time.Now().YearDay() != lastNCHDay { lastNCHDay = time.Now().YearDay(); nchDayStart = nch }
		if nchDayStart == 0 { nchDayStart = nch }
		rewards = map[string]interface{}{"nchToday": nch - nchDayStart, "live": true}
		rewardsLive = true
		lastNCH = nch
	}
	s.Rewards = rewards
	s.Meta.Live["rewards"] = rewardsLive

	// ── nessctl: node status / services / transports / stats ──
	// Stack layers per the PrivateNess architecture:
	// L1 LBRTY radio · L2 SoftEther · L2.5 Skywire (mandatory) · L3 EmerDNS
	// plus per-threat-model overlays: Yggdrasil, I2P, Tor.
	status := map[string]string{
		"lbrty": "unknown", "softether": "unknown", "skywire": "unknown",
		"emerdns": "unknown", "yggdrasil": "unknown", "i2p": "unknown", "tor": "unknown",
	}
	stats := map[string]interface{}{}
	entropy := map[string]interface{}{}
	var nextPayout float64
	havePayout := false
	nessctlLive := false
	if out, ok := c.nessctl(strings.Fields(c.NessctlStatus)...); ok {
		nessctlLive = true
		kv := parseKV(out)
		for _, layer := range []string{"lbrty", "softether", "skywire", "emerdns", "yggdrasil", "i2p", "tor"} {
			v, ok := kv[layer]
			if !ok { continue }
			lv := strings.ToLower(strings.TrimSpace(v))
			// allowlist: anything else (markup, binary, novel words) -> "unknown"
			if validStatus[lv] {
				status[layer] = lv
			} else {
				log.Printf("[reject] nessctl %s status %q not in allowlist", layer, trunc(lv, 40))
				status[layer] = "unknown"
			}
		}
		// numeric stats are emitted as numbers, bounded to sane ranges
		if f, ok := safeNum(kv["paths"], 1e6); ok { stats["paths"] = f }
		if f, ok := safeNum(kv["packets"], 1e12); ok { stats["pps"] = f }
		if f, ok := safeNum(kv["entropy"], 1e9); ok { stats["entropyBits"] = f; entropy["bits"] = f }
		if f, ok := safeNum(kv["nextpayout"], 1e7); ok { nextPayout = f; havePayout = true }
	}
	if havePayout { s.Energy["nextPayoutSec"] = nextPayout }
	// Peers come ONLY from a real reported set. No synthetic graph is ever built:
	// the dashboard renders "NO OBSERVATION" instead of decorative topology.
	if out, ok := c.nessctl(strings.Fields(c.NessctlPeers)...); ok {
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(ln))
			if len(f) < 2 { continue }
			pk, ok1 := safeStr(f[0], 128)
			tr, ok2 := safeStr(strings.ToLower(f[1]), 32)
			if !ok1 || !ok2 { continue }
			row := map[string]interface{}{"pk": pk, "transport": tr}
			if len(f) > 2 { if h, ok := safeNum(f[2], 64); ok { row["hops"] = h } }
			s.Peers = append(s.Peers, row)
			if len(s.Peers) >= 128 { break }
		}
	}
	s.Status = status
	s.Stats = stats
	s.Entropy = entropy
	s.Meta.Live["nessctl"] = nessctlLive

	// Gateways: reachability only. We report what a probe actually returned;
	// an unreachable gateway is absent from the map, never rendered as "ok".
	gw := map[string]interface{}{}
	if c.NvsGateway != "" {
		if code, ok := c.probe(c.NvsGateway); ok { gw["nvs"] = fmt.Sprintf("HTTP %d", code) }
	}
	if c.BenjiGateway != "" {
		if code, ok := c.probe(c.BenjiGateway); ok { gw["benji"] = fmt.Sprintf("HTTP %d", code) }
	}
	if len(gw) > 0 { s.Gateway = gw }

	// privacy: only expose what is measured; leave the rest absent (honest)
	s.Privacy = map[string]interface{}{"live": false}

	return s
}

func pollLoop(c Config) {
	for {
		st := collect(c)
		curMu.Lock(); cur = st; curMu.Unlock()
		live := st.Meta.Live
		log.Printf("[state] emc=%v fiber=%v nessctl=%v pending=%d",
			live["emercoind"], live["fiber"], live["nessctl"], len(st.Pending))
		time.Sleep(time.Duration(c.PollSec) * time.Second)
	}
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func main() {
	c := loadConfig()
	log.Printf("nesscollector identity=%s listen=%s emercoind=%s fiber=%s nessctl=%q actions=%v",
		c.Identity, c.Listen, c.EmercoindRPC, c.FiberNode, c.Nessctl, c.EnableActions)

	// prime once, then poll
	first := collect(c); curMu.Lock(); cur = first; curMu.Unlock()
	go pollLoop(c)

	mux := http.NewServeMux()
	mux.HandleFunc("/state.json", func(w http.ResponseWriter, r *http.Request) {
		cors(w)
		if r.Method == "OPTIONS" { return }
		w.Header().Set("Content-Type", "application/json")
		curMu.RLock(); st := cur; curMu.RUnlock()
		json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		cors(w); io.WriteString(w, "ok\n")
	})

	// Actions are OPT-IN and delegate to the operator's own nessctl. They never
	// reimplement signing and are refused unless -enable-actions is set. This
	// keeps the collector watch-only by default.
	action := func(verb string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cors(w)
			if r.Method == "OPTIONS" { return }
			w.Header().Set("Content-Type", "application/json")
			if !c.EnableActions || c.Nessctl == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"ok": false, "demo": true,
					"reason": "actions disabled — run with -enable-actions and a nessctl path to delegate",
					"would_run": c.Nessctl + " " + verb,
				})
				return
			}
			body, _ := io.ReadAll(r.Body)
			args := []string{verb}
			var m map[string]string
			if json.Unmarshal(body, &m) == nil {
				for k, v := range m { args = append(args, "--"+k, v) }
			}
			out, ok := c.nessctl(args...)
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": ok, "output": out})
		}
	}
	mux.HandleFunc("/payout", action("payout"))
	mux.HandleFunc("/randpay", action("randpay"))

	if err := http.ListenAndServe(c.Listen, mux); err != nil { log.Fatal(err) }
}
