// nessbridge — WebSocket ⇄ Skywire tic bridge for NESS DOOM lockstep.
//
// One bridge runs per node. The browser (one real DOOM peer) connects to the
// bridge over WebSocket and exchanges input-tic frames:
//
//     {"type":"tic","src":<int>,"tic":<int>,"input":<int>[,"pk":"..","sig":".."]}
//
// The bridge carries those frames to/from the other nodes' bridges over plain
// TCP (newline-delimited JSON). In a real deployment those TCP links are
// Skywire-forwarded local ports, so the bytes ride the mesh:
//
//   # publish THIS node's mesh peer port (logical :666) from local :6666
//   skywire cli skynet start-server --local 6666 --remote 666        # server side
//   # forward EACH remote peer's mesh port to a distinct local port
//   skywire cli skynet start --pk <PEER_PK> --remote 666 --local 16001
//   ...then run:  nessbridge -id 0 -ws :7666 -listen :6666 -peers 127.0.0.1:16001,127.0.0.1:16002
//
// Loop-free by construction: browser→mesh only, mesh→browser only. No frame is
// forwarded between two mesh links, so a fully-connected group never storms.
//
// Zero external dependencies: the WebSocket server (RFC 6455 subset) and TCP
// mesh are implemented on the standard library. Build: `go build -o nessbridge`.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── tic frame ───────────────────────────────────────────────────────────────
type Tic struct {
	Type  string `json:"type"`
	Src   int    `json:"src"`
	Tic   int    `json:"tic"`
	Input int    `json:"input"`
	PK    string `json:"pk,omitempty"`
	Sig   string `json:"sig,omitempty"`
}

// canonical bytes signed/verified (stable, no map ordering surprises)
func (t Tic) signedBytes() []byte {
	return []byte(fmt.Sprintf("tic|%d|%d|%d", t.Src, t.Tic, t.Input))
}

// Frame limits. A peer is UNTRUSTED: a frame must carry every field explicitly,
// in range, or it is dropped. Missing fields must never default to zero — a
// phantom {src:0,tic:0,input:0} would inject a fake input into lockstep.
const (
	maxFrame   = 4096   // bytes; a tic frame is tiny
	maxPeers   = 64     // src must index a plausible peer
	maxTic     = 1 << 28
	maxInput   = 0xFFFF
)

// parseTic strictly validates an incoming frame and returns the CANONICAL
// re-serialization, so unknown/extra fields are never relayed onward.
func parseTic(b []byte) (Tic, []byte, bool) {
	var t Tic
	if len(b) == 0 || len(b) > maxFrame { return t, nil, false }
	// require every field to be present explicitly
	var probe map[string]json.RawMessage
	if json.Unmarshal(b, &probe) != nil { return t, nil, false }
	for _, k := range []string{"type", "src", "tic", "input"} {
		if _, ok := probe[k]; !ok { return t, nil, false }
	}
	if json.Unmarshal(b, &t) != nil { return t, nil, false }
	if t.Type != "tic" { return t, nil, false }
	if t.Src < 0 || t.Src >= maxPeers { return t, nil, false }
	if t.Tic < 0 || t.Tic > maxTic { return t, nil, false }
	if t.Input < 0 || t.Input > maxInput { return t, nil, false }
	if len(t.PK) > 64 || len(t.Sig) > 128 { return t, nil, false }
	canon, err := json.Marshal(t) // drops any extra fields
	if err != nil { return t, nil, false }
	return t, canon, true
}

// ── hub: fans frames between the browser WS and the mesh links ───────────────
type Hub struct {
	mu       sync.Mutex
	toBrowser func([]byte) // set when a browser is connected
	meshOut  map[int]chan []byte
	nextLink int
	verify   bool
	seen     map[uint64]struct{}
	seenRing []uint64
}

func newHub(verify bool) *Hub {
	return &Hub{meshOut: map[int]chan []byte{}, verify: verify, seen: map[uint64]struct{}{}}
}

func (h *Hub) dedup(t Tic) bool { // true if new
	k := uint64(uint32(t.Src))<<32 | uint64(uint32(t.Tic))
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.seen[k]; ok {
		return false
	}
	h.seen[k] = struct{}{}
	h.seenRing = append(h.seenRing, k)
	if len(h.seenRing) > 8192 {
		old := h.seenRing[0]
		h.seenRing = h.seenRing[1:]
		delete(h.seen, old)
	}
	return true
}

func (h *Hub) verifyTic(t Tic) bool {
	if !h.verify {
		return true
	}
	if t.PK == "" || t.Sig == "" {
		return false
	}
	pk, err1 := hex.DecodeString(t.PK)
	sig, err2 := hex.DecodeString(t.Sig)
	if err1 != nil || err2 != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pk, t.signedBytes(), sig)
}

// browser → all mesh links
func (h *Hub) fromBrowser(b []byte) {
	t, canon, ok := parseTic(b)
	if !ok {
		log.Printf("[drop] malformed browser frame (%d bytes)", len(b))
		return
	}
	b = canon
	if !h.verifyTic(t) {
		log.Printf("[drop] browser tic failed verify src=%d tic=%d", t.Src, t.Tic)
		return
	}
	h.mu.Lock()
	links := make([]chan []byte, 0, len(h.meshOut))
	for _, c := range h.meshOut {
		links = append(links, c)
	}
	h.mu.Unlock()
	for _, c := range links {
		select {
		case c <- b:
		default: // slow link: drop rather than block lockstep
		}
	}
}

// mesh link → browser (only; never re-forwarded to other links)
func (h *Hub) fromMesh(b []byte) {
	t, canon, ok := parseTic(b)
	if !ok {
		log.Printf("[drop] malformed mesh frame (%d bytes)", len(b))
		return
	}
	b = canon
	if !h.verifyTic(t) {
		log.Printf("[drop] mesh tic failed verify src=%d tic=%d", t.Src, t.Tic)
		return
	}
	if !h.dedup(t) {
		return
	}
	h.mu.Lock()
	send := h.toBrowser
	h.mu.Unlock()
	if send != nil {
		send(b)
	}
}

func (h *Hub) addLink() (int, chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextLink
	h.nextLink++
	c := make(chan []byte, 256)
	h.meshOut[id] = c
	return id, c
}
func (h *Hub) dropLink(id int) {
	h.mu.Lock()
	if c, ok := h.meshOut[id]; ok {
		close(c)
		delete(h.meshOut, id)
	}
	h.mu.Unlock()
}
func (h *Hub) setBrowser(fn func([]byte)) {
	h.mu.Lock()
	h.toBrowser = fn
	h.mu.Unlock()
}

// ── minimal RFC 6455 WebSocket server (text frames, client-masked) ───────────
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type wsConn struct {
	rw *bufio.ReadWriter
	c  net.Conn
	mu sync.Mutex
}

func (w *wsConn) writeText(p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeFrame(0x1, p)
}
func (w *wsConn) writeFrame(opcode byte, p []byte) error {
	var hdr []byte
	b0 := byte(0x80) | opcode // FIN + opcode
	hdr = append(hdr, b0)
	n := len(p)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)) // server frames are unmasked
	case n < 65536:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, ext...)
	}
	if _, err := w.rw.Write(hdr); err != nil {
		return err
	}
	if _, err := w.rw.Write(p); err != nil {
		return err
	}
	return w.rw.Flush()
}

// readMessage returns one text payload, transparently answering ping/close.
func (w *wsConn) readMessage() ([]byte, error) {
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(w.rw, h); err != nil {
			return nil, err
		}
		opcode := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		ln := int(h[1] & 0x7f)
		switch ln {
		case 126:
			e := make([]byte, 2)
			if _, err := io.ReadFull(w.rw, e); err != nil {
				return nil, err
			}
			ln = int(binary.BigEndian.Uint16(e))
		case 127:
			e := make([]byte, 8)
			if _, err := io.ReadFull(w.rw, e); err != nil {
				return nil, err
			}
			ln = int(binary.BigEndian.Uint64(e))
		}
		var mask []byte
		if masked {
			mask = make([]byte, 4)
			if _, err := io.ReadFull(w.rw, mask); err != nil {
				return nil, err
			}
		}
		if ln < 0 || ln > maxFrame*64 { // refuse absurd allocations
			return nil, fmt.Errorf("frame too large: %d", ln)
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(w.rw, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x1, 0x2: // text / binary
			return payload, nil
		case 0x8: // close
			w.mu.Lock()
			w.writeFrame(0x8, nil)
			w.mu.Unlock()
			return nil, io.EOF
		case 0x9: // ping → pong
			w.mu.Lock()
			w.writeFrame(0xA, payload)
			w.mu.Unlock()
		case 0xA: // pong: ignore
		}
	}
}

func serveWS(h *Hub) http.HandlerFunc {
	return func(wr http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(wr, "expected websocket", 400)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, ok := wr.(http.Hijacker)
		if !ok {
			http.Error(wr, "no hijack", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
		buf.WriteString(resp)
		buf.Flush()
		ws := &wsConn{rw: buf, c: conn}
		log.Printf("[ws] browser connected %s", conn.RemoteAddr())

		h.setBrowser(func(b []byte) { ws.writeText(b) })
		defer h.setBrowser(nil)
		defer conn.Close()
		for {
			msg, err := ws.readMessage()
			if err != nil {
				log.Printf("[ws] browser closed: %v", err)
				return
			}
			h.fromBrowser(msg)
		}
	}
}

// ── TCP mesh links (newline-delimited JSON) ──────────────────────────────────
func handleMeshConn(h *Hub, c net.Conn, who string) {
	id, out := h.addLink()
	log.Printf("[mesh] link up (%s) %s", who, c.RemoteAddr())
	defer func() { h.dropLink(id); c.Close(); log.Printf("[mesh] link down %s", c.RemoteAddr()) }()

	// writer: hub → this peer
	go func() {
		w := bufio.NewWriter(c)
		for b := range out {
			w.Write(b)
			w.WriteByte('\n')
			if w.Flush() != nil {
				return
			}
		}
	}()
	// reader: this peer → hub → browser
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		h.fromMesh(cp)
	}
}

func meshListener(h *Hub, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[mesh] listen %s: %v", addr, err)
	}
	log.Printf("[mesh] listening %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleMeshConn(h, c, "accepted")
	}
}

func meshDialer(h *Hub, addr string) {
	for {
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		handleMeshConn(h, c, "dialed "+addr)
		time.Sleep(1 * time.Second) // reconnect after drop
	}
}

// ── main ─────────────────────────────────────────────────────────────────────
func main() {
	wsAddr := flag.String("ws", ":7666", "WebSocket listen addr for the browser peer")
	listen := flag.String("listen", ":6666", "TCP listen addr for inbound mesh links")
	peers := flag.String("peers", "", "comma-separated peer dial addrs (Skywire-forwarded local ports)")
	id := flag.Int("id", 0, "this node's peer id (informational)")
	verify := flag.Bool("verify", false, "require + verify ed25519 sig on every tic")
	flag.Parse()

	h := newHub(*verify)
	go meshListener(h, *listen)
	for _, p := range strings.Split(*peers, ",") {
		if p = strings.TrimSpace(p); p != "" {
			go meshDialer(h, p)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveWS(h))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	log.Printf("nessbridge id=%d ws=%s mesh-listen=%s peers=[%s] verify=%v",
		*id, *wsAddr, *listen, *peers, *verify)
	log.Fatal(http.ListenAndServe(*wsAddr, mux))
}
