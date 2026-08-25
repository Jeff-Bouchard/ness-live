package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// nchAndCoins must never surface a negative or non-finite energy reserve, and
// must drop bad rows rather than poison the sum.
func TestNchAndCoins(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		status   int
		wantOK   bool
		wantNCH  float64
	}{
		{"normal", `{"head_outputs":[{"address":"A","coins":"1500.0","calculated_hours":"8200"},{"address":"B","coins":"900.5","calculated_hours":"4258.39"}]}`, 200, true, 12458.39},
		{"negative row dropped", `{"head_outputs":[{"address":"A","coins":"100","calculated_hours":"50"},{"address":"B","coins":"-9","calculated_hours":"-9"}]}`, 200, true, 50},
		{"all negative", `{"head_outputs":[{"address":"A","coins":"-5","calculated_hours":"-100"}]}`, 200, true, 0},
		{"infinite hours", `{"head_outputs":[{"address":"A","coins":"100","calculated_hours":"1e400"}]}`, 200, true, 0},
		// A non-numeric calculated_hours fails JSON decode outright. We treat that as
		// fail-closed: fiber is marked NOT live rather than surfacing a partial sum.
		{"non-numeric", `{"head_outputs":[{"address":"A","coins":"abc","calculated_hours":"xyz"}]}`, 200, false, 0},
		{"empty", `{"head_outputs":[]}`, 200, true, 0},
		{"null outputs", `{"head_outputs":null}`, 200, true, 0},
		{"garbage json", `}{ nope`, 200, false, 0},
		{"http 500", `{}`, 500, false, 0},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			w.Write([]byte(c.body))
		}))
		cfg := Config{FiberNode: srv.URL, PaymentAddr: "A", HoardAddr: "B"}
		nch, _, ok := cfg.nchAndCoins()
		srv.Close()
		if ok != c.wantOK {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.wantOK)
			continue
		}
		if ok && (nch < c.wantNCH-0.01 || nch > c.wantNCH+0.01) {
			t.Errorf("%s: nch=%v want %v", c.name, nch, c.wantNCH)
		}
		if nch < 0 {
			t.Errorf("%s: NEGATIVE energy reserve leaked: %v", c.name, nch)
		}
	}
}
