package main

import "testing"

func TestSafeStr(t *testing.T) {
	cases := []struct{ in string; max int; wantOK bool }{
		{"online", 32, true},
		{"<img src=x onerror=alert(1)>", 64, false}, // markup
		{"a\x00b", 32, false},                       // control byte
		{"ok\nnext", 32, false},                     // newline is a control byte
		{"toolong", 3, false},                       // length
		{"", 32, false},                             // empty
		{"caf\u00e9", 32, false},                    // non-ASCII
		{"ness:id:9f2c", 64, true},
		{"a'b", 32, false},                          // quote
	}
	for _, c := range cases {
		got, ok := safeStr(c.in, c.max)
		if ok != c.wantOK {
			t.Errorf("safeStr(%q,%d) ok=%v want %v (got %q)", c.in, c.max, ok, c.wantOK, got)
		}
	}
}

func TestSafeNum(t *testing.T) {
	cases := []struct{ in string; max float64; wantOK bool; want float64 }{
		{"24", 1e6, true, 24},
		{"1536", 1e9, true, 1536},
		{"99999999999999999999", 1e6, false, 0}, // overflow bound
		{"-5", 1e9, false, 0},                    // negative
		{"NaN", 1e9, false, 0},
		{"Inf", 1e9, false, 0},
		{"1e400", 1e9, false, 0}, // parses to +Inf
		{"abc", 1e9, false, 0},
		{"", 1e9, false, 0},
		{"87.5", 100, true, 87.5},
	}
	for _, c := range cases {
		got, ok := safeNum(c.in, c.max)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("safeNum(%q,%v) = (%v,%v) want (%v,%v)", c.in, c.max, got, ok, c.want, c.wantOK)
		}
	}
}

func TestValidStatusAllowlist(t *testing.T) {
	for _, good := range []string{"online", "offline", "standby", "degraded", "unknown"} {
		if !validStatus[good] { t.Errorf("%q should be allowed", good) }
	}
	for _, bad := range []string{"<img src=x>", "ONLINE!!", "", "pwned", "on line"} {
		if validStatus[bad] { t.Errorf("%q must NOT be allowed", bad) }
	}
}

func TestTrunc(t *testing.T) {
	if got := trunc("abcdef", 3); got != "abc…" { t.Errorf("trunc = %q", got) }
	if got := trunc("ab", 5); got != "ab" { t.Errorf("trunc = %q", got) }
}

func TestValidRep(t *testing.T) {
	cases := []struct{ in interface{}; wantOK bool; want float64 }{
		{float64(98), true, 98},
		{float64(87.5), true, 87.5},
		{float64(0), true, 0},
		{float64(100), true, 100},
		{float64(-999), false, 0},                        // negative
		{float64(101), false, 0},                         // above range
		{1e308, false, 0},                                // absurd
		{"ninety-eight", false, 0},                       // wrong type
		{"<script>alert(1)</script>", false, 0},          // XSS payload
		{nil, false, 0},
		{map[string]interface{}{}, false, 0},
	}
	for _, c := range cases {
		got, ok := validRep(c.in)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("validRep(%#v) = (%v,%v) want (%v,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

func TestSafeVal(t *testing.T) {
	cases := []struct{ in string; wantOK bool }{
		{`{"score":98}`, true},                      // JSON value must survive
		{`ness:worm:id:1|pub=9f2c`, true},
		{`A=192.168.0.1|NS=ns1.x.com|TTL=400`, true},
		{`sha256=2c2de184a316be17`, true},
		{`<img src=x onerror=alert(1)>`, false},     // markup still refused
		{"bad\x00byte", false},
		{"caf\u00e9", false},
		{"", false},
	}
	for _, c := range cases {
		_, ok := safeVal(c.in, 1024)
		if ok != c.wantOK { t.Errorf("safeVal(%q) ok=%v want %v", c.in, ok, c.wantOK) }
	}
}
