package proxy

import (
	"strings"
	"testing"
)

// Pins for parseRequestLine (ibhs): the request-line split is the most
// smuggling-critical parse burpsy owns — it decides which token the whole proxy
// treats as the target, and the swqq '/a b' history is the receipt for what a
// mismatch with the origin costs. These state the contract as extracted; the
// split is deliberately unchanged from the inline strings.Fields both call sites
// ran.

func TestParseRequestLineSplitsMethodAndTarget(t *testing.T) {
	method, target, ok := parseRequestLine("GET /a HTTP/1.1\r\n")
	if !ok || method != "GET" || target != "/a" {
		t.Fatalf("ordinary line: %q %q %v", method, target, ok)
	}
}

func TestParseRequestLineIgnoresTokensPastTheSecond(t *testing.T) {
	// Stated, not endorsed: the version token and anything after it is never
	// examined. A second-token target with trailing tokens rides as that second
	// token — which is why a raw space inside a target means the bar's refusal
	// elsewhere has to do the protecting (swqq).
	method, target, ok := parseRequestLine("GET /a b HTTP/1.1\r\n")
	if !ok || method != "GET" || target != "/a" {
		t.Fatalf("extra tokens: %q %q %v", method, target, ok)
	}
}

func TestParseRequestLineRefusesFewerThanTwoTokens(t *testing.T) {
	for _, line := range []string{"", "\r\n", "GET\r\n", "   \n", "CONNECT\n"} {
		if _, _, ok := parseRequestLine(line); ok {
			t.Fatalf("accepted %q", line)
		}
	}
}

func TestParseRequestLineTakesTheSecondTokenNotTheLast(t *testing.T) {
	_, target, ok := parseRequestLine("CONNECT example.com:443 HTTP/1.1\r\n")
	if !ok || target != "example.com:443" {
		t.Fatalf("connect authority: %q %v", target, ok)
	}
}

// FuzzParseRequestLine: whatever the line, an accepted split yields two
// whitespace-free tokens that both occur in the original line, and a refusal
// means the trimmed line genuinely had fewer than two fields.
func FuzzParseRequestLine(f *testing.F) {
	f.Add("GET / HTTP/1.1\r\n")
	f.Add("CONNECT example.com:443 HTTP/1.1\r\n")
	f.Add("GET /a b HTTP/1.1\r\n")
	f.Add("OPTIONS * HTTP/1.1\r\n")
	f.Add("GET\r\n")
	f.Add("\x00\x01 /x Y\r\n")
	f.Add("GET  /spaced   HTTP/1.1\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		method, target, ok := parseRequestLine(line)
		fields := strings.Fields(strings.TrimSpace(line))
		if !ok {
			if len(fields) >= 2 {
				t.Fatalf("refused a line with %d fields: %q", len(fields), line)
			}
			return
		}
		if len(fields) < 2 {
			t.Fatalf("accepted a line with %d fields: %q", len(fields), line)
		}
		if method == "" || target == "" {
			t.Fatalf("empty token from %q", line)
		}
		if strings.ContainsAny(method, " \t\r\n") || strings.ContainsAny(target, " \t\r\n") {
			t.Fatalf("whitespace in tokens: %q %q from %q", method, target, line)
		}
		if method != fields[0] || target != fields[1] {
			t.Fatalf("split disagrees with Fields: %q %q vs %v", method, target, fields)
		}
	})
}
