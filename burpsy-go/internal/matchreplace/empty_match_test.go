package matchreplace

import (
	"bytes"
	"errors"
	"testing"
)

// burpsy-react-ui-wtm2: a blank Match. Burp gives it exactly one meaning — on a request or
// response header rule the replacement is added as a new header line — and every other use is
// refused at NewRule, and again at apply time for a Rule that skipped NewRule.

func mustRule(t *testing.T, target Target, cat Category, match, replace string) *Rule {
	t.Helper()
	r, err := NewRule(target, cat, match, replace, "test")
	if err != nil {
		t.Fatalf("NewRule(%d, %d, %q, %q): %v", target, cat, match, replace, err)
	}
	return r
}

func applyOneRule(r *Rule, dir Direction, raw string) string {
	rs := NewRuleSet()
	rs.SetRules([]*Rule{r})
	return string(rs.Apply(dir, []byte(raw)))
}

// The reported corruption, pinned exactly: before the fix this produced
// "GET / HTTP/1.1\r\nX-A: 1HX-A: 1oX-A: 1s…" — the replacement between every byte of every
// header line, on every proxied request.
func TestBlankHeaderMatchNoLongerInterleavesEveryHeaderLine(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	got := applyOneRule(mustRule(t, TargetRequestHeader, CategoryLiteral, "", "X-A: 1"), DirRequest, raw)
	want := "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nX-A: 1\r\n\r\n"
	if got != want {
		t.Fatalf("blank-match request header rule:\n got %q\nwant %q", got, want)
	}
}

func TestBlankHeaderMatchAddsAHeader(t *testing.T) {
	cases := []struct {
		name      string
		target    Target
		cat       Category
		dir       Direction
		raw, want string
	}{
		{
			name: "request literal, body untouched", target: TargetRequestHeader, cat: CategoryLiteral, dir: DirRequest,
			raw:  "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\nx\r\n\r\ny: 1\r\n",
			want: "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\nX-A: 1\r\n\r\nx\r\n\r\ny: 1\r\n",
		},
		{
			name: "response literal", target: TargetResponseHeader, cat: CategoryLiteral, dir: DirResponse,
			raw:  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			want: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: 1\r\n\r\nok",
		},
		{
			// Blank is "no match" in Burp for regex rules too, not the empty pattern.
			name: "response regex", target: TargetResponseHeader, cat: CategoryRegex, dir: DirResponse,
			raw:  "HTTP/1.1 204 No Content\r\nServer: s\r\n\r\n",
			want: "HTTP/1.1 204 No Content\r\nServer: s\r\nX-A: 1\r\n\r\n",
		},
		{
			name: "no header lines yet", target: TargetRequestHeader, cat: CategoryLiteral, dir: DirRequest,
			raw:  "GET / HTTP/1.1\r\n\r\n",
			want: "GET / HTTP/1.1\r\nX-A: 1\r\n\r\n",
		},
		{
			name: "bare-LF message", target: TargetRequestHeader, cat: CategoryLiteral, dir: DirRequest,
			raw:  "GET / HTTP/1.1\nHost: h\n\nbody",
			want: "GET / HTTP/1.1\nHost: h\nX-A: 1\n\nbody",
		},
		{
			name: "no separator, last line terminated", target: TargetRequestHeader, cat: CategoryLiteral, dir: DirRequest,
			raw:  "GET / HTTP/1.1\r\nHost: h\r\n",
			want: "GET / HTTP/1.1\r\nHost: h\r\nX-A: 1\r\n",
		},
		{
			name: "no separator, last line unterminated", target: TargetRequestHeader, cat: CategoryLiteral, dir: DirRequest,
			raw:  "GET / HTTP/1.1\r\nHost: h",
			want: "GET / HTTP/1.1\r\nHost: h\r\nX-A: 1",
		},
		{
			name: "first line only", target: TargetResponseHeader, cat: CategoryLiteral, dir: DirResponse,
			raw:  "HTTP/1.1 200 OK",
			want: "HTTP/1.1 200 OK\r\nX-A: 1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyOneRule(mustRule(t, tc.target, tc.cat, "", "X-A: 1"), tc.dir, tc.raw)
			if got != tc.want {
				t.Fatalf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// A request header rule does not fire on a response and vice versa, blank or not.
func TestBlankHeaderMatchStaysInItsDirection(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n\r\n"
	if got := applyOneRule(mustRule(t, TargetRequestHeader, CategoryLiteral, "", "X-A: 1"), DirResponse, raw); got != raw {
		t.Fatalf("request header rule changed a response: %q", got)
	}
}

// Empty input has no message to add a header to; the rule does not fire, so Apply hands the
// input back rather than inventing a header block.
func TestBlankHeaderMatchOnEmptyInputDoesNotFire(t *testing.T) {
	if got := applyOneRule(mustRule(t, TargetRequestHeader, CategoryLiteral, "", "X-A: 1"), DirRequest, ""); got != "" {
		t.Fatalf("blank-match rule on empty input = %q, want empty", got)
	}
}

// The replacement of a blank-match header rule becomes one header line verbatim, so a value
// that cannot be one is refused at NewRule — and a Rule that never went through NewRule is
// inert at apply time rather than reaching the bytes.
func TestBlankHeaderMatchRefusesAReplacementThatIsNotOneHeaderLine(t *testing.T) {
	for _, target := range []Target{TargetRequestHeader, TargetResponseHeader} {
		for _, cat := range []Category{CategoryLiteral, CategoryRegex} {
			for _, repl := range []string{"", "X-A: 1\r\nX-B: 2", "X-A: 1\n", "\r\n", "X-A: 1\rX", " folded", "\tfolded"} {
				_, err := NewRule(target, cat, "", repl, "")
				if !errors.Is(err, ErrEmptyMatch) {
					t.Errorf("NewRule(target %d, cat %d, blank, %q) err = %v, want ErrEmptyMatch", target, cat, repl, err)
				}
				dir := DirRequest
				raw := "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
				if target == TargetResponseHeader {
					dir, raw = DirResponse, "HTTP/1.1 200 OK\r\nServer: s\r\n\r\n"
				}
				bypass := &Rule{Enabled: true, Target: target, Category: cat, StringReplace: repl}
				if got := applyOneRule(bypass, dir, raw); got != raw {
					t.Errorf("unvalidated blank rule with replacement %q rewrote the message to %q", repl, got)
				}
			}
		}
	}
}

// Every target but the two header targets refuses a blank match, literal or regex: without the
// refusal a blank literal (or an empty regex) matches between every byte and the section is
// rewritten into interleaved garbage. Each case also proves the apply-time guard against a Rule
// built without NewRule, on input where the unguarded primitive would have fired.
func TestBlankMatchIsRefusedForEveryNonHeaderTarget(t *testing.T) {
	cases := []struct {
		target Target
		dir    Direction
		raw    string
	}{
		{TargetRequestBody, DirRequest, "POST / HTTP/1.1\r\nHost: h\r\n\r\nbody"},
		{TargetResponseBody, DirResponse, "HTTP/1.1 200 OK\r\n\r\nbody"},
		{TargetRequestFirstLine, DirRequest, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"},
		{TargetRequestParamName, DirRequest, "GET /?a=1&=2& HTTP/1.1\r\nHost: h\r\n\r\n"},
		{TargetRequestParamValue, DirRequest, "GET /?a=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n"},
		{TargetWebSocketToServer, DirWebSocketToServer, "frame payload"},
		{TargetWebSocketToClient, DirWebSocketToClient, "frame payload"},
	}
	if len(cases) != TargetCount-2 {
		t.Fatalf("cases cover %d targets, want every target but the two header ones (%d)", len(cases), TargetCount-2)
	}
	for _, tc := range cases {
		for _, cat := range []Category{CategoryLiteral, CategoryRegex} {
			if _, err := NewRule(tc.target, cat, "", "X", ""); !errors.Is(err, ErrEmptyMatch) {
				t.Errorf("NewRule(target %d, cat %d, blank) err = %v, want ErrEmptyMatch", tc.target, cat, err)
			}
			bypass := &Rule{Enabled: true, Target: tc.target, Category: cat, StringReplace: "X"}
			if got := applyOneRule(bypass, tc.dir, tc.raw); got != tc.raw {
				t.Errorf("unvalidated blank rule (target %d, cat %d) rewrote %q to %q", tc.target, cat, tc.raw, got)
			}
		}
	}
}

// Non-blank rules on every section behave as before: header lines matched and rewritten in place
// and dropped when rewritten to nothing, body and first line substring-rewritten. The one
// deliberate change is the regex header case: on master a regex rule rewriting a whole header
// line to nothing left the line in (see regexReplaceAll).
func TestNonBlankRulesAreUnchanged(t *testing.T) {
	cases := []struct {
		name      string
		rule      *Rule
		dir       Direction
		raw, want string
	}{
		{"header literal", mustRule(t, TargetRequestHeader, CategoryLiteral, "example.com", "other.test"), DirRequest,
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nexample.com", "GET / HTTP/1.1\r\nHost: other.test\r\n\r\nexample.com"},
		{"header regex drops line", mustRule(t, TargetResponseHeader, CategoryRegex, `^Server: .*$`, ""), DirResponse,
			"HTTP/1.1 200 OK\r\nServer: x\r\nA: b\r\n\r\n", "HTTP/1.1 200 OK\r\nA: b\r\n\r\n"},
		{"header literal drops line", mustRule(t, TargetResponseHeader, CategoryLiteral, "Server: x", ""), DirResponse,
			"HTTP/1.1 200 OK\r\nServer: x\r\nA: b\r\n\r\n", "HTTP/1.1 200 OK\r\nA: b\r\n\r\n"},
		// regexp.ReplaceAll answers nil for an all-matched input rewritten to nothing, which every
		// applier reads as "did not fire"; regexReplaceAll is what keeps these two from being no-ops.
		{"websocket regex blanks the whole message", mustRule(t, TargetWebSocketToClient, CategoryRegex, `^ping$`, ""), DirWebSocketToClient,
			"ping", ""},
		{"body literal", mustRule(t, TargetResponseBody, CategoryLiteral, "foo", "bar"), DirResponse,
			"HTTP/1.1 200 OK\r\nfoo: 1\r\n\r\nfoo foo", "HTTP/1.1 200 OK\r\nbar: 1\r\n\r\nbar bar"},
		{"first line", mustRule(t, TargetRequestFirstLine, CategoryLiteral, "HTTP/1.1", "HTTP/1.0"), DirRequest,
			"GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET / HTTP/1.0\r\nHost: h\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyOneRule(tc.rule, tc.dir, tc.raw); got != tc.want {
				t.Fatalf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The added header is visible to Content-Length fix-up as a header, not as body: with
// update_content_length on, the body length is unchanged.
func TestBlankHeaderMatchDoesNotDisturbContentLength(t *testing.T) {
	rs := NewRuleSet()
	rs.SetRules([]*Rule{mustRule(t, TargetResponseHeader, CategoryLiteral, "", "X-A: 1")})
	rs.SetUpdateContentLength(true)
	out := rs.Apply(DirResponse, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	if !bytes.Equal(out, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: 1\r\n\r\nok")) {
		t.Fatalf("got %q", out)
	}
}
