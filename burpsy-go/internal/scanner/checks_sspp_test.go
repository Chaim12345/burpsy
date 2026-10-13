package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// The server-side parameter pollution check (burpsy-react-ui-0vzb.3) against vulnapp's SSPP family,
// whose fronts call in-process internal APIs. Each safe twin below is kept quiet by one named guard,
// and the trace assertions show that guard is what decided it (not an inert parameter or a probe that
// never landed):
//
//   - /sspp/safe/path/file: a dot-segment walk is equivalent, but no URL delimiter is structural, so
//     the REST-path rule's second structural probe is missing;
//   - /sspp/safe/path/normalise: every delimiter probe answers like the original value, but its
//     literal control is refused, so the literal control does not answer like a plain value;
//   - /sspp/safe/validator/query: every delimiter is structural and none is equivalent, and the
//     unknown parameter and the repeated name are refused with the same message;
//   - /sspp/safe/json/echo: the injected member comes back, but the bare quote breaks the response
//     document itself;
//   - /sspp/safe/json/cut: the injected member's probe is equivalent, but so is the bare quote;
//   - /sspp/safe/query/delete-alias: the destructive-path gate sends nothing;
//   - /sspp/safe/path/fetch: a parameter whose value is itself a URL is not probed.

func ssppAudit(t *testing.T, path string) ([]*Finding, uint32) {
	t.Helper()
	rt := startRuntimeTarget(t)
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckServerSideParamPollution: true}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, findings := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	return findings, outcome.RequestsSent
}

func ssppFindingIn(fs []*Finding) *Finding {
	for _, f := range fs {
		if f != nil && (f.Name == IssueSSPPQuery || f.Name == IssueSSPPPath || f.Name == IssueSSPPJSON) {
			return f
		}
	}
	return nil
}

// ssppTraced audits path with the trace hook on and returns the findings and the first-round and held
// outcomes for its parameter.
func ssppTraced(t *testing.T, path, param string) ([]*Finding, uint32, map[string]*ssppOutcome, map[string]*ssppOutcome) {
	t.Helper()
	var mu sync.Mutex
	var first, held map[string]*ssppOutcome
	route, _, _ := strings.Cut(path, "?")
	ssppTrace = func(target, p string, f, h map[string]*ssppOutcome) {
		if p != param || !strings.Contains(target, route) {
			return
		}
		mu.Lock()
		first, held = f, h
		mu.Unlock()
	}
	defer func() { ssppTrace = nil }()
	fs, sent := ssppAudit(t, path)
	mu.Lock()
	defer mu.Unlock()
	return fs, sent, first, held
}

func TestSSPPFindsEachTechnique(t *testing.T) {
	cases := []struct {
		path, param, row, certainty string
		mustSay                     []string
	}{
		// First duplicate wins, unknown parameters refused, field required (PortSwigger's query-string lab).
		{"/sspp/query/search?name=carlos", "name", IssueSSPPQuery, "firm", []string{
			"repeats the parameter after the original value", "answered exactly like the original value",
			"`#` truncates", "Field not specified", "Parameter is not supported", `"carlos%26name%3D`}},
		// Last duplicate wins, unknown ignored, field optional.
		{"/sspp/query/lookup", "username", IssueSSPPQuery, "firm", []string{
			"adds an internal query parameter", "with the original value after a random one"}},
		// Strict: nothing equivalent; the unknown parameter and the repeated name are refused differently.
		{"/sspp/query/strict?name=carlos", "name", IssueSSPPQuery, "tentative", []string{
			"Parameter is not supported", "Duplicate parameter"}},
		// REST path: the walk is cleaned away, ? and # leave an unknown route.
		{"/sspp/path/user?name=carlos", "name", IssueSSPPPath, "firm", []string{
			"walks the internal path", "ends the internal path", "Invalid route", "carlos%2F"}},
		// JSON, reflected member.
		{"/sspp/json/profile", "name", IssueSSPPJSON, "firm", []string{"returned a separate JSON member"}},
		// JSON, ignored member equivalent, bare quote breaks the internal document.
		{"/sspp/json/lookup", "user", IssueSSPPJSON, "firm", []string{
			"adds a member to the internal JSON document", "answered exactly like the original value",
			"Malformed JSON in internal request"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, sent := ssppAudit(t, c.path)
			f := ssppFindingIn(fs)
			if f == nil {
				t.Fatalf("no server-side parameter pollution finding (%d requests sent)", sent)
			}
			if f.Name != c.row || f.Confidence != c.certainty || f.Param != c.param {
				t.Fatalf("got %q/%s on %q, want %q/%s on %q\n%s", f.Name, f.Confidence, f.Param,
					c.row, c.certainty, c.param, f.Evidence)
			}
			t.Logf("%s, %s, %d requests\n%s\n%s", f.Name, f.Confidence, sent, f.Description, f.Evidence)
			for _, s := range c.mustSay {
				if !strings.Contains(f.Evidence, s) {
					t.Errorf("evidence lacks %q:\n%s", s, f.Evidence)
				}
			}
			if sent > ssppMaxSends+20 {
				t.Errorf("sent %d requests, over the check's budget", sent)
			}
		})
	}
}

func TestSSPPStaysQuietOnTheSafeTwins(t *testing.T) {
	type outcomes = map[string]*ssppOutcome
	st := func(m outcomes, id string) bool { return m[id] != nil && m[id].structural }
	eq := func(m outcomes, id string) bool { return m[id] != nil && m[id].equivalent }
	cases := []struct {
		path, param string
		// notProbed marks a parameter the check must leave alone (a URL value).
		notProbed bool
		// why asserts the guard that decided it, on the first-round and held outcomes.
		why func(t *testing.T, first, held outcomes)
	}{
		{"/sspp/safe/query/search?name=carlos", "name", false, func(t *testing.T, first, held outcomes) {
			if len(held) != 0 {
				t.Errorf("an encoded value made probes structural: %v", ssppIDs(held))
			}
		}},
		{"/sspp/safe/query/lookup", "username", false, nil},
		{"/sspp/safe/query/strict?name=carlos", "name", false, nil},
		{"/sspp/safe/query/truncate?name=carlos", "name", false, func(t *testing.T, first, _ outcomes) {
			if st(first, ssppQAmp) || st(first, ssppHash) {
				t.Error("the probe and its literal control are cut alike, yet a probe was structural")
			}
		}},
		{"/sspp/safe/path/user?name=carlos", "name", false, nil},
		{"/sspp/safe/path/file?name=carlos", "name", false, func(t *testing.T, first, held outcomes) {
			if !eq(held, ssppPDot) || st(held, ssppPQuery) || st(held, ssppHash) {
				t.Errorf("want only the dot-segment walk equivalent; held %v", ssppIDs(held))
			}
		}},
		{"/sspp/safe/path/normalise?name=carlos", "name", false, func(t *testing.T, first, _ outcomes) {
			o := first[ssppPDot]
			if o == nil || o.structural || o.equivalent {
				t.Fatalf("the dot-segment walk should be stopped by its refused literal control")
			}
			if a, b := ssppTestView(o.P), ssppTestView(o.C); a == b {
				t.Errorf("the probe and its literal control answered alike, so this twin tests nothing")
			}
		}},
		{"/sspp/safe/path/fetch?src=https%3A%2F%2Fcdn.example.test%2Flogo.png", "src", true, nil},
		{"/sspp/safe/validator/path?name=carlos", "name", false, func(t *testing.T, _, held outcomes) {
			if !st(held, ssppPDot) || eq(held, ssppPDot) || eq(held, ssppPQuery) {
				t.Errorf("want the delimiters structural and none equivalent; held %v", ssppIDs(held))
			}
		}},
		{"/sspp/safe/validator/query?name=carlos", "name", false, func(t *testing.T, _, held outcomes) {
			if !st(held, ssppQAmp) || !st(held, ssppQFirst) || eq(held, ssppQAmp) || eq(held, ssppQFirst) {
				t.Errorf("want the unknown and repeated parameters structural, not equivalent; held %v", ssppIDs(held))
			}
		}},
		{"/sspp/safe/json/profile", "name", false, nil},
		{"/sspp/safe/json/lookup", "user", false, nil},
		{"/sspp/safe/json/echo", "name", false, func(t *testing.T, first, held outcomes) {
			if held[ssppJField] == nil || !held[ssppJField].field {
				t.Fatalf("the concatenated response should carry the injected member; held %v", ssppIDs(held))
			}
			if q := first[ssppJQuote]; q == nil || ssppDocumentIntact(q.P.Body) {
				t.Error("the bare quote should have broken the response document")
			}
		}},
		{"/sspp/safe/json/cut", "name", false, func(t *testing.T, first, held outcomes) {
			if !eq(held, ssppJField) || !eq(first, ssppJQuote) {
				t.Errorf("want the member probe and the bare quote both equivalent; first %v held %v",
					ssppIDs(first), ssppIDs(held))
			}
		}},
		{"/sspp/safe/validator/json", "name", false, nil},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			fs, sent, first, held := ssppTraced(t, c.path, c.param)
			if f := ssppFindingIn(fs); f != nil {
				t.Fatalf("reported %q (%s) on a safe twin:\n%s", f.Name, f.Confidence, f.Evidence)
			}
			if c.notProbed {
				if first != nil {
					t.Fatalf("parameter %q should not have been probed", c.param)
				}
				return
			}
			if first == nil {
				t.Fatalf("parameter %q was never decided (%d requests): silence here proves nothing", c.param, sent)
			}
			if c.why != nil {
				c.why(t, first, held)
			}
		})
	}
}

// The destructive-path gate: the vulnerable search behind a path naming a delete gets no probe.
func TestSSPPDoesNotProbeADestructivePath(t *testing.T) {
	fs, sent, first, _ := ssppTraced(t, "/sspp/safe/query/delete-alias?name=carlos", "name")
	if f := ssppFindingIn(fs); f != nil || first != nil {
		t.Fatalf("a destructive path was probed (%d requests): %v", sent, f)
	}
	if !ssppProbeable("GET /sspp/query/search?name=x HTTP/1.1\r\n\r\n") ||
		ssppProbeable("PUT /sspp/query/search?name=x HTTP/1.1\r\n\r\n") ||
		ssppProbeable("POST /account/remove HTTP/1.1\r\n\r\n") {
		t.Error("ssppProbeable gates the wrong requests")
	}
}

// A POST that would send mail — by its path or by a parameter name — gets no request at all from the
// check: re-sending it ~30 times would mail a real address ~30 times. Both twins front the vulnerable
// lookup, so without the gate each is found.
func TestSSPPSendsNothingToAMailSendingPost(t *testing.T) {
	for _, path := range []string{"/sspp/safe/query/forgot-password", "/sspp/safe/query/account"} {
		t.Run(path, func(t *testing.T) {
			startRuntimeTarget(t) // seeded (one capture request each) before counting
			before := vulnapp.SSPPMailRequests()
			fs, sent := ssppAudit(t, path)
			if got := vulnapp.SSPPMailRequests() - before; got != 0 || sent != 0 {
				t.Fatalf("the mail-sending POST received %d request(s) (engine counted %d); want 0", got, sent)
			}
			if f := ssppFindingIn(fs); f != nil {
				t.Fatalf("reported %q without sending anything?", f.Name)
			}
		})
	}
	for raw, want := range map[string]bool{
		"POST /sspp/x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=a":         true,
		"POST /forgot-password HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nu=a":   false,
		"POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemailAddress=a":      false,
		"POST /x HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"phone\":\"1\",\"sms_code\":\"2\"}": false,
		"GET /forgot-password?username=a HTTP/1.1\r\n\r\n":                                               true,
	} {
		if got := ssppProbeable(raw); got != want {
			t.Errorf("ssppProbeable(%q) = %v, want %v", raw, got, want)
		}
	}
}

// The switch alone admits the check, through the descriptor it rides.
func TestSSPPRidesTheClientSideHPPDescriptor(t *testing.T) {
	for _, d := range NativeCheckRegistry() {
		if d.Name != "Client-side HTTP parameter pollution (reflected)" {
			continue
		}
		if !d.Enabled(&ScanConfig{CheckServerSideParamPollution: true}) {
			t.Fatal("check_server_side_parameter_pollution does not admit the descriptor")
		}
		if d.Enabled(&ScanConfig{}) {
			t.Fatal("the descriptor is admitted with every switch off")
		}
		return
	}
	t.Fatal("descriptor not registered")
}

func ssppTestView(r ProbeResponse) string {
	p := &ssppProber{}
	v := p.view(r)
	return v.body + "|" + v.location
}

func ssppIDs(m map[string]*ssppOutcome) []string {
	var out []string
	for id, o := range m {
		tag := id
		switch {
		case o.equivalent:
			tag += "=eq"
		case o.structural:
			tag += "=st"
		case o.field:
			tag += "=field"
		}
		out = append(out, tag)
	}
	return out
}
