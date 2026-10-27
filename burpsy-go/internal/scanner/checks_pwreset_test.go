package scanner

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

var pwrRows = []string{pwrTokenInResponse, pwrPredictable, pwrLowEntropy, pwrReusable, pwrNoExpiry,
	pwrInsecureLink, pwrReferer, pwrPoisoning, pwrNoRateLimit, IssueUsernameEnumeration}

// Every reset variant reports exactly the password-reset rows its defect explains — the planted row,
// plus the http:// link every cleartext variant mails and the missing rate limit every variant but
// safe-rate has — and nothing else of the family. This is the cross-row half the per-row manifest
// assertions cannot see: a safe twin of one row reporting another.
func TestPasswordResetRowsPerVariant(t *testing.T) {
	rt := startRuntimeTarget(t)
	// leak answers a known address with its token and an unknown one without: that is enumeration too.
	want := map[string][]string{
		"leak":                {pwrTokenInResponse, pwrInsecureLink, pwrNoRateLimit, IssueUsernameEnumeration},
		"clock":               {pwrPredictable, pwrInsecureLink, pwrNoRateLimit},
		"weak":                {pwrLowEntropy, pwrInsecureLink, pwrNoRateLimit},
		"reuse":               {pwrReusable, pwrInsecureLink, pwrNoRateLimit},
		"jwt":                 {pwrNoExpiry, pwrInsecureLink, pwrNoRateLimit},
		"poison":              {pwrPoisoning, pwrInsecureLink, pwrNoRateLimit},
		"plain":               {pwrInsecureLink, pwrNoRateLimit},
		"referer":             {pwrReferer, pwrInsecureLink, pwrNoRateLimit},
		"referer-script":      {pwrReferer, pwrInsecureLink, pwrNoRateLimit},
		"enum":                {IssueUsernameEnumeration, pwrInsecureLink, pwrNoRateLimit},
		"rate":                {pwrInsecureLink, pwrNoRateLimit},
		"safe-leak":           {pwrInsecureLink, pwrNoRateLimit},
		"safe-pred":           {pwrInsecureLink, pwrNoRateLimit},
		"safe-entropy":        {pwrInsecureLink, pwrNoRateLimit},
		"safe-reuse":          {pwrInsecureLink, pwrNoRateLimit},
		"safe-jwt":            {pwrInsecureLink, pwrNoRateLimit},
		"safe-poison":         {pwrInsecureLink, pwrNoRateLimit},
		"safe-plain":          {pwrNoRateLimit},
		"safe-referer":        {pwrInsecureLink, pwrNoRateLimit},
		"safe-referer-script": {pwrInsecureLink, pwrNoRateLimit},
		"safe-enum":           {pwrInsecureLink, pwrNoRateLimit},
	}
	// safe-rate throttles by address, and every other check of the audit re-sends the captured request
	// too, so whether the reset check's own first request still gets a token depends on timing. Only
	// the rows its throttle answers are pinned: absent. TestPasswordResetRateNeedsDeliveryAndNoThrottle
	// pins the guard itself.
	absentOnly := map[string][]string{"safe-rate": {pwrNoRateLimit, IssueUsernameEnumeration}}
	seen := 0
	for _, e := range vulnapp.Vulnerabilities() {
		if !strings.HasPrefix(e.Path, "/pwreset/") {
			continue
		}
		variant := strings.TrimSuffix(strings.TrimPrefix(e.Path, "/pwreset/"), "/request")
		exp, ok := want[variant]
		absent, onlyAbsent := absentOnly[variant]
		if !ok && !onlyAbsent {
			t.Fatalf("variant %q has no expectation here", variant)
		}
		seen++
		e := e
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			if e.DOM && !rt.chrome {
				domexectest.Skip(t, "no Chrome on PATH: this browser-observed variant is untested")
			}
			got := rt.findingsFor(t, e.Path, e.DOM)
			if onlyAbsent {
				for _, r := range absent {
					if f := got[r]; f != nil {
						t.Errorf("%s (%s): %q reported: %s", e.Path, e.Note, r, f.Evidence)
					}
				}
				return
			}
			var have []string
			for _, r := range pwrRows {
				if got[r] != nil {
					have = append(have, r)
				}
			}
			sort.Strings(have)
			w := append([]string(nil), exp...)
			sort.Strings(w)
			if strings.Join(have, "|") != strings.Join(w, "|") {
				var ev []string
				for _, r := range have {
					ev = append(ev, r+": "+got[r].Evidence)
				}
				t.Errorf("%s (%s): password-reset rows %v, want %v\nevidence:\n  %s", e.Path, e.Note, have, w,
					strings.Join(ev, "\n  "))
			}
		})
	}
	if seen != len(want)+len(absentOnly) {
		t.Fatalf("exercised %d variants, expectations cover %d", seen, len(want))
	}
}

// An identity the operator did not list is never acted on, and a reset-looking request with no
// identity configured reports the missing input instead of a clean result.
func TestPasswordResetActsOnlyOnDeclaredIdentities(t *testing.T) {
	raw := "POST /account/forgot HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n" +
		`{"email":"victim@corp.test"}`
	if id, resetish := pwrIdentityIn(raw, []string{"tester@corp.test"}); id != "" || !resetish {
		t.Fatalf("got identity %q resetish=%v, want none and a reset candidate", id, resetish)
	}
	if id, _ := pwrIdentityIn(raw, []string{"VICTIM@corp.test"}); id != "VICTIM@corp.test" {
		t.Fatalf("a listed identity was not recognised: %q", id)
	}
	login := "POST /login HTTP/1.1\r\nHost: t\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 40\r\n\r\n" +
		"email=victim%40corp.test&password=hunter2"
	if id, resetish := pwrIdentityIn(login, []string{"victim@corp.test"}); id != "" || resetish {
		t.Fatalf("a login request (password parameter) was taken for a reset request: %q %v", id, resetish)
	}

	store := core.NewTrafficStore()
	reqID, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{ID: 1, Host: "t", Port: 80, Method: "POST", Path: "/account/forgot", Request: &reqID}
	store.AddExchange(ex)
	s := NewActiveScanner(store, zap.NewNop()) // no sender: any probe attempt would fail with "no sender"
	cc := &CheckContext{Scanner: s, Exchange: ex, Config: &ScanConfig{CheckPasswordReset: true}}
	_, err = checkPasswordReset(context.Background(), cc)
	if err == nil || !errors.Is(err, errCapabilityMissing) || !strings.Contains(err.Error(), "no test identity") {
		t.Fatalf("got %v, want the missing-identity capability error", err)
	}
	cc.Config.ResetTestIdentities = []string{"tester@corp.test"}
	if f, err := checkPasswordReset(context.Background(), cc); err != nil || len(f) != 0 {
		t.Fatalf("an unlisted identity was acted on: %v %v", f, err)
	}
}

// The clock and counter models predict only the token the model produces, inside the window.
func TestPasswordResetPredictionNeedsTheNextToken(t *testing.T) {
	now := time.Now().Unix()
	enc := func(n int64) string {
		return base64.RawURLEncoding.EncodeToString([]byte("u7:" + strconv.FormatInt(n, 10)))
	}
	vals := []string{enc(now - 5), enc(now - 4), enc(now - 3)}
	m := pwrNumericModel(vals)
	if m == nil || m.encoding != "base64url" {
		t.Fatalf("no base64url clock model from %v: %+v", vals, m)
	}
	if _, ok := pwrInPrediction(m, vals, now-1, now+4, enc(now)); !ok {
		t.Error("the token inside the predicted window was not accepted")
	}
	if _, ok := pwrInPrediction(m, vals, now-1, now+4, enc(now+60)); ok {
		t.Error("a token outside the predicted window was accepted")
	}
	if _, ok := pwrInPrediction(m, vals, now-1, now+4, base64.RawURLEncoding.EncodeToString([]byte("u8:"+strconv.FormatInt(now, 10)))); ok {
		t.Error("a token with a different template was accepted")
	}
	// Random digits have a model (one varying field) but no step: never a counter.
	if r := pwrNumericModel([]string{"rst-48211", "rst-03977", "rst-71520"}); r == nil || r.digits != 5 {
		t.Fatalf("no digits model for random codes: %+v", r)
	}
}

func TestPasswordResetKeyspace(t *testing.T) {
	if ks, _ := pwrKeyspace([]string{"weak-1234", "weak-9876", "weak-5555", "weak-1029"}); ks != 1e4 {
		t.Errorf("4 decimal digits: keyspace %v, want 1e4", ks)
	}
	strong := []string{"9f86d081884c7d659a2feaa0c55ad015", "a3f1c0e2b4d5968771aa02be3c9d4e1f",
		"07c1ab33de5f4c2a9b8e6d1f0a2b3c4d", "5e2d7c9b1a0f3e4d6c8b2a1f0e9d7c6b"}
	if ks, _ := pwrKeyspace(strong); ks <= pwrMaxKeyspace {
		t.Errorf("128-bit hex tokens: keyspace %v reported as small", ks)
	}
}

func TestPasswordResetEffectiveReferrerPolicy(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nReferrer-Policy: no-referrer, unsafe-url\r\n\r\n"
	if p, from := pwrEffectivePolicy(resp, "<html></html>"); p != "unsafe-url" || from != "Referrer-Policy header" {
		t.Errorf("last recognised header token: got %s from %s", p, from)
	}
	if p, _ := pwrEffectivePolicy(resp, `<meta name="referrer" content="no-referrer">`); p != "no-referrer" {
		t.Errorf("the meta referrer is applied after the header: got %s", p)
	}
	if p, _ := pwrEffectivePolicy("HTTP/1.1 200 OK\r\n\r\n", "<p>"); pwrPolicyLeaksURL(p) {
		t.Errorf("the browser default %s was taken to leak the full URL", p)
	}
}

func TestPasswordResetTokensInText(t *testing.T) {
	mail := `<a href="https://app.test/reset?uid=7&amp;token=Zx81kQ">reset</a>`
	got := pwrTokensInText(mail)
	if len(got) != 1 || got[0].value != "Zx81kQ" || got[0].param != "token" || got[0].link != "https://app.test/reset?uid=7&token=Zx81kQ" {
		t.Fatalf("got %+v", got)
	}
	js := `{"message":"sent","data":{"resetToken":"abcd1234"},"next":"https://app.test/x"}`
	got = pwrTokensInText(js)
	if len(got) != 1 || got[0].value != "abcd1234" || got[0].param != "resetToken" {
		t.Fatalf("got %+v", got)
	}
}

// The rate verdict needs every reset request to have delivered a message and none to be throttled;
// each guard alone keeps it undecided.
func TestPasswordResetRateNeedsDeliveryAndNoThrottle(t *testing.T) {
	ok := func() *pwrIssuance {
		return &pwrIssuance{resp: ProbeResponse{Status: 200, Body: `{"message":"If the account exists, a link was sent"}`},
			mailText: "Reset: https://app.test/r?token=x"}
	}
	run := func(mut func([]*pwrIssuance)) bool {
		p := &pwrProber{}
		for i := 0; i < pwrRateMin; i++ {
			p.issued = append(p.issued, ok())
		}
		if mut != nil {
			mut(p.issued)
		}
		return p.rateUndecided()
	}
	if run(nil) {
		t.Fatal("ten delivered, unthrottled requests were left undecided")
	}
	if !run(func(is []*pwrIssuance) { is[7].mailText = "" }) {
		t.Error("a request that delivered nothing (a silent limit) was not treated as undecided")
	}
	if !run(func(is []*pwrIssuance) {
		is[6].resp = ProbeResponse{Status: 200, Body: `{"error":"Too many reset requests, try again later"}`}
	}) {
		t.Error("a throttled answer (HTTP 200, wording) was not treated as undecided")
	}
	if !run(func(is []*pwrIssuance) { is[3].resp = ProbeResponse{Status: 429} }) {
		t.Error("an HTTP 429 answer was not treated as undecided")
	}
}

// Enumeration through the reset form needs a stable difference between the declared identity and
// invented ones that is not a throttle and not the echoed address.
func TestPasswordResetEnumerationNeedsAStableUnthrottledDifference(t *testing.T) {
	const me = "me@corp.test"
	run := func(t *testing.T, answer func(email string) string) *Finding {
		t.Helper()
		cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, answer(r.URL.Query().Get("email")))
		}, "/forgot?email="+url.QueryEscape(me))
		cc.Config = &ScanConfig{CheckPasswordReset: true, ResetTestIdentities: []string{me}}
		raw := requestRaw(cc.Scanner, cc.Exchange)
		p := &pwrProber{cc: cc, raw: raw, identity: me}
		h, err := NewProbeHarness(context.Background(), cc, []string{"query", "body"})
		if err != nil {
			t.Fatal(err)
		}
		p.h = h
		base := h.Baseline()
		first, err := p.issue(context.Background(), raw, &base, false)
		if err != nil {
			t.Fatal(err)
		}
		f, err := p.enumeration(context.Background(), first)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	generic := `{"message":"If the account exists, a link was sent to %s"}`
	t.Run("not found for unknown", func(t *testing.T) {
		f := run(t, func(e string) string {
			if e == me {
				return fmt.Sprintf(generic, e)
			}
			return `{"error":"No account found for ` + e + `"}`
		})
		if f == nil || f.Name != IssueUsernameEnumeration {
			t.Fatalf("a not-found answer for invented identities was not reported: %+v", f)
		}
	})
	t.Run("same answer echoing the address", func(t *testing.T) {
		if f := run(t, func(e string) string { return fmt.Sprintf(generic, e) }); f != nil {
			t.Fatalf("an identical answer that echoes the address was reported: %s", f.Evidence)
		}
	})
	t.Run("known identity throttled", func(t *testing.T) {
		f := run(t, func(e string) string {
			if e == me {
				return `{"error":"Too many reset requests for this account, try again later"}`
			}
			return fmt.Sprintf(generic, e)
		})
		if f != nil {
			t.Fatalf("a per-account throttle was reported as enumeration: %s", f.Evidence)
		}
	})
}
