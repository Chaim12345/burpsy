package scanner

// The capability contract, enforced over every wired row rather than per check.
//
// CheckRunner's own doc states the rule this file polices: "a nil finding slice is a clean
// result, not an implicit unsupported result." A check that needs the network, a browser, a
// stored-canary ledger or a session and does not have one must therefore return an *error*.
// Returning (nil, nil) claims the check looked and the target was clean, which is the exact
// dishonest outcome the project forbids — and it is invisible in a report, because the row
// counts as runnable and contributes zero findings just like a genuinely clean target.
//
// Two properties are asserted for all 183 rows, and one more for the families that cannot
// work without a capability:
//
//  1. No row panics on a minimal exchange with no capabilities attached. This is the failure
//     mode wiring-without-tests actually produces: a nil-pointer dereference on cc.Sender.
//  2. No row invents a finding from an empty, uninteresting exchange. Every finding here
//     would be a false positive with nothing to point at.
//  3. Rows in the network- and capability-dependent families must return an error when the
//     capability is absent, never (nil, nil).
//
// This is a contract test, not a substitute for behavioural tests: it proves a row cannot lie
// about a capability it lacks, not that it detects anything. The per-family behavioural files
// carry that half.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// bareContext builds a CheckContext over a deliberately WELL-CONFIGURED exchange, with no
// sender, browser, stored ledger, session coordinator or provenance ledger attached.
//
// Hardened, not minimal. The first version of this fixture served a bare `200 OK` over port 80
// and five passive rows correctly reported findings against it — no CSP, no X-Frame-Options, no
// charset, no TLS. Those were true statements about the fixture, which made "reports nothing"
// the wrong property to assert. A response that is actually secure is what lets the absence of
// findings mean something: anything reported here is a false positive with nothing to point at.
func bareContext(t *testing.T) *CheckContext {
	t.Helper()
	store := core.NewTrafficStore()
	req := "GET / HTTP/1.1\r\n" +
		"Host: app.test\r\n" +
		"Referer: https://app.test/\r\n" +
		"\r\n"
	reqID, err := store.Put([]byte(req), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
		"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; base-uri 'self'\r\n" +
		"X-Frame-Options: DENY\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Referrer-Policy: strict-origin-when-cross-origin\r\n" +
		"Cache-Control: no-store, private\r\n" +
		"Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/\r\n" +
		"\r\n" +
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>ok</title></head>" +
		"<body><p>nothing to see</p></body></html>"
	respID, err := store.Put([]byte(resp), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: "app.test", Port: 443,
		TLS: true, Method: "GET", Path: "/"}
	store.AddExchange(ex)
	// Every per-family switch on, so no row is skipped by its own gate: the point is to reach
	// each evaluator, and a row that never runs proves nothing here.
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(allChecksOn())
	return NewCheckContext(scan, ex, nil)
}

// allChecksOn turns on every per-family switch. Kept as one place so a new family added to
// ScanConfig without being listed here shows up as a row this contract silently stopped
// covering — see TestEveryWiredRowIsReachedByTheCapabilityContract.
func allChecksOn() *ScanConfig {
	return &ScanConfig{
		MaxConcurrency:          1,
		CheckSqli:               true,
		CheckXss:                true,
		CheckPathTraversal:      true,
		CheckSSRF:               true,
		CheckXXE:                true,
		CheckJwtWeak:            true,
		CheckJSVulns:            true,
		CheckHeaders:            true,
		CheckCachePoisoning:     true,
		CheckReflectionProbes:   true,
		CheckHostDiscovery:      true,
		CheckResponseDependence: true,
		CheckPassivePosture:     true,
		CheckPassiveAnalysis:    true,
		CheckActiveInjection:    true,
		CheckDOM:                true,
		CheckStored:             true,
		CheckExtendedActive:     true,
		// Without this the five collaborator rows are absent from every contract assertion in
		// this file, which would exempt them from the refusal rules rather than test them.
		CheckOutOfBand:        true,
		CheckExtendedCoverage: true,
	}
}

// capabilityDependentFamilies names the descriptor sets whose rows cannot produce an honest
// verdict without a capability the bare context deliberately withholds.
func capabilityDependentFamilies() map[string][]CheckDescriptor {
	return map[string][]CheckDescriptor{
		"injection": InjectionCheckDescriptors(),
		"dom":       DOMCheckDescriptors(),
		"dom-extra": DOMExtraCheckDescriptors(),
		"stored":    StoredCheckDescriptors(),
		"remaining": RemainingCheckDescriptors(),
		"final":     FinalCheckDescriptors(),
	}
}

// Property 1 and 2, over the whole registry.
func TestNoWiredRowPanicsOrInventsAFindingWithoutCapabilities(t *testing.T) {
	rows := NativeCheckRegistry()
	if len(rows) == 0 {
		t.Fatal("empty registry")
	}
	var checked int
	for _, d := range rows {
		if !d.Runnable() {
			continue
		}
		checked++
		d := d
		t.Run(d.Name, func(t *testing.T) {
			cc := bareContext(t)
			var findings []*Finding
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked on a bare exchange with no capabilities: %v", r)
					}
				}()
				findings, err = d.Run(context.Background(), cc)
			}()
			if len(findings) != 0 {
				t.Errorf("reported %d finding(s) from an empty exchange with nothing to detect: %s",
					len(findings), describeFindings(findings))
			}
			// An error is fine and expected for capability-dependent rows; what is not fine is
			// an error with nothing in it, which tells an operator nothing about why.
			if err != nil && strings.TrimSpace(err.Error()) == "" {
				t.Error("returned an empty error; a refusal has to say what was missing")
			}
		})
	}
	if checked != len(rows) {
		t.Errorf("exercised %d of %d registry rows; a row that is not runnable cannot be under contract", checked, len(rows))
	}
}

// answeredFromTheCapturedExchange lists the rows in the otherwise-active families that are
// genuinely passive: they read the request and response the scanner already holds, so a missing
// sender is irrelevant to them and demanding an error would be a false refusal.
//
// This is an explicit list rather than a family split because the families are not uniform —
// checks_remaining.go holds both "fetch /crossdomain.xml" and "read the response for a file
// upload form". Each entry carries the reason it is passive, so the classification can be
// audited instead of trusted.
var answeredFromTheCapturedExchange = map[string]string{
	"JWT private key disclosed":                                   "scans the captured response body for private key material in a JWKS",
	"Cross-origin resource sharing":                               "reads Access-Control-Allow-Origin off the captured response",
	"File upload functionality":                                   "looks for a file input in the captured response HTML",
	"OpenAPI definition found (passive scan check)":               "recognises an OpenAPI document in the captured response",
	"React Server Components remote code execution (React2Shell)": "fingerprints a version from the captured response, no probe",
	"SQL statement in request parameter":                          "a heuristic over the captured request's own parameters",
	"Path-relative style sheet import":                            "parses the captured response HTML for a path-relative stylesheet",
}

// needsPreconditionInTheExchange lists rows that legitimately answer "nothing to do" on the
// bare fixture because the thing they examine is absent from it, not because they gave up. Each
// is exercised against a primed exchange in TestActiveRowsRefuseOnAPrimedExchangeWithNoEgress.
var needsPreconditionInTheExchange = map[string]string{
	"TLS certificate":                      "needs a TLS exchange; a plaintext capture has no certificate",
	"Hidden HTTP 2":                        "needs a TLS exchange to compare an ALPN offer against",
	"JWT arbitrary jku header supported":   "needs a JWT in the request to forge from",
	"JWT arbitrary x5u header supported":   "needs a JWT in the request to forge from",
	"JWT signature not verified":           "needs a JWT in the request to forge from",
	"JWT none algorithm supported":         "needs a JWT in the request to forge from",
	"JWT self-signed JWK header supported": "needs a JWT in the request to forge from",
}

// Property 3: an active row must refuse rather than read as clean.
func TestCapabilityDependentRowsRefuseInsteadOfReportingClean(t *testing.T) {
	for family, descs := range capabilityDependentFamilies() {
		if len(descs) == 0 {
			t.Errorf("family %q is empty; the contract would cover nothing", family)
			continue
		}
		for _, d := range descs {
			d := d
			if _, passive := answeredFromTheCapturedExchange[d.Name]; passive {
				continue
			}
			if _, primed := needsPreconditionInTheExchange[d.Name]; primed {
				continue
			}
			t.Run(family+"/"+d.Name, func(t *testing.T) {
				if !d.Runnable() {
					t.Fatalf("%q is not runnable", d.Name)
				}
				cc := bareContext(t)
				findings, err := d.Run(context.Background(), cc)
				if len(findings) != 0 {
					t.Fatalf("reported %d finding(s) with no capability attached: %s",
						len(findings), describeFindings(findings))
				}
				if err == nil {
					t.Fatalf("returned (nil, nil) with no sender, browser, ledger or session attached. "+
						"That reads as %q was tested and found clean. A missing capability must be an error — "+
						"see CheckRunner's contract.", d.Name)
				}
			})
		}
	}
}

// The rows deferred above, now given the precondition they examine and still no egress. This is
// where the JWT and TLS rows actually earn their place: with a token present and nothing able to
// send it, "clean" would be a lie rather than an absence.
func TestActiveRowsRefuseOnAPrimedExchangeWithNoEgress(t *testing.T) {
	byName := map[string]CheckDescriptor{}
	for _, descs := range capabilityDependentFamilies() {
		for _, d := range descs {
			byName[d.Name] = d
		}
	}

	for row := range needsPreconditionInTheExchange {
		d, ok := byName[row]
		if !ok {
			t.Errorf("%q is listed as precondition-dependent but is not in any active family", row)
			continue
		}
		t.Run(row, func(t *testing.T) {
			cc := primedContext(t, strings.HasPrefix(row, "JWT"))
			findings, err := d.Run(context.Background(), cc)
			if len(findings) != 0 {
				t.Fatalf("reported %d finding(s) with no egress: %s", len(findings), describeFindings(findings))
			}
			if err == nil {
				t.Fatalf("returned (nil, nil) on an exchange that carries what %q examines, with nothing able to send a probe. "+
					"The precondition is present, so this is not an absence — it reads as tested and clean.", row)
			}
		})
	}
}

// The gap the egress guard cannot close: a scan that HAS a sender, whose probe still does not
// arrive. RequireEgress passes, the check proceeds, and the send fails in flight — so the
// refusal has to come from the check's own error handling rather than from the guard.
//
// This is the path a dead upstream produces in production, and it is where a discarded error
// turns "could not ask" into "asked and it was fine". The JWT rows are the sharpest case: they
// loop over several forged tokens, and a per-token send failure used to be summarised into the
// same false the application's rejection produces.
func TestARowWhoseProbeFailsInFlightRefusesRatherThanReportingClean(t *testing.T) {
	cc := deadServerContext(t)
	if err := cc.RequireEgress(); err != nil {
		t.Fatalf("fixture has no egress, so it cannot exercise an in-flight failure: %v", err)
	}
	if _, _, ok := jwtFromExchange(cc); !ok {
		t.Fatal("fixture carries no parseable JWT; the JWT rows would return early and prove nothing")
	}

	var ran int
	for _, d := range RemainingCheckDescriptors() {
		if !strings.HasPrefix(d.Name, "JWT ") || d.Name == "JWT private key disclosed" {
			continue // the passive JWKS row reads the captured response and sends nothing
		}
		ran++
		t.Run(d.Name, func(t *testing.T) {
			findings, err := d.Run(context.Background(), cc)
			if len(findings) != 0 {
				t.Fatalf("reported %d finding(s) although no probe reached the target: %s",
					len(findings), describeFindings(findings))
			}
			if err == nil {
				t.Fatal("returned (nil, nil) although every forged-token probe failed to send; " +
					"a rejected forgery and an undelivered forgery are not the same verdict")
			}
		})
	}
	if ran == 0 {
		t.Fatal("no active JWT row was exercised; the test name promises coverage it did not deliver")
	}
}

// deadServerContext wires a real sender at a port that accepted a connection once and then
// stopped listening, so egress is configured but no probe can complete.
func deadServerContext(t *testing.T) *CheckContext {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // the port is now closed; the sender will fail to connect

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split server address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store := core.NewTrafficStore()
	rawReq := fmt.Sprintf("GET /api?id=1 HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: Bearer %s\r\n\r\n",
		host, port, testJWT())
	reqID, err := store.Put([]byte(rawReq), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{Request: reqID, Response: &respID, Host: host, Port: port,
		Method: "GET", Path: "/api?id=1"}
	store.AddExchange(ex)
	scan := NewActiveScanner(store, zap.NewNop()).WithConfig(allChecksOn()).WithSender(sender.NewSender(nil))
	return NewCheckContext(scan, ex, nil)
}

// The out-of-band rows open an external collaborator process. Doing that before checking whether
// a probe can be sent at all made every sender-less scan spawn interactsh-client and wait for a
// domain it would never use — which is also what made this contract suite hang.
//
// Elapsed time is the observable, and it has to be. The error text alone does not distinguish
// the two orderings: when the collaborator *succeeds* (this machine has interactsh-client and a
// route out) the wrong order still ends up returning the local egress error, having spawned a
// process and registered a public DNS name to answer a question already settled locally. A local
// refusal is microseconds; opening the channel is seconds. The bound is deliberately loose so
// this asserts "no external process was started", not a performance target.
func TestOutOfBandRowsRefuseBeforeOpeningTheCollaborator(t *testing.T) {
	const localRefusalBudget = 750 * time.Millisecond

	cc := bareContext(t)
	var ran int
	for _, d := range append(RemainingCheckDescriptors(), FinalCheckDescriptors()...) {
		if !strings.Contains(d.Name, "Out-of-band") && !strings.Contains(d.Name, "External service interaction") {
			continue
		}
		ran++
		t.Run(d.Name, func(t *testing.T) {
			start := time.Now()
			_, err := d.Run(context.Background(), cc)
			elapsed := time.Since(start)

			if err == nil {
				t.Fatal("returned no error with no sender attached")
			}
			if strings.Contains(err.Error(), "out-of-band channel unavailable") {
				t.Errorf("the collaborator was opened before the local egress check: %v. "+
					"Cheap local preconditions must be settled before an external process is spawned.", err)
			}
			if elapsed > localRefusalBudget {
				t.Errorf("took %s to refuse a scan with no sender, budget %s. That is long enough to have "+
					"spawned the collaborator and waited on it; the egress check belongs before the channel is opened.",
					elapsed, localRefusalBudget)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no out-of-band row was found; this test covers nothing")
	}
}

// primedContext builds a TLS exchange, optionally carrying a real JWT in an Authorization
// header, and still attaches no sender.
func primedContext(t *testing.T, withJWT bool) *CheckContext {
	t.Helper()
	req := "GET /api?id=1 HTTP/1.1\r\nHost: app.test\r\n"
	if withJWT {
		// A structurally valid HS256 token: three base64url segments, parseable by ParseJWT.
		req += "Authorization: Bearer " + testJWT() + "\r\n"
	}
	req += "\r\n"
	cc := postureFixture(t, req, htmlResponse("<html><body>ok</body></html>"), true)
	cc.Scanner.WithConfig(allChecksOn())
	cc.Config = cc.Scanner.config
	if withJWT {
		if _, _, ok := jwtFromExchange(cc); !ok {
			t.Fatal("the primed request does not carry a JWT this build can parse; the test would prove nothing")
		}
	}
	if err := cc.RequireEgress(); err == nil {
		t.Fatal("primedContext unexpectedly has egress; the whole point is that it cannot send")
	}
	return cc
}

func testJWT() string {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return b64(`{"alg":"HS256","typ":"JWT"}`) + "." + b64(`{"sub":"1","name":"t"}`) + "." + b64("signature-bytes")
}

// The contract is only worth what it covers, so the partition is pinned: every row in an active
// family is either asserted to refuse, listed as passive with a reason, or listed as
// precondition-dependent and asserted to refuse once primed.
func TestEveryWiredRowIsReachedByTheCapabilityContract(t *testing.T) {
	covered := map[uint32]string{}
	var refusing, passive, primed int
	for family, descs := range capabilityDependentFamilies() {
		for _, d := range descs {
			if prev, dup := covered[d.TypeIndex]; dup {
				t.Errorf("TypeIndex %d claimed by both %q and %q", d.TypeIndex, prev, family)
			}
			covered[d.TypeIndex] = family
			switch {
			case answeredFromTheCapturedExchange[d.Name] != "":
				passive++
			case needsPreconditionInTheExchange[d.Name] != "":
				primed++
			default:
				refusing++
			}
		}
	}
	if refusing+passive+primed != len(covered) {
		t.Fatalf("partition does not cover the families: %d+%d+%d != %d", refusing, passive, primed, len(covered))
	}

	const (
		wantCovered = 111
		wantPassive = 7
		wantPrimed  = 7
	)
	if len(covered) != wantCovered {
		t.Errorf("rows in active families = %d, want %d; update this together with the family list, "+
			"because a family left out is a family whose rows may return (nil, nil) unnoticed", len(covered), wantCovered)
	}
	if passive != wantPassive {
		t.Errorf("rows classified passive = %d, want %d; every entry needs a stated reason and every "+
			"addition here removes a row from the refusal contract", passive, wantPassive)
	}
	if primed != wantPrimed {
		t.Errorf("rows classified precondition-dependent = %d, want %d", primed, wantPrimed)
	}

	// Nothing may be listed in both buckets: a row is either passive or it refuses.
	for row := range answeredFromTheCapturedExchange {
		if _, both := needsPreconditionInTheExchange[row]; both {
			t.Errorf("%q is listed as both passive and precondition-dependent", row)
		}
	}
	// Every stated reason has to actually say something.
	for row, reason := range answeredFromTheCapturedExchange {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q is exempted from the refusal contract with no reason given", row)
		}
	}
}

func describeFindings(f []*Finding) string {
	names := make([]string, 0, len(f))
	for _, x := range f {
		if x == nil {
			names = append(names, "<nil finding>")
			continue
		}
		names = append(names, fmt.Sprintf("%s/%s", x.Name, x.Confidence))
	}
	return strings.Join(names, ", ")
}

// The four rows behind CheckOutOfBand are pinned by name.
//
// Each waits on a callback nothing in this process can synthesise, so each costs seconds of wall
// clock whether or not anything answers. A fifth row joining them quietly would slow every scan that
// enables the family and, worse, spend the time budget later checks need to reach a verdict at all -
// the failure that already cost this harness its CORS row once.
//
// It was five. "TLS certificate" was grouped here and did not belong: it shells out to tlsx and needs
// only a port to connect to, no callback at all, so sharing a gate with the collaborator rows made it
// undemonstrable for a reason that was never true of it. That is the other direction this test
// guards - a row wrongly IN this set is silently uncoverable, not just slow.
func TestOnlyTheCollaboratorRowsRequireTheOutOfBandSwitch(t *testing.T) {
	want := map[string]bool{
		"Out-of-band resource load (HTTP)":    true,
		"External service interaction (DNS)":  true,
		"External service interaction (HTTP)": true,
		"External service interaction (SMTP)": true,
	}

	// The difference between the two configurations is the definition, so it cannot drift from it.
	without := &ScanConfig{CheckExtendedActive: true}
	with := &ScanConfig{CheckExtendedActive: true, CheckOutOfBand: true}

	got := map[string]bool{}
	for _, d := range NativeCheckRegistry() {
		if d.Enabled == nil {
			continue
		}
		if !d.Enabled(without) && d.Enabled(with) {
			got[d.Name] = true
		}
	}

	for name := range want {
		if !got[name] {
			t.Errorf("%q no longer needs CheckOutOfBand; if it stopped waiting on a collaborator "+
				"say so here, because it is now paying no such cost", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%q now requires CheckOutOfBand and was not declared as a collaborator row. "+
				"Rows in this set cost seconds of wall clock each and can starve later checks of "+
				"the time budget they need to reach a verdict", name)
		}
	}
}
