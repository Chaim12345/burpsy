package sender

import (
	"context"
	"reflect"
	"testing"

	"github.com/burpsy-go/burpsy/internal/alpn"
)

// burpsy-react-ui-57yk: planSend switched on only !useTLS and ProtocolPreferenceHTTP1, so Auto and
// ForceH2 fell through to the same branch and produced byte-identical plans —
//
//	auto : wantH2=true block=<nil>
//	force: wantH2=true block=<nil>
//	reflect.DeepEqual(auto, force) == true
//
// ProtocolPreferenceForceH2 was parsed at the web layer (repeater_options.go) and never consulted
// again anywhere in this package. This file pins two things: that planSend itself now produces
// distinguishable plans, and that the distinction actually reaches the outcome of a real send rather
// than sitting in sendPlan unread.

// A carriable HTTP/1.1 request over TLS gets a different plan under Force than under Auto — the
// literal reproduction from the issue, now failing the DeepEqual it used to pass.
func TestPlanSendDistinguishesAutoFromForceH2(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	auto, err := planSend(raw, true, ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("planSend(auto): %v", err)
	}
	force, err := planSend(raw, true, ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("planSend(force): %v", err)
	}
	if reflect.DeepEqual(auto, force) {
		t.Fatal("planSend produced byte-identical plans for Auto and ForceH2 — the preference still has nowhere to go")
	}
	if auto.mustH2 {
		t.Error("Auto's plan claims mustH2 — Auto never requires h2, it only offers it")
	}
	if !force.mustH2 {
		t.Error("ForceH2's plan does not claim mustH2 — the one field this preference exists to set")
	}
	// Both still offer h2 on the wire: this is not HTTP1's pin, and force_h2_test.go already fixes what
	// happens when the target actually negotiates h2 or refuses to carry the request at all. Asserted
	// here too so a future edit cannot satisfy mustH2 by accidentally clearing wantH2.
	if !auto.wantH2 || !force.wantH2 {
		t.Fatalf("wantH2 = (auto:%v force:%v), want both true — Force does not withdraw the offer, only escalates what a decline means", auto.wantH2, force.wantH2)
	}

	// A request h2 has nowhere to put (the archetypal smuggling probe) blocks identically under both:
	// mustH2 must not survive a plan-time refusal, because nothing was offered for Force to have
	// required.
	smuggle := []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n")
	autoBlocked, err := planSend(smuggle, true, ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("planSend(auto, smuggle): %v", err)
	}
	forceBlocked, err := planSend(smuggle, true, ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("planSend(force, smuggle): %v", err)
	}
	if autoBlocked.mustH2 || forceBlocked.mustH2 {
		t.Errorf("mustH2 = (auto:%v force:%v) on a request h2 cannot carry — there is nothing to require here", autoBlocked.mustH2, forceBlocked.mustH2)
	}
	if !reflect.DeepEqual(autoBlocked.block, forceBlocked.block) {
		t.Errorf("block = (auto:%+v force:%+v), want identical — Force cannot change what h2 can carry", autoBlocked.block, forceBlocked.block)
	}
}

// The distinction is not a dead field: against a target whose ALPN chooses http/1.1, Auto's and
// Force's outcomes agree on everything force_h2_test.go already pins (no error, DowngradeNegotiatedHTTP11,
// an HTTP/1.1 response) and differ on the one new bit that exists to tell "Auto happened to get
// downgraded" apart from "Force asked for h2 and was refused".
func TestForceH2MarksTheDowngradeAsForcedWhereAutoDoesNot(t *testing.T) {
	srv := startALPNServer(t, []string{alpn.HTTP11}, false)
	s := testSender()

	_, autoOutcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceAuto)
	if err != nil {
		t.Fatalf("auto send: %v", err)
	}
	_, forceOutcome, err := s.SendRawOutcome(context.Background(), srv.host, srv.port, true,
		rawGet(srv.host, srv.port), ProtocolPreferenceForceH2)
	if err != nil {
		t.Fatalf("force send: %v", err)
	}

	if autoOutcome.Downgrade == nil || autoOutcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("auto downgrade = %+v, want DowngradeNegotiatedHTTP11", autoOutcome.Downgrade)
	}
	if forceOutcome.Downgrade == nil || forceOutcome.Downgrade.Reason != DowngradeNegotiatedHTTP11 {
		t.Fatalf("force downgrade = %+v, want DowngradeNegotiatedHTTP11", forceOutcome.Downgrade)
	}
	if autoOutcome.Downgrade.Forced {
		t.Error("auto's downgrade is marked Forced — Auto never required h2, so nothing was forced")
	}
	if !forceOutcome.Downgrade.Forced {
		t.Error("force's downgrade is not marked Forced — this is the bit the whole fix exists to set")
	}
}
