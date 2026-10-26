package sender

import (
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
	"github.com/burpsy-go/burpsy/internal/alpn"
)

// Structural pins for the freeze the behavioural tests in dial_identity_test.go cannot
// interpose on: the stamp's inputs and the dial's inputs must be one read, and the settings
// generation must move when the settings or the carrier do.

// The upstream rule has no public interposition seam — the capture and the dial sit
// microseconds apart with no network between — so the freeze is pinned directly: after
// capture, mutating the live policy moves neither the identity's frozen policy nor its
// stamp, and the frozen policy still resolves the host to the capture-time rule.
func TestDialIdentityFreezesTheUpstreamRuleAtCapture(t *testing.T) {
	policy := upstream.NewPolicy()
	if _, err := policy.Set("*", "http://127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	s := NewSender(config)

	id := s.captureDialIdentity("example.com", true)
	if !id.wrap {
		t.Fatal("a configured policy must route the dial through upstream.Dialer")
	}
	if _, err := policy.Set("*", "http://127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if got := id.upstream.For("example.com").Raw(); got != "http://127.0.0.1:8081" {
		t.Errorf("the frozen policy resolves to %q after the live policy moved, want the capture-time rule", got)
	}
	if id.route == "" || id.route == s.captureDialIdentity("example.com", true).route {
		t.Error("the stamp did not change when the rule it names did")
	}
}

// The freeze rebuilds the resolved rule through Raw -> Parse, the persistence round trip.
// Pin the classes that round trip must not lose: credentials, the socks5h remote-resolution
// flag, and the TLS-to-the-proxy kind. Raw equality is the canonical-form comparison — the
// frozen rule is semantically the rule that was resolved, credentials included (the stamp is
// in-memory only; nothing logs it).
func TestDialIdentityFrozenRulePreservesTheResolvedProxy(t *testing.T) {
	for _, raw := range []string{
		"http://user:s3cret@127.0.0.1:8081",
		"https://127.0.0.1:8443",
		"socks5h://user:p%40ss@127.0.0.1:1080",
	} {
		policy := upstream.NewPolicy()
		if _, err := policy.Set("*", raw); err != nil {
			t.Fatalf("Set(%q): %v", raw, err)
		}
		config := DefaultSenderConfig()
		config.Upstream = policy
		s := NewSender(config)

		id := s.captureDialIdentity("example.com", true)
		got := id.upstream.For("example.com").Raw()
		want := policy.For("example.com").Raw()
		if got != want {
			t.Errorf("rule %q: frozen resolution renders %q, live renders %q — the round trip lost semantics", raw, got, want)
		}
	}
}

// The certificate and the generation: a capture taken while the binding is live keeps
// answering with that certificate after the store is emptied, and ApplyNetwork moves the
// stamp even when the applied settings change nothing the route string names.
func TestDialIdentityFreezesTheCertificateAndTheSettingsGeneration(t *testing.T) {
	identity, _ := generateClientIdentity(t)
	certs := netauth.NewClientCerts()
	certs.Add(identity)
	config := DefaultSenderConfig()
	config.ClientCerts = certs
	config.TLSVerify = false
	config.Timeout = 500 * time.Millisecond
	s := NewSender(config)

	id := s.captureDialIdentity("127.0.0.1", true)
	if !certs.Remove("127.0.0.1") {
		t.Fatal("the binding just added was not there to remove")
	}
	if id.certSource().For("127.0.0.1") == nil {
		t.Error("the frozen certificate source went empty with the live store")
	}

	n := s.Network()
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	if after := s.captureDialIdentity("127.0.0.1", true); after.route == id.route {
		t.Error("ApplyNetwork left the stamp unchanged: a settings change would retire nothing")
	}
}

// The ClientHello fingerprint (63pf) rides the identity because it is a dial input read
// beyond the settings generation's reach: the binding store has no generation of its own.
// (In-tree it is populated only at construction — nothing outside tests calls Add/Remove —
// but an embedder can hand the sender a store it later mutates, and the freeze keeps the
// dial and the stamp on one answer regardless.)
func TestDialIdentityFreezesTheTLSFingerprintAtCapture(t *testing.T) {
	fingerprints := &TLSFingerprints{}
	fingerprints.Add("example.com", alpn.Fingerprint("chrome-test"))
	config := DefaultSenderConfig()
	config.TLSFingerprints = fingerprints
	s := NewSender(config)

	id := s.captureDialIdentity("example.com", true)
	fingerprints.Add("example.com", alpn.Fingerprint("firefox-test"))
	if id.fingerprint != alpn.Fingerprint("chrome-test") {
		t.Errorf("the frozen fingerprint moved with the live store: %q", id.fingerprint)
	}
	if after := s.captureDialIdentity("example.com", true); after.route == id.route {
		t.Error("a fingerprint change left the stamp unchanged")
	}
}

// The carrier and the generation must be one consistent snapshot: a capture concurrent with
// WithUpstreamCarrier reads either the whole before state or the whole after state, never a
// new carrier under an old generation (which would let a carrier change escape the stamp).
// The pair consistency is pinned by assertion; the race detector is the other half of this
// test — it is only meaningful under -race, which the package gate runs.
func TestDialIdentityCarrierAndGenerationAreAConsistentPair(t *testing.T) {
	config := DefaultSenderConfig()
	s := NewSender(config)
	before := upstream.NewCarrier()
	after := upstream.NewCarrier()
	s.WithUpstreamCarrier(before)
	base := s.captureDialIdentity("example.com", false)

	const captures = 200
	var wg sync.WaitGroup
	stop := make(chan struct{})
	failures := make(chan string, captures)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				id := s.captureDialIdentity("example.com", false)
				sawNewCarrier := id.carrier == after
				sawNewGeneration := id.gen > base.gen
				if sawNewCarrier != sawNewGeneration {
					select {
					case failures <- "capture straddled the swap: carrier and generation disagree":
					default:
					}
					return
				}
			}
		}()
	}
	s.WithUpstreamCarrier(after)
	close(stop)
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
	if s.captureDialIdentity("example.com", false).carrier != after {
		t.Error("the carrier settled on the pre-swap value")
	}
}
