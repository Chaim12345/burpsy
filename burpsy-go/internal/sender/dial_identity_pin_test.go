package sender

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/netauth"
	"github.com/burpsy-go/burpsy/internal/upstream"
)

// Structural pins for the freeze the behavioural tests in dial_identity_test.go and
// dial_identity_route_test.go cannot interpose on: the stamp's inputs and the dial's inputs
// must be one read, the frozen policy must be the WHOLE policy, and the settings generation
// must move when the settings or the carrier do.

func mustCapture(t *testing.T, s *Sender, host string, port uint16, useTLS bool) dialIdentity {
	t.Helper()
	id, err := s.captureDialIdentity(context.Background(), host, port, useTLS)
	if err != nil {
		t.Fatalf("captureDialIdentity: %v", err)
	}
	return id
}

// The upstream rule has no public interposition seam — the capture and the dial sit
// microseconds apart with no network between — so the freeze is pinned directly: after
// capture, mutating the live policy moves neither the identity's frozen policy nor its
// stamp, and the frozen policy still resolves the dialled address to the capture-time rule.
func TestDialIdentityFreezesTheUpstreamRuleAtCapture(t *testing.T) {
	policy := upstream.NewPolicy()
	if _, err := policy.Set("*", "http://127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	s := NewSender(config)

	id := mustCapture(t, s, "example.com", 443, true)
	if !id.wrap {
		t.Fatal("a configured policy must route the dial through upstream.Dialer")
	}
	if _, err := policy.Set("*", "http://127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	if got := id.upstream.ForAddr(id.dialAddr).Raw(); got != "http://127.0.0.1:8081" {
		t.Errorf("the frozen policy resolves to %q after the live policy moved, want the capture-time rule", got)
	}
	if id.route == "" || id.route == mustCapture(t, s, "example.com", 443, true).route {
		t.Error("the stamp did not change when the rule it names did")
	}
}

// The frozen policy is the whole policy as a value, not the one resolved rule: the dial
// resolves the policy for the address it dials (the override's answer, often an IP literal),
// and isHTTPProxyAddr — the check that keeps a connection to a configured proxy from being
// tunnelled through another proxy — reads every rule, so dropping the unmatching rules would
// change both answers. Snapshot equality pins the whole content; the resolution pins the
// lookup key.
func TestDialIdentityFrozenPolicyIsTheWholePolicyResolvedForTheDialledAddress(t *testing.T) {
	policy := upstream.NewPolicy()
	if _, err := policy.Set("127.0.0.1", "http://user:s3cret@127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Set("other.example", "socks5h://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	config := DefaultSenderConfig()
	config.Upstream = policy
	s := NewSender(config)
	n := s.Network()
	n.Resolution.Overrides = []HostOverride{{Host: "example.test", Address: "127.0.0.1", Enabled: true}}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	id := mustCapture(t, s, "example.test", 443, true)
	if id.dialAddr != "127.0.0.1:443" {
		t.Fatalf("dialAddr = %q, want the override's answer", id.dialAddr)
	}
	if got := id.upstream.ForAddr(id.dialAddr).Raw(); got != "http://user:s3cret@127.0.0.1:8081" {
		t.Errorf("the frozen rule for the dialled address is %q, want the IP-literal rule with its credentials", got)
	}
	if !strings.Contains(id.route, "http://user:s3cret@127.0.0.1:8081") {
		t.Error("the stamp does not name the IP-literal rule the dial consumes")
	}
	if got, want := id.upstream.Snapshot(), policy.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Errorf("the frozen policy is not the whole policy: got %+v, want %+v", got, want)
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

	id := mustCapture(t, s, "127.0.0.1", 443, true)
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
	if after := mustCapture(t, s, "127.0.0.1", 443, true); after.route == id.route {
		t.Error("ApplyNetwork left the stamp unchanged: a settings change would retire nothing")
	}
}

// The settings the dial consumes are the capture's value, not a later ApplyNetwork's: the
// dial address (override), the resolver, the timeouts and the TLS policy all come from
// id.settings, so the stamp's generation and the dial's settings describe the same instant.
func TestDialIdentityFreezesTheSettingsValueAtCapture(t *testing.T) {
	config := DefaultSenderConfig()
	s := NewSender(config)
	n := s.Network()
	n.Resolution.Overrides = []HostOverride{{Host: "example.test", Address: "127.0.0.1", Enabled: true}}
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}

	id := mustCapture(t, s, "example.test", 443, false)
	if id.dialAddr != "127.0.0.1:443" {
		t.Fatalf("dialAddr = %q, want the override's answer", id.dialAddr)
	}

	n.Resolution.Overrides = nil
	if err := s.ApplyNetwork(n); err != nil {
		t.Fatal(err)
	}
	if id.dialAddr != "127.0.0.1:443" {
		t.Error("the captured dial address moved with the live settings")
	}
	if id.settings.Resolution.Overrides == nil {
		t.Error("the captured settings value aliases the live settings")
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

	id := mustCapture(t, s, "example.com", 443, true)
	fingerprints.Add("example.com", alpn.Fingerprint("firefox-test"))
	if id.fingerprint != alpn.Fingerprint("chrome-test") {
		t.Errorf("the frozen fingerprint moved with the live store: %q", id.fingerprint)
	}
	if after := mustCapture(t, s, "example.com", 443, true); after.route == id.route {
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
	base := mustCapture(t, s, "example.com", 443, false)

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
				id, err := s.captureDialIdentity(context.Background(), "example.com", 443, false)
				if err != nil {
					select {
					case failures <- err.Error():
					default:
					}
					return
				}
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
	if id := mustCapture(t, s, "example.com", 443, false); id.carrier != after {
		t.Error("the carrier settled on the pre-swap value")
	}
}
