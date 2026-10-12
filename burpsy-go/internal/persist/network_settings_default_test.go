package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/sender"
)

// A stored network-settings document with no tls key must load with verification ON. Decoding onto a
// zero struct turned it off: Verify's zero value is false, and applying the loaded settings then
// accepted any certificate from any target without the operator choosing that.
func TestNetworkSettingsWithoutATLSKeyKeepVerificationOn(t *testing.T) {
	p := newTestStore(t)
	if err := p.setSetting("network.settings", `{"timeouts":{"connect_ms":2000,"read_ms":0,"total_ms":9000}}`); err != nil {
		t.Fatal(err)
	}
	got, err := p.LoadNetworkSettings()
	if err != nil || got == nil {
		t.Fatalf("LoadNetworkSettings: %v (nil=%v)", err, got == nil)
	}
	if !got.TLS.Verify {
		t.Fatal("a saved document without a tls key loaded with TLS verification OFF")
	}
	if got.Timeouts.TotalMS != 9000 || got.Timeouts.ConnectMS != 2000 {
		t.Errorf("the stored keys were not applied over the defaults: %+v", got.Timeouts)
	}
	if def := sender.DefaultNetworkSettings(); got.Redirects != def.Redirects {
		t.Errorf("an absent redirects key did not keep its default: %+v", got.Redirects)
	}
}

// An explicit opt-out is still honoured: the default fills only what the document does not say.
func TestNetworkSettingsWithVerifyFalseStayOff(t *testing.T) {
	p := newTestStore(t)
	if err := p.setSetting("network.settings", `{"tls":{"verify":false}}`); err != nil {
		t.Fatal(err)
	}
	got, err := p.LoadNetworkSettings()
	if err != nil || got == nil {
		t.Fatalf("LoadNetworkSettings: %v", err)
	}
	if got.TLS.Verify {
		t.Fatal("an explicit tls.verify=false was overridden by the default")
	}
}
