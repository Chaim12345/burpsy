package persist

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/upstream"
)

// The global SOCKS layer has to survive a restart, or an operator who configured it watches every
// session start without it and concludes the setting does not work.
//
// A carrier that came back empty would be the worse failure: the panel would read the restored
// document and show no hop, and an operator watching a connection go direct would have no way to
// tell that from the setting never having applied (burpsy-react-ui-mr83 part 3).

func TestTheUpstreamCarrierRoundTripsThroughARestart(t *testing.T) {
	store := newTestStore(t)

	live := upstream.NewCarrier()
	if err := live.SetSocks("socks5://proxy.internal.test:1080", []string{"intranet.example.test", "*.local.test"}, true); err != nil {
		t.Fatalf("SetSocks: %v", err)
	}
	store.SaveUpstreamCarrier(live)

	// A fresh carrier, because the claim is about a restart rather than about a re-read of the same
	// object: restoring into the carrier it was saved from would pass even if the load were a no-op.
	restored := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(restored)
	if err != nil {
		t.Fatalf("LoadUpstreamCarrier: %v", err)
	}
	if !ok {
		t.Fatal("the carrier did not report as restored; a saved layer that reads back as unconfigured is " +
			"worse than one that was never saved, because nothing on screen says so")
	}
	if _, bypass, remote, configured := restored.Configured(); !configured || len(bypass) != 2 || !remote {
		t.Errorf("restored carrier = configured %v bypass %v remote %v; want the saved values",
			configured, bypass, remote)
	}
	// Whether the restored layer actually CARRIES is asserted in internal/upstream, where carries is
	// reachable. Persistence owns exactly one question — does the value survive a restart — and a test
	// here that reached past it would be asserting the carrier's behaviour with the wrong tool.
}

// An absent row is not a failure: no row means no carrier was ever configured, which is the ordinary
// state of every process that never set one.
func TestAnAbsentCarrierRowLeavesTheCarrierUnconfigured(t *testing.T) {
	store := newTestStore(t)
	carrier := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(carrier)
	if err != nil {
		t.Fatalf("an absent carrier row was an error: %v", err)
	}
	if ok {
		t.Error("an absent row reported a restored carrier")
	}
	if _, _, _, configured := carrier.Configured(); configured {
		t.Error("an absent row left the carrier configured")
	}
}

// A row that cannot be read is an error, not a silent no-op. The caller makes it fatal because
// starting with a layer the operator configured but this process could not read means traffic going
// out a way they did not choose.
func TestAnUnreadableCarrierRowIsAnError(t *testing.T) {
	store := newTestStore(t)
	if err := store.setSetting("network.carrier", "{not json"); err != nil {
		t.Fatal(err)
	}
	carrier := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(carrier)
	if err == nil {
		t.Fatal("a corrupt carrier row loaded without an error; the process would start with no layer and no warning")
	}
	if ok {
		t.Error("a corrupt row reported as restored")
	}
}

// An empty address in a saved document is "no carrier", not a hop to nowhere — the same rule
// SetSocks applies live, applied on restore so a cleared setting stays cleared across a restart.
func TestACarrierRowWithAnEmptyAddressRestoresAsUnconfigured(t *testing.T) {
	store := newTestStore(t)
	live := upstream.NewCarrier()
	if err := live.SetSocks("socks5://127.0.0.1:1080", nil, false); err != nil {
		t.Fatal(err)
	}
	store.SaveUpstreamCarrier(live)
	// The operator clears it.
	if err := live.SetSocks("", nil, false); err != nil {
		t.Fatal(err)
	}
	store.SaveUpstreamCarrier(live)

	restored := upstream.NewCarrier()
	ok, err := store.LoadUpstreamCarrier(restored)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok {
		t.Error("a cleared carrier came back configured; the operator cleared the setting and a restart " +
			"put it back, which is the definition of a setting that cannot be turned off")
	}
}
