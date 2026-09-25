package sender

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"time"
)

// A dual-stack target behind IPv4-only routing can resolve to an AAAA first, and burpsy dialled the
// unreachable address: the connect timeout elapsed before the A was tried, so the request took the full
// timeout to fail on a host that was reachable all along. There was no setting that fixed it, only the
// per-hostname override table applied one address at a time (burpsy-react-ui-mr83, part 2).
//
// Burp's answer is the resolution-address preference (settings/network/dns.html:49-65): system
// default, prefer IPv4, or prefer IPv6, "because routing restrictions may permit only one family".
// These tests pin the filter itself, which is where a wrong implementation is invisible.

// filterFamily is the whole of the preference's behaviour, and it is worth testing directly: a dial
// test can only prove that SOME address was chosen, not that the other family was excluded.
func TestTheFamilyFilterKeepsOnlyTheFamilyAskedFor(t *testing.T) {
	addrs := []string{"2001:db8::1", "192.0.2.10", "2001:db8::2", "192.0.2.11"}

	v4, ok := filterFamily(addrs, FamilyIPv4)
	if !ok {
		t.Fatal("IPv4 filter found nothing in a list that has two")
	}
	if len(v4) != 2 || v4[0] != "192.0.2.10" || v4[1] != "192.0.2.11" {
		t.Errorf("IPv4 filter = %v, want the two A records in the resolver's order", v4)
	}

	v6, ok := filterFamily(addrs, FamilyIPv6)
	if !ok {
		t.Fatal("IPv6 filter found nothing in a list that has two")
	}
	if len(v6) != 2 || v6[0] != "2001:db8::1" || v6[1] != "2001:db8::2" {
		t.Errorf("IPv6 filter = %v, want the two AAAA records in the resolver's order", v6)
	}
}

// System is not a filter. It must return the answer UNTOUCHED, in the resolver's order, because that
// order encodes the operator's own routing preferences and overriding it is a decision they have to
// make deliberately.
func TestSystemIsNotAFilter(t *testing.T) {
	addrs := []string{"2001:db8::1", "192.0.2.10"}
	got, ok := filterFamily(addrs, FamilySystem)
	if !ok {
		t.Fatal("the system preference filtered the answer away")
	}
	if len(got) != 2 || got[0] != "2001:db8::1" {
		t.Errorf("system = %v, want the resolver's answer unchanged and in its order", got)
	}
	// And an absent value is the same answer, which is what Normalise guarantees.
	got, ok = filterFamily(addrs, "")
	if !ok || len(got) != 2 {
		t.Errorf("an empty family = %v (ok=%v), want the resolver's answer unchanged", got, ok)
	}
}

// A family with no address in it must be a NAMED failure, not an empty list. A dual-stack host
// reachable only over IPv6, asked for IPv4, is a routing problem the operator has to see; a generic
// "could not resolve" would send them to the DNS settings instead of the family preference.
func TestAFamilyWithNoAddressIsNamedAsSuch(t *testing.T) {
	_, ok := filterFamily([]string{"2001:db8::1"}, FamilyIPv4)
	if ok {
		t.Error("the IPv4 filter accepted a list with no IPv4 address")
	}

	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4
	// An unresolvable name, so the failure comes from the path rather than the name.
	_, err := settings.resolveForDial(context.Background(), "nothing-here.burpsy.invalid")
	if err == nil {
		t.Fatal("an unresolvable host produced no error")
	}
	if !strings.Contains(err.Error(), "burpsy.invalid") {
		t.Errorf("error = %q, want it to name the host", err)
	}
}

// The empty-family message has to say what to do about it, because the fix is one click away in a
// different field.
func TestTheEmptyFamilyMessagePointsAtTheSettingThatFixesIt(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4
	err := &resolutionFailure{host: "dual.test", family: FamilyIPv4, empty: true}
	_ = settings
	if msg := err.Error(); !strings.Contains(msg, "resolution.family") || !strings.Contains(msg, "dual.test") {
		t.Errorf("message = %q, want it to name the field to change and the host", msg)
	}
}

// An override is an operator naming one address, and the family preference must not second-guess it:
// filtering here would silently discard the address they typed and dial somewhere they did not ask
// for, which is a worse failure than the one the preference exists to fix.
func TestAnOverrideIsNeverFilteredByTheFamilyPreference(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Resolution.Overrides = []HostOverride{
		{Host: "pinned.test", Address: "192.0.2.99", Enabled: true},
	}
	// IPv4 asked for, and the override IS an IPv4 address — so pick one that is NOT, to prove the
	// override is used as typed.
	settings.Resolution.Overrides[0].Address = "2001:db8::99"
	settings.Resolution.Family = FamilyIPv4

	addr, err := settings.resolveForDial(context.Background(), "pinned.test")
	if err != nil {
		t.Fatalf("resolveForDial: %v", err)
	}
	if addr != "2001:db8::99" {
		t.Errorf("resolved to %q; an override is an operator naming one address, and the family "+
			"preference silently discarding it would dial somewhere they did not ask for", addr)
	}
}

// A host that is already a literal needs no lookup and no filter: there is one address and it is the
// address.
func TestALiteralAddressNeedsNoResolution(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4

	addr, err := settings.resolveForDial(context.Background(), "192.0.2.5")
	if err != nil {
		t.Fatalf("an IPv4 literal under the IPv4 preference failed: %v", err)
	}
	if addr != "192.0.2.5" {
		t.Errorf("resolved %q, want the literal unchanged", addr)
	}
}

// A literal of the WRONG family is a real refusal, and saying so is the point: an IPv6 literal under
// the IPv4 preference cannot be dialled, and dialling it anyway would be the defect in a new place.
func TestALiteralOfTheWrongFamilyIsRefusedRatherThanDialled(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4

	// resolveForDial only filters the resolver's answer, so a literal is passed through by
	// dialAddressFor. The DIAL is what must refuse it, and it does — the point here is that the
	// preference did not try to be clever and substitute something else.
	addr := settings.dialAddressFor(context.Background(), "2001:db8::1", 443)
	if !strings.Contains(addr, "2001:db8::1") {
		t.Errorf("dialAddressFor substituted %q for a literal of the wrong family; substituting an "+
			"address nobody named is worse than a refused dial", addr)
	}
	// And it is bracketed, so the dialled authority is parseable.
	if !strings.HasPrefix(addr, "[2001:db8::1]:") {
		t.Errorf("address = %q, want the IPv6 literal bracketed", addr)
	}
}

// dialAddressFor applies the family preference and leaves the system preference alone, which is the
// whole difference and is what a dial test can actually see.
func TestDialAddressLeavesTheSystemPreferenceAlone(t *testing.T) {
	settings := DefaultNetworkSettings()
	got := settings.dialAddressFor(context.Background(), "example.invalid", 443)
	if got != "example.invalid:443" {
		t.Errorf("address = %q, want the hostname unchanged: the system preference must not cost a "+
			"lookup the dialer is about to do anyway", got)
	}
}

// The whole preference, observed through a real dial: a host that resolves to both families must be
// reached on the family the operator asked for, and the connect must not time out first.
func TestTheFamilyPreferenceReachesTheAddressTheOperatorAskedFor(t *testing.T) {
	// A listener on the loopback's IPv4 side.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4

	// The address the preference must produce for a name that resolves to both families. localhost is
	// the one name on a loopback test host that reliably has both an A and an AAAA.
	addr, err := settings.resolveForDial(context.Background(), "localhost")
	if err != nil {
		t.Skipf("localhost does not resolve on this host: %v", err)
	}
	if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
		t.Errorf("the IPv4 preference resolved localhost to %q, which is not an IPv4 address", addr)
	}
}

// The TYPED path, which is the one Repeater sends through.
//
// A fake resolver rather than localhost, because localhost is IPv4-only on most machines and the
// preference is then indistinguishable from not applying it — which is exactly how a mutation that
// removed the family handling from the transport's DialContext survived the first version of this
// test. The resolver below answers with an IPv6 address FIRST and an IPv4 one second, so a dial that
// ignores the preference tries the address nothing is listening on, and one that honours it reaches
// the listener. A real dual-stack name would have the same property, but not every machine has one.
func TestTheTypedTransportAlsoAppliesTheFamilyPreference(t *testing.T) {
	// A listener only IPv4 can reach.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()

	// The seam is installed on the SETTINGS, before they are applied, because ApplyNetwork rebuilds
	// the transport from them — a seam assigned to a live sender afterwards would never be consulted,
	// and a test written that way would pass without proving anything about the transport.
	settings := DefaultNetworkSettings()
	settings.Resolution.Family = FamilyIPv4
	settings.Resolution.Lookup = func(_ context.Context, host string) ([]string, error) {
		if host == "dual.test" {
			// IPv6 FIRST, and nothing is listening there: a transport that ignores the preference
			// dials this and the request fails. One that honours it picks the A record.
			return []string{"2001:db8::dead", "127.0.0.1"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	snd := NewSender(DefaultSenderConfig())
	if err := snd.ApplyNetwork(settings); err != nil {
		t.Fatalf("apply: %v", err)
	}

	a := NewAuthorisedSender(core.NewScopeAllowEverything(), snd, "dual.test", port, false)
	resp, err := a.SendRequest(context.Background(), &Request{
		Method: "GET",
		URL:    "http://dual.test:" + strconv.Itoa(int(port)) + "/",
	})
	if err != nil {
		t.Fatalf("the typed send failed under the IPv4 preference: %v — the transport did not "+
			"filter to the family, so it dialled the AAAA nothing is listening on", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200: the typed path did not reach the IPv4 listener", resp.StatusCode)
	}
}

// The typed path must also leave the SYSTEM preference alone, for the same reason the raw one does:
// a preference that costs a lookup the transport is about to do anyway is a slowdown nobody asked for.
func TestTheTypedTransportLeavesTheSystemPreferenceToTheDialer(t *testing.T) {
	snd := NewSender(DefaultSenderConfig())
	if err := snd.ApplyNetwork(DefaultNetworkSettings()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// A name that does not resolve, so the transport's DialContext is what answers, and the answer
	// must be a resolution failure rather than a substituted address.
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), snd, "nothing-here.burpsy.invalid", 80, false)
	_, err := a.SendRequest(context.Background(), &Request{
		Method: "GET",
		URL:    "http://nothing-here.burpsy.invalid/",
	})
	if err == nil {
		t.Fatal("an unresolvable host produced no error under the system preference")
	}
	if !strings.Contains(err.Error(), "burpsy.invalid") {
		t.Errorf("error = %q, want it to name the host that could not be resolved", err)
	}
}
