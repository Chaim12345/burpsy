package sender

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// headRecordingServer answers a fixed 200 and hands back every request head it received.
//
// The head is what the resolution-override tests are actually about: proving the bytes arrived is only
// half of it, because an override that rewrote the Host header too would arrive at the right address
// asking for the wrong vhost — which is a different test than the operator wanted to run.
func headRecordingServer(t *testing.T) (addr string, heads func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu struct {
		lock sync.Mutex
		got  []string
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				head := ""
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					head += line
					if strings.HasSuffix(head, "\r\n\r\n") || strings.HasSuffix(head, "\n\n") {
						break
					}
				}
				mu.lock.Lock()
				mu.got = append(mu.got, head)
				mu.lock.Unlock()
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.lock.Lock()
		defer mu.lock.Unlock()
		out := make([]string, len(mu.got))
		copy(out, mu.got)
		return out
	}
}

// overrideOnly builds settings whose only departure from the defaults is one resolution override.
func overrideOnly(host, address string) NetworkSettings {
	settings := DefaultNetworkSettings()
	settings.Resolution.Overrides = []HostOverride{{Host: host, Address: address, Enabled: true}}
	return settings
}

// The name the tests dial. `.invalid` is reserved by RFC 2606 and never resolves, so a request that
// arrives at the listener could only have got there through the override table — which is the claim
// under test. A hostname that happened to resolve would prove nothing.
const unresolvableHost = "staging.burpsy.invalid"

// The raw path: sendHTTP1Plain dials through NetworkSettings.dialAddress.
func TestAResolutionOverrideDecidesWhereTheRawPathDials(t *testing.T) {
	addr, heads := headRecordingServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	snd := NewSender(DefaultSenderConfig())
	if err := snd.ApplyNetwork(overrideOnly(unresolvableHost, "127.0.0.1")); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), snd, unresolvableHost, port, false)

	raw := []byte("GET /probe HTTP/1.1\r\nHost: " + unresolvableHost + "\r\n\r\n")
	res, err := a.Send(context.Background(), raw)
	if err != nil {
		t.Fatalf("send to an overridden host failed, so the override did not decide the dial: %v", err)
	}
	if res.Status == nil || *res.Status != 200 {
		t.Fatalf("status = %v, want 200", res.Status)
	}
	got := heads()
	if len(got) != 1 {
		t.Fatalf("the listener saw %d requests, want 1", len(got))
	}
	// The whole point of the override: the address changed, the name did not. A Host header naming
	// 127.0.0.1 would mean this asked the box what it serves by default rather than asking for the
	// vhost under test.
	if !strings.Contains(got[0], "Host: "+unresolvableHost) {
		t.Errorf("the request that arrived does not name the overridden host:\n%s", got[0])
	}
}

// The typed path: http.Transport hands an already-computed address to DialContext, so the override has
// to be applied by overrideAddr rather than by dialAddress. Two code paths, so two tests — a fix to one
// has silently missed the other before.
func TestAResolutionOverrideDecidesWhereTheTypedPathDials(t *testing.T) {
	addr, heads := headRecordingServer(t)
	_, port, err := hostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	snd := NewSender(DefaultSenderConfig())
	if err := snd.ApplyNetwork(overrideOnly(unresolvableHost, "127.0.0.1")); err != nil {
		t.Fatalf("apply settings: %v", err)
	}
	a := NewAuthorisedSender(core.NewScopeAllowEverything(), snd, unresolvableHost, port, false)

	resp, err := a.SendRequest(context.Background(), &Request{
		Method: "GET",
		URL:    "http://" + net.JoinHostPort(unresolvableHost, strconv.Itoa(int(port))) + "/typed",
		Host:   unresolvableHost,
		Port:   port,
	})
	if err != nil {
		t.Fatalf("typed send to an overridden host failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := heads()
	if len(got) != 1 {
		t.Fatalf("the listener saw %d requests, want 1", len(got))
	}
	if !strings.Contains(got[0], "Host: "+unresolvableHost) {
		t.Errorf("the typed path rewrote the Host header along with the address:\n%s", got[0])
	}
}

// A disabled row is not a row. Asserted because the enabled flag is the operator's way of keeping a
// table entry around without it firing, and a flag nothing reads is worse than no flag: the panel would
// show an override as off while every dial obeyed it.
func TestADisabledOverrideIsNotConsulted(t *testing.T) {
	settings := overrideOnly("a.test", "127.0.0.1")
	settings.Resolution.Overrides[0].Enabled = false
	if got := settings.dialAddress("a.test", 80); got != "a.test:80" {
		t.Errorf("dialAddress with a disabled override = %q, want the unmodified host", got)
	}
	if got := settings.overrideAddr("a.test:80"); got != "a.test:80" {
		t.Errorf("overrideAddr with a disabled override = %q, want the unmodified address", got)
	}
}

// Matching is case-insensitive on both sides, because a hostname is. The normalising step lowercases
// the table on the way in; this pins that a differently-cased dial still finds the row.
func TestOverrideMatchingIgnoresHostnameCase(t *testing.T) {
	settings := overrideOnly("Staging.Example.test", "10.0.0.7").Normalise()
	if got := settings.dialAddress("STAGING.example.TEST", 8443); got != "10.0.0.7:8443" {
		t.Errorf("dialAddress = %q, want the override applied regardless of case", got)
	}
}

// An address overrideAddr cannot split is passed through rather than refused, and that is deliberate:
// this function decides whether an override applies, not whether a send is allowed. Failing a dial over
// an address it could not parse would break sends that have nothing to do with the table.
func TestAnUnsplittableAddressIsLeftAloneRatherThanRefused(t *testing.T) {
	settings := overrideOnly("a.test", "127.0.0.1")
	if got := settings.overrideAddr("no-port-here"); got != "no-port-here" {
		t.Errorf("overrideAddr = %q, want the input back unchanged", got)
	}
}

// The three timeouts have to be separable, or the surface is just SenderConfig.Timeout with more
// fields. readTimeout is where that separation is observable: a declared streaming host waits on its
// own bound, everything else on the read bound, and the total only stands in when no read bound is set.
func TestTheReadBoundIsPerHostForADeclaredStreamingHost(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.Timeouts.ReadMS = 2_000
	settings.Streaming.Hosts = []string{"*.events.test"}
	settings.Streaming.TimeoutMS = 30_000

	if got := settings.readTimeout("api.test"); got != 2*time.Second {
		t.Errorf("readTimeout for an ordinary host = %v, want the 2s read bound", got)
	}
	if got := settings.readTimeout("live.events.test"); got != 30*time.Second {
		t.Errorf("readTimeout for a declared streaming host = %v, want its own 30s bound", got)
	}
	// The suffix pattern matches the bare domain too, which is what an operator writing
	// `*.events.test` means; it does not match a host that merely ends in those characters.
	if !settings.Streaming.isStreaming("events.test") {
		t.Error("*.events.test does not match events.test, so the bare domain would need a second row")
	}
	if settings.Streaming.isStreaming("notevents.test") {
		t.Error("*.events.test matched notevents.test, so the pattern is a substring test rather than a " +
			"suffix one")
	}

	// No read bound: the total stands in, preserving what SenderConfig.Timeout used to be the only
	// deadline for.
	settings.Timeouts.ReadMS = 0
	if got := settings.readTimeout("api.test"); got != settings.exchangeTimeout() {
		t.Errorf("readTimeout with no read bound = %v, want the total (%v)", got, settings.exchangeTimeout())
	}
}

// Refuse-by-default on unparseable input, for every arm of the document. Each case names the field it
// is about so a failure says which rule stopped guarding.
func TestValidateRefusesSettingsThatCannotBeApplied(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*NetworkSettings)
		wantIn string
	}{
		{"an override with no host", func(n *NetworkSettings) {
			n.Resolution.Overrides = []HostOverride{{Address: "10.0.0.1", Enabled: true}}
		}, "names no host"},
		{"an override pointing at another name", func(n *NetworkSettings) {
			n.Resolution.Overrides = []HostOverride{{Host: "a.test", Address: "b.test", Enabled: true}}
		}, "not an IP address"},
		{"an override host that is a pattern", func(n *NetworkSettings) {
			n.Resolution.Overrides = []HostOverride{{Host: "*.a.test", Address: "10.0.0.1", Enabled: true}}
		}, "not a hostname"},
		{"two addresses for one name", func(n *NetworkSettings) {
			n.Resolution.Overrides = []HostOverride{
				{Host: "a.test", Address: "10.0.0.1", Enabled: true},
				{Host: "a.test", Address: "10.0.0.2", Enabled: true},
			}
		}, "repeats host"},
		{"a resolver policy with no resolver", func(n *NetworkSettings) {
			n.Resolution.Policy = ResolutionResolver
		}, "names no address"},
		{"a resolver that needs a lookup of its own", func(n *NetworkSettings) {
			n.Resolution.Policy = ResolutionResolver
			n.Resolution.Resolver = "dns.example.test"
		}, "not an IP address"},
		{"a negative timeout", func(n *NetworkSettings) { n.Timeouts.ReadMS = -1 }, "cannot be negative"},
		{"a timeout beyond the ceiling", func(n *NetworkSettings) {
			n.Timeouts.TotalMS = MaxTimeoutMS + 1
		}, "longer than"},
		{"a mode that does not exist", func(n *NetworkSettings) {
			n.Redirects.Mode = RedirectMode("occasionally")
		}, "occasionally"},
		{"more hops than the ceiling", func(n *NetworkSettings) {
			n.Redirects.Mode = RedirectOnSite
			n.Redirects.MaxHops = MaxRedirectHops + 1
		}, "bounded to between"},
		{"a following mode that follows nothing", func(n *NetworkSettings) {
			n.Redirects.Mode = RedirectOnSite
			n.Redirects.MaxHops = 0
		}, "follows nothing"},
		{"a streaming pattern that matches everything", func(n *NetworkSettings) {
			n.Streaming.Hosts = []string{"  "}
		}, "would match every host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := DefaultNetworkSettings()
			tc.mutate(&settings)
			err := settings.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("refusal %q does not mention %q", err, tc.wantIn)
			}
		})
	}
}

// ApplyNetwork is all-or-nothing. A half-applied document — the new timeouts live and the new
// resolution table not — is a state no operator asked for and none could diagnose from the panel.
func TestARefusedApplyChangesNothing(t *testing.T) {
	snd := NewSender(DefaultSenderConfig())
	before := snd.Network()

	bad := DefaultNetworkSettings()
	bad.Timeouts.ReadMS = 1_500
	bad.Resolution.Overrides = []HostOverride{{Host: "a.test", Address: "not-an-address", Enabled: true}}
	if err := snd.ApplyNetwork(bad); err == nil {
		t.Fatal("ApplyNetwork accepted an override with an unparseable address")
	}
	after := snd.Network()
	if after.Timeouts.ReadMS != before.Timeouts.ReadMS {
		t.Errorf("read_ms moved to %d on a refused apply; the valid half of a refused document must "+
			"not take effect", after.Timeouts.ReadMS)
	}
	if len(after.Resolution.Overrides) != 0 {
		t.Errorf("a refused override list was installed: %v", after.Resolution.Overrides)
	}
}

// The defaults reproduce what shipped before these settings existed, and that is the whole argument
// for the surface being safe to add: an operator who never opens the panel gets the tool they had.
func TestTheDefaultsAreTheBehaviourThatAlreadyShipped(t *testing.T) {
	if err := DefaultNetworkSettings().Validate(); err != nil {
		t.Fatalf("the defaults do not validate: %v", err)
	}
	// A sender built the old way must report the same thing, because SenderConfig.Timeout is what
	// every existing caller still passes.
	snd := NewSender(&SenderConfig{Timeout: 3 * time.Second, UserAgent: "x"})
	got := snd.Network()
	if got.Timeouts.TotalMS != 3_000 {
		t.Errorf("total_ms = %d, want the 3000 the config named", got.Timeouts.TotalMS)
	}
	// Clamped rather than left at the 10s default, so `Timeout: 3s` still means a three-second dial.
	if got.Timeouts.ConnectMS != 3_000 {
		t.Errorf("connect_ms = %d, want it clamped to the shorter total", got.Timeouts.ConnectMS)
	}
	if got.Redirects.Mode != RedirectNever {
		t.Errorf("redirects.mode = %q on a sender nobody configured, want %q", got.Redirects.Mode, RedirectNever)
	}
}

// normaliseResolver defaults the DNS port and refuses what cannot be dialled without a lookup of its
// own — a resolver named by hostname is a chicken-and-egg the operator cannot debug from a timeout.
func TestResolverAddressesTakeTheDnsPortAndRefuseNames(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.53", "10.0.0.53:53"},
		{"10.0.0.53:5353", "10.0.0.53:5353"},
		{"::1", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
	} {
		got, err := normaliseResolver(tc.in)
		if err != nil {
			t.Errorf("normaliseResolver(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normaliseResolver(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "dns.example.test", "10.0.0.53:notaport"} {
		if _, err := normaliseResolver(bad); err == nil {
			t.Errorf("normaliseResolver(%q) was accepted", bad)
		}
	}
}
