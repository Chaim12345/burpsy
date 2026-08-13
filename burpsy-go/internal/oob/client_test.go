package oob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These two fixtures are verbatim records from a live capture against the public
// oast.online instance: a real nslookup and a real curl against a registered payload
// domain. Using the real bytes rather than invented ones is what makes the
// casing-mismatch and fan-out tests below meaningful — both properties were discovered
// from this capture, not assumed.
const (
	realDNSRecord  = `{"protocol":"dns","unique-id":"d9uonjrm27j35omjson0jo63uk6db5pzc","full-id":"d9UoNjrm27J35OMjson0Jo63Uk6dB5PZc","q-type":"A","raw-request":"q","raw-response":"r","remote-address":"172.253.12.216","timestamp":"2026-08-13T09:18:21.635703237Z"}`
	realHTTPRecord = `{"protocol":"http","unique-id":"d9uonjrm27j35omjson0jo63uk6db5pzc","full-id":"d9uonjrm27j35omjson0jo63uk6db5pzc","raw-request":"GET /burpsy-probe-path?x=canary123 HTTP/1.1\r\nHost: d9uonjrm27j35omjson0jo63uk6db5pzc.oast.online\r\n\r\n","raw-response":"HTTP/1.1 200 OK\r\n\r\n","remote-address":"77.137.70.183","timestamp":"2026-08-13T09:18:23.522188929Z"}`
)

// fakeClientBinary writes an executable stand-in for interactsh-client that announces a
// payload domain on stderr exactly as the real binary does, then appends the given JSONL
// records to the -o path (its third argument). No network, no real binary.
func fakeClientBinary(t *testing.T, records ...string) string {
	t.Helper()
	var appends strings.Builder
	for _, r := range records {
		// Single-quote the record for sh and escape any embedded single quote.
		appends.WriteString(fmt.Sprintf("printf '%%s\\n' '%s' >> \"$3\"\n", strings.ReplaceAll(r, `'`, `'\''`)))
	}
	script := "#!/bin/sh\n" +
		"echo '[INF] Current interactsh version 1.3.1 (latest)' >&2\n" +
		"echo '[INF] abc123def456.oast.me' >&2\n" +
		appends.String() +
		"sleep 5\n"

	path := filepath.Join(t.TempDir(), "fake-interactsh-client")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("could not create the fake client binary: %v", err)
	}
	return path
}

func newTestClient(t *testing.T, records ...string) *Client {
	t.Helper()
	c, err := NewClient(context.Background(), Options{
		BinaryPath: fakeClientBinary(t, records...),
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatalf("the fake client should have registered, but NewClient refused: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestTheRegisteredPayloadDomainIsReadFromTheClientsOwnAnnouncement(t *testing.T) {
	c := newTestClient(t)
	if got := c.Domain(); got != "abc123def456.oast.me" {
		t.Fatalf("Domain() returned %q; a check embedding that in a payload would call back to the wrong host", got)
	}
}

func TestEveryRecordedInteractionIsParsedFromTheAppendedLog(t *testing.T) {
	c := newTestClient(t, realDNSRecord, realHTTPRecord)
	// The subprocess appends after announcing, so allow it to land.
	var got []Interaction
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		got, err = c.Interactions()
		if err != nil {
			t.Fatalf("Interactions() failed: %v", err)
		}
		if len(got) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(got) != 2 {
		t.Fatalf("got %d interactions, want 2; a dropped record is a missed callback and therefore a missed finding", len(got))
	}
	if got[0].Protocol != "dns" || got[0].QType != "A" {
		t.Errorf("first record decoded as protocol=%q qtype=%q, want dns/A", got[0].Protocol, got[0].QType)
	}
	if got[1].Protocol != "http" || !strings.Contains(got[1].RawRequest, "canary123") {
		t.Errorf("second record decoded as protocol=%q with request %q, want http carrying the canary", got[1].Protocol, got[1].RawRequest)
	}
	if got[1].RemoteAddress != "77.137.70.183" {
		t.Errorf("http RemoteAddress decoded as %q, want the real client IP 77.137.70.183", got[1].RemoteAddress)
	}
	if got[0].Timestamp.IsZero() {
		t.Error("timestamp did not decode; evidence with no time is not reportable")
	}
}

func TestFullIDCarriesRandomisedCasingSoOnlyUniqueIDIsSafeToCorrelateOn(t *testing.T) {
	c := newTestClient(t, realDNSRecord)
	var got []Interaction
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, _ = c.Interactions()
		if len(got) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(got) != 1 {
		t.Fatalf("got %d interactions, want 1", len(got))
	}
	if got[0].FullID == got[0].UniqueID {
		t.Fatal("this fixture is a real capture in which full-id was 0x20-randomised; if they now match, the fixture was edited and the casing trap is no longer covered")
	}
	if !strings.EqualFold(got[0].FullID, got[0].UniqueID) {
		t.Errorf("full-id %q and unique-id %q differ by more than case, so neither is a reliable correlation key", got[0].FullID, got[0].UniqueID)
	}
}

func TestDeduplicateCollapsesTheDNSFanOutOfASingleLookup(t *testing.T) {
	// A single real nslookup produced six interactions: A and AAAA from three resolvers.
	burst := []Interaction{
		{Protocol: "dns", QType: "A", RemoteAddress: "172.253.12.216"},
		{Protocol: "dns", QType: "A", RemoteAddress: "162.158.254.77"},
		{Protocol: "dns", QType: "AAAA", RemoteAddress: "172.253.228.149"},
		{Protocol: "dns", QType: "AAAA", RemoteAddress: "162.158.254.77"},
		{Protocol: "dns", QType: "A", RemoteAddress: "172.253.12.216"},
		{Protocol: "dns", QType: "AAAA", RemoteAddress: "172.253.228.149"},
	}
	got := Deduplicate(burst)
	if len(got) != 4 {
		t.Fatalf("Deduplicate returned %d of 6 rows, want 4 distinct (protocol,qtype,resolver) events; over-counting here would report one payload firing as six", len(got))
	}
}

func TestInteractionsForKeepsOnlyTheCallersOwnMarkedCallbacks(t *testing.T) {
	other := strings.Replace(realHTTPRecord, "canary123", "somebodyelse", 2)
	c := newTestClient(t, realHTTPRecord, other)
	var mine []Interaction
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		all, _ := c.Interactions()
		if len(all) == 2 {
			var err error
			mine, err = c.InteractionsFor("canary123")
			if err != nil {
				t.Fatalf("InteractionsFor failed: %v", err)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(mine) != 1 {
		t.Fatalf("got %d interactions for marker canary123, want 1; leaking a sibling check's callback would attribute its finding to us", len(mine))
	}
}

func TestAMissingBinaryIsReportedAsNoChannelRatherThanNoInteractions(t *testing.T) {
	// An empty PATH makes the lookup fail, which is the real-world case of the tool not
	// being installed.
	t.Setenv("PATH", "")
	_, err := NewClient(context.Background(), Options{Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("NewClient succeeded with no binary available; a caller would then read zero interactions as 'no vulnerability'")
	}
	if !strings.Contains(err.Error(), binaryName) {
		t.Errorf("error %q does not name %q, so an operator cannot tell what to install", err.Error(), binaryName)
	}
}
