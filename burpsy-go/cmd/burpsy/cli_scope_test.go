package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

// HARD-03 for the CLI surface. `cli_tools.go` used to contain no reference to scope at all:
// cmdRepeater called the raw Sender.SendRaw, and cmdIntruder reached Intruder.sendAttack, which
// dialled the target itself (tls.DialWithDialer with InsecureSkipVerify, or net.DialTimeout) and so
// never entered internal/sender. Both delivered traffic to hosts the operator's own
// -scope-include excluded, and reported it as ordinary work.
//
// These assert the *target's own* request counter is zero. A refusal counter proves bookkeeping;
// only a silent target proves the dial did not happen.

func cliTargetHostPort(t *testing.T, raw string) (string, uint16) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %q: %v", raw, err)
	}
	return u.Hostname(), uint16(p)
}

// scopedCLI builds a CLI context whose scope includes only `allowed`, with output discarded.
func scopedCLI(t *testing.T, allowed string) (*cliContext, *bytes.Buffer) {
	t.Helper()
	ctx, err := newCLIContext("", 1<<20, allowed, "", "", "", "", "", "", "", "")
	if err != nil {
		t.Fatalf("newCLIContext: %v", err)
	}
	var out bytes.Buffer
	ctx.out = &out
	return ctx, &out
}

func TestCLIRepeaterRefusesAnOutOfScopeTargetAndSendsNothing(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := cliTargetHostPort(t, target.URL)

	// Scope allows a different host entirely.
	ctx, _ := scopedCLI(t, "only-this-host.invalid")

	err := cmdRepeater(ctx, []string{
		"-target", host + ":" + strconv.Itoa(int(port)),
		"-raw", "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
	})
	if err == nil {
		t.Error("an out-of-scope repeater send returned no error; it must be refused")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the target received %d request(s); a refused send must never reach the transport", n)
	}
}

func TestCLIRepeaterSendsWhenTheTargetIsInScope(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := cliTargetHostPort(t, target.URL)

	// The positive control: without it, "zero requests arrived" above is equally consistent with a
	// repeater that cannot send at all.
	ctx, _ := scopedCLI(t, host)
	if err := cmdRepeater(ctx, []string{
		"-target", host + ":" + strconv.Itoa(int(port)),
		"-raw", "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
	}); err != nil {
		t.Fatalf("an in-scope repeater send failed: %v", err)
	}
	if n := hits.Load(); n == 0 {
		t.Error("the in-scope send never reached the target, so the refusal above proves nothing")
	}
}

func TestCLIIntruderRefusesAnOutOfScopeTargetAndSendsNothing(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := cliTargetHostPort(t, target.URL)

	ctx, _ := scopedCLI(t, "only-this-host.invalid")

	// cmdIntruder streams results rather than returning an error per payload, so the assertion that
	// matters is the target's counter: every payload must be refused before its dial.
	_ = cmdIntruder(ctx, []string{
		"-target", host + ":" + strconv.Itoa(int(port)),
		"-raw", "GET /__PAYLOAD__ HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"-payloads", "a,b,c",
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("the target received %d attack request(s) while out of scope; "+
			"the intruder engine dialled past the engagement scope", n)
	}
}

func TestCLIIntruderAttacksWhenTheTargetIsInScope(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer target.Close()
	host, port := cliTargetHostPort(t, target.URL)

	ctx, _ := scopedCLI(t, host)
	if err := cmdIntruder(ctx, []string{
		"-target", host + ":" + strconv.Itoa(int(port)),
		"-raw", "GET /__PAYLOAD__ HTTP/1.1\r\nHost: " + host + "\r\n\r\n",
		"-payloads", "a,b,c",
	}); err != nil {
		t.Fatalf("an in-scope attack failed: %v", err)
	}
	if n := hits.Load(); n != 3 {
		t.Errorf("the target received %d of 3 in-scope payloads; the refusal test above proves nothing "+
			"unless the engine can actually send", n)
	}
}
