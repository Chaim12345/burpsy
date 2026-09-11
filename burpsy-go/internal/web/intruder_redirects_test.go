package web

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// tirx: an attack never followed a 3xx, so a result only visible after a redirect — a
// login/brute-force success page, say — was invisible to Intruder. internal/intruder/intruder.go's
// file header explains why that was deliberate until now: "if an attack ever needs to follow a
// redirect it must do so per hop, re-authorising the new authority through the scope chokepoint,
// because a 30x is exactly how a target steers an attack somewhere nobody authorised." These tests
// are that per-hop re-authorisation exercised end to end over real sockets, not a mock of
// sender.AuthorisedSender — the guarantee only means something if the hop actually goes through the
// same gate the first request did.

// redirectHopServer answers every request with a 302 to `location` and counts requests received.
func redirectHopServer(t *testing.T, location string) (addr string, hits *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var count atomic.Int64
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
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				count.Add(1)
				fmt.Fprintf(c, "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n", location)
			}(conn)
		}
	}()
	return ln.Addr().String(), &count
}

// redirectFinalServer answers every request 200 with body and counts requests received — the
// destination a followed chain should, and a refused one should not, ever reach.
func redirectFinalServer(t *testing.T, body string) (addr string, hits *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var count atomic.Int64
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
				if _, err := br.ReadString('\n'); err != nil {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				count.Add(1)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().String(), &count
}

// redirectRunView is the slice of RunView these tests read: the per-attempt status/length the
// operator sees, and the setting's own proof-of-work counter.
type redirectRunView struct {
	Report struct {
		Sent     int `json:"sent"`
		Attempts []struct {
			Status      *int `json:"status"`
			ResponseLen int  `json:"response_len"`
		} `json:"attempts"`
	} `json:"report"`
	RedirectsFollowed int `json:"redirects_followed"`
}

func TestFollowRedirectsUnsetLeavesTheThreeOhXAsTheResponse(t *testing.T) {
	final, finalHits := redirectFinalServer(t, "the flag")
	hop, hopHits := redirectHopServer(t, "http://"+final+"/found")
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var out redirectRunView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":        id,
		"target":        "http://" + hop,
		"mode":          "sniper",
		"point_index":   0,
		"payload_sets":  [][]string{{"x"}},
		"max_requests":  10,
		"max_in_flight": 1,
		"rps":           1000,
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if out.Report.Sent != 1 || len(out.Report.Attempts) != 1 {
		t.Fatalf("fixture: sent=%d attempts=%d", out.Report.Sent, len(out.Report.Attempts))
	}
	if got := out.Report.Attempts[0].Status; got == nil || *got != 302 {
		t.Fatalf("status = %v, want the 302 itself — the default is not to follow", got)
	}
	if hopHits.Load() != 1 {
		t.Fatalf("hop server saw %d requests, want exactly 1 (no follow)", hopHits.Load())
	}
	if finalHits.Load() != 0 {
		t.Fatalf("final server saw %d requests; nothing should have followed the redirect there", finalHits.Load())
	}
	if out.RedirectsFollowed != 0 {
		t.Fatalf("redirects_followed = %d, want 0 when nothing was followed", out.RedirectsFollowed)
	}
}

func TestFollowRedirectsAlwaysReachesTheFinalPageAndCountsTheHop(t *testing.T) {
	final, finalHits := redirectFinalServer(t, "the flag")
	hop, hopHits := redirectHopServer(t, "http://"+final+"/found")
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var out redirectRunView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":           id,
		"target":           "http://" + hop,
		"mode":             "sniper",
		"point_index":      0,
		"payload_sets":     [][]string{{"x"}},
		"max_requests":     10,
		"max_in_flight":    1,
		"rps":              1000,
		"follow_redirects": "always",
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if len(out.Report.Attempts) != 1 {
		t.Fatalf("fixture: attempts=%d", len(out.Report.Attempts))
	}
	if got := out.Report.Attempts[0].Status; got == nil || *got != 200 {
		t.Fatalf("status = %v, want 200 — the followed page, not the 302", got)
	}
	// response_len is the full raw response (status line, headers, body) — the same convention
	// every other attempt row uses (doSend: `length: len(sent.Raw)`) — not just the body.
	wantLen := len("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nthe flag")
	if out.Report.Attempts[0].ResponseLen != wantLen {
		t.Fatalf("response_len = %d, want the final page's raw length (%d) — proof the bucketed response is the followed page, not the 302", out.Report.Attempts[0].ResponseLen, wantLen)
	}
	if hopHits.Load() != 1 {
		t.Fatalf("hop server saw %d requests, want 1", hopHits.Load())
	}
	if finalHits.Load() != 1 {
		t.Fatalf("final server saw %d requests, want the one followed hop", finalHits.Load())
	}
	if out.RedirectsFollowed != 1 {
		t.Fatalf("redirects_followed = %d, want 1 — the report's own proof the setting did something", out.RedirectsFollowed)
	}
}

func TestFollowRedirectsNeverAppliesEvenWhenTheSettingIsMisspelled(t *testing.T) {
	hop, _ := redirectHopServer(t, "http://127.0.0.1:1/found")
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	body := httpBody(t, srv, map[string]any{
		"msg_id":           id,
		"target":           "http://" + hop,
		"mode":             "sniper",
		"point_index":      0,
		"payload_sets":     [][]string{{"x"}},
		"max_requests":     10,
		"follow_redirects": "sometimes",
	})
	if body == "" {
		t.Fatalf("expected a 400 body naming the bad mode")
	}
}

// The scope gate that makes any of this safe: a hop whose Location names a host the operator did
// not authorise must never be sent, however the attack's own follow_redirects setting is spelled.
func TestFollowRedirectsRefusesAHopOutOfScope(t *testing.T) {
	final, finalHits := redirectFinalServer(t, "should never be seen")
	hop, hopHits := redirectHopServer(t, "http://"+final+"/found")
	_, hopPortStr, err := net.SplitHostPort(hop)
	if err != nil {
		t.Fatal(err)
	}
	var hopPort int
	fmt.Sscanf(hopPortStr, "%d", &hopPort)

	// Only the hop's own host:port is authorised — the final server, on a different port of the
	// same loopback address, is not. A whole-host "127.0.0.1" include would let both through and
	// prove nothing about the per-hop gate.
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, "127.0.0.1", uint16(hopPort)))

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var out redirectRunView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":           id,
		"target":           "http://" + hop,
		"mode":             "sniper",
		"point_index":      0,
		"payload_sets":     [][]string{{"x"}},
		"max_requests":     10,
		"max_in_flight":    1,
		"rps":              1000,
		"follow_redirects": "always",
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if got := out.Report.Attempts[0].Status; got == nil || *got != 302 {
		t.Fatalf("status = %v, want the 302 to survive a refused hop", got)
	}
	if finalHits.Load() != 0 {
		t.Fatalf("final server saw %d requests; an out-of-scope hop must never be sent", finalHits.Load())
	}
	if out.RedirectsFollowed != 0 {
		t.Fatalf("redirects_followed = %d, want 0 — nothing was actually sent", out.RedirectsFollowed)
	}
	if hopHits.Load() != 1 {
		t.Fatalf("hop server saw %d requests, want exactly the one initial send", hopHits.Load())
	}
}
