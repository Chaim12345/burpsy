package web

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
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// The attack this closes: the operator's scope excludes /admin on the target, and a payload
// spliced into a path-position insertion point rewrites the request line to /admin. The host
// check authorises the host; only the per-request check against the actual outbound bytes can
// catch the path. This is the Rust web layer's `intruder_run` wiring, without the HTTP handler.

// recordServer answers every request and remembers the request lines it saw.
func recordServer(t *testing.T) (string, *[]string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var seen []string
	var mu sync.Mutex
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
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				seen = append(seen, strings.TrimSuffix(line, "\r\n"))
				mu.Unlock()
				// Drain the rest so the request fully arrives before we answer.
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						break
					}
					if l == "\r\n" || l == "\n" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}(conn)
		}
	}()
	return ln.Addr().String(), &seen
}

func TestAnAttackPayloadThatRewritesThePathOutOfScopeIsNeverSent(t *testing.T) {
	addr, seen := recordServer(t)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))

	auth := sender.NewAuthorisedSender(scope, sender.NewSender(sender.DefaultSenderConfig()), "127.0.0.1", uint16(port), false)
	send := func(raw []byte) (intruder.Sent, error) {
		res, err := auth.Send(context.Background(), raw)
		if err != nil {
			return intruder.Sent{}, err
		}
		return intruder.Sent{Raw: res.Raw, Duration: res.Duration, Status: res.Status}, nil
	}

	store := core.NewTrafficStore()
	id, err := store.Put([]byte("GET /search HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	points := intruder.FindPoints(msg, &intruder.PointConfig{URLPathFile: true})
	var pathPoint *intruder.InsertionPoint
	for i := range points {
		if points[i].Kind == intruder.PointURLPathFilename {
			pathPoint = &points[i]
			break
		}
	}
	if pathPoint == nil {
		t.Fatalf("no path-position point found; points = %+v", points)
	}

	// "good" stays on an authorised path; "admin/delete-all" rewrites the request line's path to
	// /admin/delete-all, which the scope excludes. (The filename insertion point covers the
	// segment without its leading slash, so the payload carries the slash itself.)
	payloads := []intruder.PayloadSet{{
		Kind: "list", Items: []string{"good", "admin/delete-all"}, Count: 2,
		Total: 2, TotalExact: true,
	}}
	plan := intruder.NewAttackPlan(intruder.AttackKindSniper, 1, []int{2}, 100)
	a := intruder.NewAttack(msg.Raw(), []intruder.InsertionPoint{*pathPoint}, payloads, plan).
		WithLimits(intruder.Unthrottled(1))

	report := intruder.Run(a, send, nil)

	if report.Sent != 1 {
		t.Fatalf("sent = %d, want exactly the one in-scope request", report.Sent)
	}
	if report.Failed != 1 {
		t.Fatalf("failed = %d, want the refused payload counted as a failure, not dropped", report.Failed)
	}
	// The server must have seen only /good. /admin never reached it. The run has finished, so no
	// further writes to the slice can race the read.
	if len(*seen) != 1 {
		t.Fatalf("the target saw %d requests, want 1: %v", len(*seen), *seen)
	}
	if got := (*seen)[0]; got != "GET /good HTTP/1.1" {
		t.Fatalf("the request that went out is %q, want the in-scope /good", got)
	}
	if auth.Refused() != 1 || auth.Sent() != 1 {
		t.Fatalf("sender counters sent/refused = %d/%d, want 1/1", auth.Sent(), auth.Refused())
	}
}

// The refusal must not have silently swallowed the attack's own reporting: the failed ordinal
// carries the scope reason so the operator can see why a payload never got sent.
func TestTheRefusedPayloadIsReportedAsAReasonNotSilence(t *testing.T) {
	addr, _ := recordServer(t)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))

	auth := sender.NewAuthorisedSender(scope, sender.NewSender(sender.DefaultSenderConfig()), "127.0.0.1", uint16(port), false)
	send := func(raw []byte) (intruder.Sent, error) {
		res, err := auth.Send(context.Background(), raw)
		if err != nil {
			return intruder.Sent{}, err
		}
		return intruder.Sent{Raw: res.Raw, Duration: res.Duration, Status: res.Status}, nil
	}

	store := core.NewTrafficStore()
	id, err := store.Put([]byte("GET /search HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\n\r\n"), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := store.Get(id)
	points := intruder.FindPoints(msg, &intruder.PointConfig{URLPathFile: true})
	var pathPoint *intruder.InsertionPoint
	for i := range points {
		if points[i].Kind == intruder.PointURLPathFilename {
			pathPoint = &points[i]
			break
		}
	}
	if pathPoint == nil {
		t.Fatalf("no path-position point found")
	}
	payloads := []intruder.PayloadSet{{
		Kind: "list", Items: []string{"admin/delete-all"}, Count: 1, Total: 1, TotalExact: true,
	}}
	plan := intruder.NewAttackPlan(intruder.AttackKindSniper, 1, []int{1}, 100)
	a := intruder.NewAttack(msg.Raw(), []intruder.InsertionPoint{*pathPoint}, payloads, plan).
		WithLimits(intruder.Unthrottled(1))

	report := intruder.Run(a, send, nil)

	if report.Failed != 1 || len(report.Errors) != 1 {
		t.Fatalf("failed = %d, errors = %d, want a single grouped refusal", report.Failed, len(report.Errors))
	}
	if !strings.Contains(report.Errors[0].Error, "/admin") {
		t.Fatalf("the refusal must say which path: %q", report.Errors[0].Error)
	}
	if len(report.Attempts) != 1 || report.Attempts[0].Error == nil {
		t.Fatalf("the attempt must carry the reason: %+v", report.Attempts)
	}
}
