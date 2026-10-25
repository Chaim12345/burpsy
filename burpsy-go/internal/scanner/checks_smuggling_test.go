package scanner

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// The read window's floor is shortened for the whole test binary: five seconds per timed-out probe
// would make the runtime corpus pay twenty seconds per vulnerable listener. The baseline still scales
// the window up on a loaded machine.
func init() {
	smugglingTiming.minSettle = 1500 * time.Millisecond
}

func smugglingScanner(scope *core.Scope) *ActiveScanner {
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.Timeout = 30 * time.Second
	s := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithSender(sender.NewSender(cfg))
	if scope != nil {
		s = s.WithScope(scope)
	}
	return s
}

func smugglingAt(host string, port uint16, tls bool) *CheckContext {
	return NewCheckContext(smugglingScanner(nil), &core.Exchange{
		Host: host, Port: port, TLS: tls, Method: "GET", Path: "/desync/probe?view=1",
	}, nil)
}

// runSmuggling runs the check against one vulnapp listener and returns its findings, the error and
// the number of probes it sent.
func runSmuggling(t *testing.T, name string) ([]*Finding, error, uint32) {
	t.Helper()
	l, err := vulnapp.StartListener(name)
	if err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() { l.Close() })
	meter := &probeMeter{}
	ctx, cancel := context.WithTimeout(withMeter(context.Background(), meter), 2*time.Minute)
	defer cancel()
	findings, err := checkRequestSmuggling(ctx, smugglingAt(l.Host, l.Port, l.TLS))
	return findings, err, meter.sent.Load()
}

// Each vulnerable pairing is reported, with the technique and the Transfer-Encoding spelling that
// produced it.
func TestRequestSmugglingNamesTheTechniqueAndVariant(t *testing.T) {
	cases := map[string]string{
		"desync-clte":            "CL.TE plain",
		"desync-tecl":            "TE.CL plain",
		"desync-clte-obfuscated": "CL.TE space-before-colon",
		"desync-h2-te":           "H2.TE transfer-encoding: chunked",
		"desync-h2-cl":           "H2.CL content-length larger than DATA",
	}
	for name, want := range cases {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			findings, err, _ := runSmuggling(t, name)
			if err != nil {
				t.Fatalf("check failed: %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Name != smugglingRow || f.Param != want {
				t.Errorf("finding = %q / %q, want %q / %q", f.Name, f.Param, smugglingRow, want)
			}
			if !strings.Contains(f.Evidence, "on all 2 sends") || !strings.Contains(f.Evidence, "answered every time") {
				t.Errorf("evidence does not state the repeated timeout and the prompt control: %q", f.Evidence)
			}
		})
	}
}

// The safe twins: hops that agree, a front end that re-frames, an HTTP/2 front end that refuses
// framing mismatches. Each must be probed (sent > 0) and stay quiet.
func TestRequestSmugglingStaysQuietWhenTheHopsAgree(t *testing.T) {
	for _, name := range []string{"desync-compliant", "desync-normalising", "desync-h2-compliant"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			findings, err, sent := runSmuggling(t, name)
			if err != nil {
				t.Fatalf("check failed: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("reported %q (%s) against hops that agree on framing", findings[0].Param, findings[0].Evidence)
			}
			// 1 baseline + per spelling a CL.TE and usually a TE.CL probe; the HTTP/2 listeners add two.
			if sent < uint32(len(teVariants)) {
				t.Errorf("only %d probes were sent; silence here is not evidence", sent)
			}
		})
	}
}

// scriptedTarget is a raw listener that records each request and either answers it or holds it open,
// as hang decides from the request's ordinal and bytes. One request per connection, which is how the
// check sends.
type scriptedTarget struct {
	mu   sync.Mutex
	reqs []string
	host string
	port uint16
}

func startScriptedTarget(t *testing.T, hang func(n int, req string) bool) *scriptedTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &scriptedTarget{host: "127.0.0.1", port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				var b strings.Builder
				for {
					line, err := br.ReadString('\n')
					b.WriteString(line)
					if err != nil || line == "\r\n" {
						break
					}
				}
				// Whatever body the probe carries arrives with the head.
				c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				buf := make([]byte, 4096)
				n, _ := br.Read(buf)
				b.Write(buf[:n])
				st.mu.Lock()
				st.reqs = append(st.reqs, b.String())
				ord := len(st.reqs)
				st.mu.Unlock()
				if hang(ord, b.String()) {
					select {
					case <-stop:
					case <-time.After(30 * time.Second):
					}
					return
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}()
		}
	}()
	return st
}

func (st *scriptedTarget) received() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]string(nil), st.reqs...)
}

// A target that stalls on every request carrying a Transfer-Encoding header stalls the control too.
// That is not a framing disagreement, and the check must say it could not decide rather than report.
func TestRequestSmugglingNeedsAPromptControl(t *testing.T) {
	st := startScriptedTarget(t, func(_ int, req string) bool {
		return strings.Contains(strings.ToLower(req), "transfer-encoding")
	})
	findings, err := checkRequestSmuggling(context.Background(), smugglingAt(st.host, st.port, false))
	if len(findings) != 0 {
		t.Fatalf("reported %q although the consistently framed control stalled too", findings[0].Evidence)
	}
	if !errors.Is(err, errCheckInconclusive) {
		t.Errorf("err = %v, want inconclusive after %d unconfirmed timeouts", err, maxUnconfirmed)
	}
}

// One stalled attack is not a finding: the repeat must time out as well. And once a CL.TE attack has
// timed out for a spelling, the TE.CL attack for that spelling is never sent, because against a CL.TE
// pair it would leave a byte on the back-end connection.
func TestRequestSmugglingRepeatsTheAttackAndNeverFollowsACLTETimeoutWithTECL(t *testing.T) {
	// Request 1 is the baseline, request 2 the first spelling's CL.TE attack.
	st := startScriptedTarget(t, func(n int, _ string) bool { return n == 2 })
	findings, err := checkRequestSmuggling(context.Background(), smugglingAt(st.host, st.port, false))
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("reported %q from a single stalled attack", findings[0].Evidence)
	}
	authority := smugglingAuthority(st.host, st.port, false)
	path := "/desync/probe?view=1"
	plainTECL := string(teclProbe(path, authority, teVariants[0]).attack)
	otherTECL := string(teclProbe(path, authority, teVariants[1]).attack)
	var sawOther bool
	for _, r := range st.received() {
		if r == plainTECL {
			t.Fatal("the TE.CL attack was sent for a spelling whose CL.TE attack had timed out")
		}
		if r == otherTECL {
			sawOther = true
		}
	}
	if !sawOther {
		t.Fatal("no TE.CL attack was sent for any later spelling, so the absence above proves nothing")
	}
}

// Every probe is authorised against the engagement scope before it is dialled.
func TestRequestSmugglingSendsNothingOutsideTheScope(t *testing.T) {
	st := startScriptedTarget(t, func(int, string) bool { return false })
	scope := core.NewScope()
	scope.AddInclude("other.test")
	cc := NewCheckContext(smugglingScanner(scope), &core.Exchange{
		Host: st.host, Port: st.port, Method: "GET", Path: "/",
	}, nil)
	findings, err := checkRequestSmuggling(context.Background(), cc)
	if err == nil || len(findings) != 0 {
		t.Fatalf("findings=%d err=%v, want a refusal", len(findings), err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := st.received(); len(got) != 0 {
		t.Fatalf("%d request(s) reached a target outside the scope", len(got))
	}
}

// Client-side desync's probe runs on the scanner's own connection and consumes its own
// follow-up, so it never leaves anything for a third party's connection. A target that never
// answers leaves the batch unread: the check stays silent - no finding, no error - rather than
// report on half a probe.
func TestClientSideDesyncStaysSilentWhenTheProbeCannotBeRead(t *testing.T) {
	st := startScriptedTarget(t, func(int, string) bool { return false })
	fs, err := checkClientSideDesync(context.Background(), smugglingAt(st.host, st.port, false))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("findings = %v", fs)
	}
}
