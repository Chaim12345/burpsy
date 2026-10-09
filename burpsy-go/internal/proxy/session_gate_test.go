package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// The acceptance claim for the proxy leg's session seam (burpsy-react-ui-9llt): a
// browser-shaped request through the relay against a session rule, and the retried
// request carried the cookie the login macro established. This is the test the
// sender-side and crawler-side session tests cannot be: they prove a rule can be
// honoured by those tools; this proves the leg that carries the operator's browser
// traffic consults the same coordinator.
//
// The origin's shape: /protected answers 401 for a request with no cookie and 200 for
// one carrying it. The first request goes out unauthenticated (the jar starts empty),
// the 401 flags the template, the SECOND request — on a separate browser connection —
// re-logs in through the coordinator's single-flight and carries the fresh cookie. The
// stronger claim the Digest test already makes for its nonce, and the reason the gate's
// state lives on the Server rather than in a socket.
func TestAProxiedRequestAgainstASessionRuleCarriesTheCookieAfterRelogin(t *testing.T) {
	originSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			// The login page AT 200 — the exact case the pattern signal exists for: the
			// application answers an expired (or absent) cookie with the form, and the
			// status-flip rule cannot see it.
			w.Write([]byte("please log in"))
			return
		}
		w.Write([]byte("application content"))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go originSrv.Serve(ln)
	t.Cleanup(func() { originSrv.Close(); ln.Close() })
	host, _, _ := net.SplitHostPort(ln.Addr().String())

	// The coordinator: one rule covering this host whose login macro establishes the
	// cookie. The macro's step runs through the fake runner, which absorbs the login
	// response's Set-Cookie into the jar — mirroring what the real wirer's runner does.
	coord := session.NewCoordinator(zap.NewNop())
	rule := session.NewSessionRule("login", []string{host}, []session.MacroStep{
		{Method: "GET", URL: "http://" + ln.Addr().String() + "/login"},
	})
	if _, err := coord.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	var macroSends int
	var mu sync.Mutex
	runner := func(_ context.Context) session.MacroStepRunner {
		return func(step session.MacroStep) (*session.StepResult, error) {
			mu.Lock()
			macroSends++
			mu.Unlock()
			coord.AbsorbCookie(host, uint16(port16Of(ln.Addr().String())), false, "sessid=fresh")
			return &session.StepResult{Status: 200, Headers: map[string]string{"Set-Cookie": "sessid=fresh"}, Body: []byte("logged in")}, nil
		}
	}

	store := core.NewTrafficStore()
	cfg := NewProxyConfig(store).
		WithScope(core.NewScopeAllowEverything()).
		WithSessionCoordinator(coord, runner).
		WithLogger(zap.NewNop())
	cfg.LoginPagePattern = regexp.MustCompile("please log in")
	srv := NewServer(cfg)
	proxyAddr := startProxyListener(t, srv)

	var statuses []int
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(conn, "GET /protected HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr())
		br := bufio.NewReader(conn)
		line, _ := br.ReadString('\n')
		status := 0
		fmt.Sscanf(line, "HTTP/1.1 %d", &status)
		statuses = append(statuses, status)
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		conn.Close()

		if i == 0 {
			// The flag the second request reads is set by noteProxiedResponse, which runs from
			// record() - and record() runs AFTER the response has been relayed to the client.
			// Reading the response therefore does not mean the template is flagged yet, and a
			// second request sent straight away could race ahead of the flag: it then went out
			// with no re-login, the macro ran 0 times, and the test failed on its scheduling
			// rather than on the gate (seen on loaded CI runners and locally ~1 in 900 runs).
			//
			// The row landing in the store is the event to wait for: record() flags the
			// template before it indexes the row, so once the row exists the flag does too.
			//
			// The window is real outside the test as well: a request that reaches the proxy in
			// the instant between a flagged response being relayed and being recorded goes out
			// without a re-login. This test's claim is what the gate does for a request sent
			// after the template is flagged, so it now waits for that ordering instead of
			// assuming it.
			deadline := time.Now().Add(10 * time.Second)
			for len(store.Exchanges()) == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if len(store.Exchanges()) == 0 {
				t.Fatal("the first request's exchange never reached history, so the template could " +
					"not have been flagged before the second request")
			}
		}
	}

	if len(statuses) != 2 || statuses[0] != http.StatusOK {
		t.Errorf("the first request answered %v, want 200: the login page at 200 is the exact case "+
			"the pattern signal exists for, and it is what flags the template", statuses)
	}
	if statuses[1] != http.StatusOK {
		t.Errorf("the second request answered %d, want 200: the gate re-logged in and the retried "+
			"request carried the cookie the macro established (burpsy-react-ui-9llt)", statuses[1])
	}
	mu.Lock()
	sends := macroSends
	mu.Unlock()
	if sends != 1 {
		t.Errorf("the login macro ran %d times; the coordinator's single-flight per rule means the "+
			"flagged template produces one login, not one per request", sends)
	}
}

// port16Of splits a host:port into the port as an int, 0 when it cannot.
func port16Of(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
