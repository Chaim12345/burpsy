package vulnapp

// Cross-site WebSocket hijacking and spoofable client-IP headers (scanner/checks_ws_hijack.go,
// scanner/checks_client_ip.go).
//
// The WebSocket routes are a hand-rolled RFC 6455 server: accept the upgrade, send one greeting text
// frame, send a close, drop the socket. Nothing is read from the client; the greeting is the whole
// conversation, which is what the scanner compares.

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// The captured handshake every WebSocket route is seeded with: a browser on the application's own
// origin, logged in as alice.
const wsipOwnOrigin = "https://app.vulnapp.test"

func wsipHandshakeHeaders(cookie bool) map[string]string {
	h := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin":                wsipOwnOrigin,
	}
	if cookie {
		h["Cookie"] = "session=alice"
	}
	return h
}

func wsipEndpoints() []Endpoint {
	const cswsh = "Cross-site WebSocket hijacking"
	const acl = "Access control bypass via spoofed client IP header"
	const rl = "Rate limit bypass via spoofed client IP header"
	const spoof = "Spoofable client IP address"
	return []Endpoint{
		{Path: "/wsip/ws/chat", Row: cswsh, RequestHeaders: wsipHandshakeHeaders(true),
			Note: "cookie-authenticated socket (no cookie: 401) that never checks Origin"},
		{Path: "/wsip/ws/feed", Row: cswsh, RequestHeaders: wsipHandshakeHeaders(true),
			Note: "socket open to anyone, greeting names the cookie's user (guest without one); Origin unchecked"},
		{Path: "/wsip/safe/ws/chat", Row: cswsh, Safe: true, RequestHeaders: wsipHandshakeHeaders(true),
			Note: "cookie-authenticated socket that refuses (403) any Origin but the application's own"},
		{Path: "/wsip/safe/ws/public", Row: cswsh, Safe: true, RequestHeaders: wsipHandshakeHeaders(true),
			Note: "public socket, Origin unchecked, same greeting with or without cookies: nothing to hijack"},
		{Path: "/wsip/safe/ws/token?ticket=Tk7f3a9c2e1b8d4f6a0", Row: cswsh, Safe: true,
			RequestHeaders: wsipHandshakeHeaders(true),
			Note:           "socket that needs a per-session ticket in the URL a cross-site page cannot know"},

		{Path: "/wsip/admin", Row: acl,
			Note: "internal page admitted only when X-Forwarded-For's first address is loopback"},
		{Path: "/wsip/tci/admin", Row: acl,
			Note: "internal page admitted only when True-Client-IP is loopback"},
		{Path: "/wsip/safe/admin", Row: acl, Safe: true,
			Note: "internal page restricted by the socket address alone; client-IP headers ignored"},
		{Path: "/wsip/safe/via-proxy", Row: acl, Safe: true,
			Note: "page served to any request that carries X-Forwarded-For at all, whatever the address"},

		// The rate-limit pair declares no Row: a route that answers its captured request 429 puts every
		// step of a whole-corpus audit behind the scanner's 2 s auto-backoff (99 waits, 200 s measured),
		// so checks_client_ip_test.go audits them with only this check's switch on instead.
		{Path: "/wsip/ratelimit?report=annual",
			Note: rl + ": per-report limiter keyed on X-Forwarded-For (else the socket address, already exhausted)"},
		{Path: "/wsip/safe/ratelimit?report=annual",
			Note: rl + " (safe): per-report limiter keyed on the socket address only, already exhausted"},
		{Path: "/wsip/safe/ratelimit-lapsing",
			Note: rl + " (safe): answers 429 to its first two requests and never again, whatever the headers " +
				"(counted per ?run= value, so an audit can start its own lapse)"},

		{Path: "/wsip/whoami", Row: spoof,
			Note: "page greets the client by the address in X-Real-IP"},
		{Path: "/wsip/safe/whoami", Row: spoof, Safe: true,
			Note: "page greets the client by its socket address; headers ignored"},
		{Path: "/wsip/safe/echo-headers", Row: spoof, Safe: true,
			Note: "debug page echoing every request header: reflection without the address being used"},
	}
}

func wsipAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsipServeSocket accepts the upgrade, sends greeting as one text frame and a close, and drops it.
func wsipServeSocket(w http.ResponseWriter, r *http.Request, greeting string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsipAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
	_, _ = rw.WriteString(resp)
	_, _ = rw.Write(wsipFrame(0x1, []byte(greeting)))
	_, _ = rw.Write(wsipFrame(0x8, []byte{0x03, 0xe8}))
	_ = rw.Flush()
}

// wsipFrame encodes one unmasked server frame (payloads here are short).
func wsipFrame(op byte, payload []byte) []byte {
	out := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		out = append(out, byte(n))
	default:
		out = append(out, 126, byte(n>>8), byte(n))
	}
	return append(out, payload...)
}

func wsipIsUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && r.Header.Get("Sec-WebSocket-Key") != ""
}

func wsipUser(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// wsipFirstForwarded is the first address of X-Forwarded-For, as an application that trusts it reads it.
func wsipFirstForwarded(r *http.Request) string {
	first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ",")
	return strings.TrimSpace(first)
}

func wsipSocketHost(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// wsipLimiter is a fixed-budget limiter per client and report, whose loopback budget for the annual
// report is already spent (the fixture's history: this client has been regenerating it).
type wsipLimiter struct {
	mu   sync.Mutex
	used map[string]int
}

const wsipBudget = 5

func newWsipLimiter() *wsipLimiter {
	return &wsipLimiter{used: map[string]int{"127.0.0.1|annual": wsipBudget, "::1|annual": wsipBudget}}
}

func (l *wsipLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[key] >= wsipBudget {
		return false
	}
	l.used[key]++
	return true
}

func registerWsip(mux *http.ServeMux) {
	notSocket := func(w http.ResponseWriter) { http.Error(w, "WebSocket endpoint", http.StatusUpgradeRequired) }

	mux.HandleFunc("/wsip/ws/chat", func(w http.ResponseWriter, r *http.Request) {
		if !wsipIsUpgrade(r) {
			notSocket(w)
			return
		}
		user := wsipUser(r)
		if user == "" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		wsipServeSocket(w, r, fmt.Sprintf(`{"type":"history","user":%q,"messages":["hi bob"]}`, user))
	})
	mux.HandleFunc("/wsip/ws/feed", func(w http.ResponseWriter, r *http.Request) {
		if !wsipIsUpgrade(r) {
			notSocket(w)
			return
		}
		user := wsipUser(r)
		if user == "" {
			user = "guest"
		}
		wsipServeSocket(w, r, "welcome "+user)
	})
	mux.HandleFunc("/wsip/safe/ws/chat", func(w http.ResponseWriter, r *http.Request) {
		if !wsipIsUpgrade(r) {
			notSocket(w)
			return
		}
		if r.Header.Get("Origin") != wsipOwnOrigin {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		user := wsipUser(r)
		if user == "" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		wsipServeSocket(w, r, fmt.Sprintf(`{"type":"history","user":%q}`, user))
	})
	mux.HandleFunc("/wsip/safe/ws/public", func(w http.ResponseWriter, r *http.Request) {
		if !wsipIsUpgrade(r) {
			notSocket(w)
			return
		}
		wsipServeSocket(w, r, "ticker: ACME 101.5")
	})
	mux.HandleFunc("/wsip/safe/ws/token", func(w http.ResponseWriter, r *http.Request) {
		if !wsipIsUpgrade(r) {
			notSocket(w)
			return
		}
		if r.URL.Query().Get("ticket") != "Tk7f3a9c2e1b8d4f6a0" || wsipUser(r) == "" {
			http.Error(w, "ticket required", http.StatusUnauthorized)
			return
		}
		wsipServeSocket(w, r, "welcome "+wsipUser(r))
	})

	admin := func(w http.ResponseWriter, ok bool) {
		w.Header().Set("Content-Type", "text/html")
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><body>Forbidden: the admin console is available to local users only.</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><h1>Admin console</h1><ul><li>alice</li><li>bob</li></ul></body></html>"))
	}
	isLoop := func(ip string) bool { return ip == "127.0.0.1" || ip == "::1" }
	mux.HandleFunc("/wsip/admin", func(w http.ResponseWriter, r *http.Request) {
		// Behind a proxy that (the application assumes) always sets the header; the socket address is
		// the proxy's and is not consulted.
		admin(w, isLoop(wsipFirstForwarded(r)))
	})
	mux.HandleFunc("/wsip/tci/admin", func(w http.ResponseWriter, r *http.Request) {
		admin(w, isLoop(strings.TrimSpace(r.Header.Get("True-Client-IP"))))
	})
	mux.HandleFunc("/wsip/safe/admin", func(w http.ResponseWriter, r *http.Request) {
		// The management network, by socket address; the test harness never connects from it.
		admin(w, strings.HasPrefix(wsipSocketHost(r), "10."))
	})
	mux.HandleFunc("/wsip/safe/via-proxy", func(w http.ResponseWriter, r *http.Request) {
		admin(w, r.Header.Get("X-Forwarded-For") != "")
	})

	limited := func(w http.ResponseWriter, ok bool) {
		if !ok {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("search results: 0 items"))
	}
	vuln, safe := newWsipLimiter(), newWsipLimiter()
	mux.HandleFunc("/wsip/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		key := wsipFirstForwarded(r)
		if key == "" {
			key = wsipSocketHost(r)
		}
		limited(w, vuln.allow(key+"|"+r.URL.Query().Get("report")))
	})
	mux.HandleFunc("/wsip/safe/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		limited(w, safe.allow(wsipSocketHost(r)+"|"+r.URL.Query().Get("report")))
	})

	// The lapse is counted per `run` query value, not for the route as a whole. One process-wide
	// counter was spent by whatever reached the route first — the corpus seeding, a whole-corpus
	// sweep, an earlier audit in the same test binary — so an audit that came later found the limit
	// long gone, its baseline answered 200, and the rate-limit test never ran: two requests, no
	// verdict (burpsy-react-ui-qgtr). A caller that needs the lapse to start fresh names its own run.
	var lapsingMu sync.Mutex
	lapsing := map[string]int{}
	mux.HandleFunc("/wsip/safe/ratelimit-lapsing", func(w http.ResponseWriter, r *http.Request) {
		run := r.URL.Query().Get("run")
		lapsingMu.Lock()
		lapsing[run]++
		n := lapsing[run]
		lapsingMu.Unlock()
		limited(w, n > 2)
	})

	mux.HandleFunc("/wsip/whoami", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.Header.Get("X-Real-IP"))
		if ip == "" {
			ip = wsipSocketHost(r)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body>Signed in from %s</body></html>", ip)
	})
	mux.HandleFunc("/wsip/safe/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><body>Signed in from %s</body></html>", wsipSocketHost(r))
	})
	mux.HandleFunc("/wsip/safe/echo-headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for name, vs := range r.Header {
			for _, v := range vs {
				_, _ = fmt.Fprintf(w, "%s: %s\n", name, v)
			}
		}
	})
}
