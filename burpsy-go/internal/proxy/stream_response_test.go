package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// The defect burpsy-react-ui-wet3 records: the proxy buffered every response, so an open-ended one
// produced no bytes at all until it ended — and on an SSE stream it never ends. The client saw a
// hung request.
//
// The test drives a real origin that sends an event, pauses, sends another, and keeps the connection
// open. It then asserts the FIRST event reached the client while the origin was still holding the
// connection, which is the only claim that distinguishes streaming from buffering: a buffered proxy
// passes every assertion about the final body and fails this one.

func TestAnOpenEndedResponseReachesTheClientWhileTheOriginIsStillSending(t *testing.T) {
	// The origin's own script: an event, a pause long enough that a buffered proxy would still be
	// waiting, then another event, and then it holds the connection open.
	release := make(chan struct{})
	// sync.Once so the goroutine's release and the test's cleanup cannot both close it. The origin
	// holds the response open until this fires, so it has to happen exactly once.
	var releaseOnce sync.Once
	releaseOrigin := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseOrigin()
	origin := startStreamingOrigin(t, make(chan struct{}), release)

	store := core.NewTrafficStore()
	_, proxyAddr := startPlainProxy(t, store, testScope())

	type readResult struct {
		line string
		err  error
	}
	lines := make(chan readResult, 4)
	go func() {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			lines <- readResult{err: err}
			return
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /events HTTP/1.1\r\nHost: %s\r\nAccept: text/event-stream\r\n\r\n", origin)
		br := bufio.NewReader(conn)
		events := 0
		// Read until both events have arrived rather than for a fixed line count: the head is
		// several lines, and a fixed count would stop inside the headers and prove nothing about the
		// body. The release fires after the FIRST event, so the second can only arrive if the
		// connection survived the origin's pause — which is the claim under test.
		for events < 2 {
			line, err := br.ReadString('\n')
			if err != nil {
				lines <- readResult{err: err}
				return
			}
			lines <- readResult{line: line}
			if strings.HasPrefix(line, "data: ") {
				events++
				if events == 1 {
					releaseOrigin()
				}
			}
		}
	}()

	// The head, then the first event, must arrive while the origin is still holding the connection.
	// A buffered proxy sends neither until the response ends, and the origin does not end it until
	// released — so this select times out on the old behaviour rather than hanging the test.
	deadline := time.After(5 * time.Second)
	var got []string
	events := 0
	for events < 2 {
		select {
		case r := <-lines:
			if r.err != nil {
				t.Fatalf("client read failed before the stream was delivered: %v\nwhat arrived: %v", r.err, got)
			}
			line := strings.TrimRight(r.line, "\r\n")
			got = append(got, line)
			if strings.HasPrefix(line, "data: ") {
				events++
			}
		case <-deadline:
			t.Fatalf("the client received %d event(s) while the origin was still sending: %v\n"+
				"a proxy that buffers an open-ended response sends nothing until it ends, and this one never does "+
				"(burpsy-react-ui-wet3)", events, got)
		}
	}

	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "HTTP/1.1 200") {
		t.Errorf("no status line in what the client received: %q", joined)
	}
	if !strings.Contains(joined, "data: first") {
		t.Errorf("the first event never arrived: %q", joined)
	}
	if !strings.Contains(joined, "data: second") {
		t.Errorf("the second event never arrived, so the connection did not stay usable across chunks: %q", joined)
	}
}

// A streamed exchange is recorded like any other, with a note saying it never ended — so an operator
// reading history can tell a truncated stream from a short response.
func TestAStreamedResponseIsRecordedAndSaysItNeverEnded(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseOrigin := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseOrigin()
	origin := startStreamingOrigin(t, make(chan struct{}), release)

	store := core.NewTrafficStore()
	srv, proxyAddr := startPlainProxy(t, store, testScope())

	// A short window, so the test does not wait the default half minute for the stream to be cut.
	if err := srv.config.Streaming().Set(nil, 400*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}

	go func() {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /events HTTP/1.1\r\nHost: %s\r\n\r\n", origin)
		br := bufio.NewReader(conn)
		// Read until the connection goes quiet, which is the window closing.
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
		}
	}()

	// Wait for the record rather than sleeping a fixed time: the exchange is created when the
	// response is completed, which is when the window closes.
	deadline := time.Now().Add(6 * time.Second)
	var found *core.Exchange
	for time.Now().Before(deadline) {
		for _, ex := range store.Exchanges() {
			if ex != nil && strings.Contains(ex.Path, "/events") {
				found = ex
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if found == nil {
		t.Fatal("no exchange was recorded for the streamed response; the client got bytes and history got nothing")
	}
	if found.Notes == nil {
		t.Fatal("the recorded stream carries no note: a response the peer never ended is a different fact from a short one, and history has to say which it was")
	}
	if !strings.Contains(*found.Notes, "open-ended response") {
		t.Errorf("notes = %q, want the open-ended explanation", *found.Notes)
	}
	if found.ResponseLen == 0 {
		t.Error("the recorded response is empty: what the client received must be what history shows")
	}
}

// A response that frames itself is never streamed, however long it takes. Match & Replace and the
// intercept hold are entitled to see the whole message before any of it reaches the client, and a
// Content-Length says the message has an end.
func TestAFramedResponseIsNotStreamed(t *testing.T) {
	body := "complete body"
	srv := httptestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	head := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body)))
	if httputil.ResponseIsFrameless(head) {
		t.Error("a Content-Length response was treated as open-ended; its end is knowable, so it must be buffered")
	}

	chunked := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	if httputil.ResponseIsFrameless(chunked) {
		t.Error("a chunked response was treated as open-ended; a terminal chunk says where it ends")
	}

	unframed := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
	if !httputil.ResponseIsFrameless(unframed) {
		t.Error("an unframed response was not treated as open-ended, which is the case this path exists for")
	}
}

// startStreamingOrigin runs a real HTTP server that emits one event, waits for the test to say so,
// emits a second, and then holds the connection open until the test releases it.
//
// The pause between the two events is what makes the streaming claim falsifiable: a buffered proxy
// sends nothing during that pause, because it is waiting for an end that never comes.
func startStreamingOrigin(t *testing.T, firstSent chan struct{}, release <-chan struct{}) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		w.Write([]byte("data: first\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
		close(firstSent)
		// Hold the response open. This is the whole shape: an SSE feed does not end.
		<-release
		w.Write([]byte("data: second\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// startPlainProxy starts the proxy with an in-memory store and returns the server and its address.
func startPlainProxy(t *testing.T, store *core.TrafficStore, scope *core.Scope) (*Server, string) {
	t.Helper()
	cfg := NewProxyConfig(store).
		WithScope(scope).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop()))
	srv := NewServer(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	return srv, ln.Addr().String()
}

// httptestServer is a helper for the framing test, which needs a real response but no listener.
func httptestServer(t *testing.T, h http.Handler) *http.Server {
	t.Helper()
	return &http.Server{Handler: h}
}
