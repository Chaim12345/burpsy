package sender

// The scanner's single-packet race surface (burpsy-react-ui-0vzb.8): a synchronized group
// through the scope/pacing gate, mirroring the Repeater orchestration in
// internal/web/api_repeater_group.go.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// countingListener counts accepted connections, so a refused or declined group can prove the
// transport was never reached.
type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func serveOkOver(t *testing.T, ln net.Listener) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
}

func groupRaws(host string, n int) [][]byte {
	raws := make([][]byte, n)
	for i := range raws {
		raws[i] = []byte("GET /race HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	}
	return raws
}

// A scope refusal refuses the whole group before any byte is written, and the refusal is
// counted like a Send refusal.
func Test_a_synchronized_group_refused_on_scope_writes_nothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	serveOkOver(t, cl)
	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	sc := core.NewScope()
	sc.AddExclude("127.0.0.1")
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), host, port, false)

	results, err := a.SendSynchronizedGroup(context.Background(), groupRaws(host, 3))
	if err == nil {
		t.Fatal("an out-of-scope group sent anyway")
	}
	if results != nil {
		t.Fatalf("a refused group returned %d per-member results, want none: nothing ran", len(results))
	}
	if got := cl.accepted.Load(); got != 0 {
		t.Fatalf("the target accepted %d connections from a refused group", got)
	}
	if a.Sent() != 0 {
		t.Fatalf("sent = %d after a scope refusal, want 0", a.Sent())
	}
	if a.Refused() != 1 {
		t.Fatalf("refused = %d, want the group refusal counted once", a.Refused())
	}
}

// The point of the mode: no member's final byte leaves until every member is holding its
// own. Made deterministic with one member whose request far exceeds the kernel's buffers:
// its partial write cannot complete (and so cannot signal readiness) until the server drains
// it, which gives the small member's held final byte a hard, observable reason to wait.
func Test_a_synchronized_group_holds_every_final_byte_until_all_members_are_ready(t *testing.T) {
	const bodyBytes = 32 << 20

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	smallRaw := []byte("GET /small HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	bigRaw := []byte("POST /big HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: " +
		strconv.Itoa(bodyBytes) + "\r\n\r\n" + strings.Repeat("x", bodyBytes))

	releasedEarly := make(chan bool, 1)
	go func() {
		var conns []net.Conn
		for len(conns) < 2 {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
		defer conns[0].Close()
		defer conns[1].Close()
		brs := [2]*bufio.Reader{bufio.NewReader(conns[0]), bufio.NewReader(conns[1])}

		// Five bytes identify each member ("GET /" vs "POST ") without over-reading.
		small, big := 0, 1
		tags := [2][]byte{{}, {}}
		for i, br := range brs {
			tag := make([]byte, 5)
			if _, err := io.ReadFull(br, tag); err != nil {
				return
			}
			tags[i] = tag
		}
		if bytes.HasPrefix(tags[0], []byte("POST")) {
			small, big = 1, 0
		}
		// The small member's partial write is its request minus the final newline: read
		// exactly that many bytes, so no read can swallow the held byte.
		rest := make([]byte, len(smallRaw)-1-5)
		if _, err := io.ReadFull(brs[small], rest); err != nil {
			return
		}

		// The big member is still blocked mid-write: nothing has drained its body, so its
		// readiness signal cannot have fired and the barrier must still hold the small
		// member's final byte. A read that finds it proves an early release.
		_ = conns[small].SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := brs[small].ReadByte(); err == nil {
			releasedEarly <- true
			return
		}
		_ = conns[small].SetReadDeadline(time.Time{})

		// Drain the big member: head to the blank line, then the body, then its held byte.
		_ = conns[big].SetReadDeadline(time.Now().Add(30 * time.Second))
		var head []byte
		for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
			b, err := brs[big].ReadByte()
			if err != nil {
				return
			}
			head = append(head, b)
		}
		if _, err := io.CopyN(io.Discard, brs[big], int64(bodyBytes)-1); err != nil {
			return
		}
		if _, err := brs[big].ReadByte(); err != nil {
			return
		}

		// Drained: the barrier must have released, so the small member's final byte arrives.
		_ = conns[small].SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := brs[small].ReadByte(); err != nil {
			return
		}
		releasedEarly <- false
		for i := range conns {
			_, _ = conns[i].Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		}
	}()

	sc := core.NewScope()
	sc.AddInclude("127.0.0.1")
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), host, port, false)
	if _, err := a.SendSynchronizedGroup(context.Background(), [][]byte{smallRaw, bigRaw}); err != nil {
		t.Fatalf("the group send failed: %v", err)
	}

	select {
	case early := <-releasedEarly:
		if early {
			t.Fatal("the small member's final byte left while the big member was still writing: the barrier released early")
		}
	case <-time.After(45 * time.Second):
		t.Fatal("the server never saw the group through")
	}
}

// The evidence the mode exists to produce: a check-then-set endpoint falls to four
// simultaneous arrivals and stands against four sequential ones.
func Test_a_synchronized_group_beats_a_check_then_set_endpoint_that_sequential_sends_lose(t *testing.T) {
	var mu sync.Mutex
	taken := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		already := taken
		mu.Unlock()
		// The race window: wide enough that scheduler order decides a sequential run, and
		// simultaneity decides a synchronized one.
		time.Sleep(50 * time.Millisecond)
		if already {
			_, _ = w.Write([]byte("LOSE"))
			return
		}
		mu.Lock()
		taken = true
		mu.Unlock()
		_, _ = w.Write([]byte("WIN"))
	}))
	defer srv.Close()

	host, port, err := hostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScope()
	sc.AddInclude("127.0.0.1")
	a := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), host, port, false)

	wins := func(results []AuthorisedResult) int {
		n := 0
		for _, r := range results {
			if strings.HasSuffix(string(r.Raw), "WIN") {
				n++
			}
		}
		return n
	}

	var sequential []AuthorisedResult
	for range 4 {
		res, err := a.Send(context.Background(), groupRaws(host, 1)[0])
		if err != nil {
			t.Fatalf("sequential send: %v", err)
		}
		sequential = append(sequential, res)
	}
	if got := wins(sequential); got != 1 {
		t.Fatalf("sequential sends won %d times, want exactly 1 - the endpoint is not check-then-set", got)
	}

	mu.Lock()
	taken = false
	mu.Unlock()
	group, err := a.SendSynchronizedGroup(context.Background(), groupRaws(host, 4))
	if err != nil {
		t.Fatalf("the group send failed: %v", err)
	}
	if got := wins(group); got < 2 {
		t.Fatalf("the synchronized group won %d times: simultaneity beat the race no more than sequential sends did", got)
	}
}

// Decline, never stagger: a pacer that cannot reserve the whole group atomically refuses the
// group with a distinguishable kind, and no bytes leave.
func Test_a_synchronized_group_declines_when_pacing_cannot_admit_it_atomically(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	serveOkOver(t, cl)
	host, port, err := hostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := core.NewScope()
	sc.AddInclude("127.0.0.1")

	// A pacer with no group contract: per-send pacing is all it knows, and per-send pacing of
	// a synchronized group would stagger the releases the mode exists to align.
	single := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), host, port, false).
		WithPace(paceFunc(func(ctx context.Context) (func(), error) { return func() {}, nil }))
	results, err := single.SendSynchronizedGroup(context.Background(), groupRaws(host, 2))
	if err == nil {
		t.Fatal("a group behind a per-send-only pacer sent anyway")
	}
	if len(results) != 2 {
		t.Fatalf("want one declined result per member, got %d", len(results))
	}
	for i, r := range results {
		if r.Failure != SendFailurePacing {
			t.Fatalf("member %d failure kind = %v, want the pacing decline", i, r.Failure)
		}
		if r.Err == nil {
			t.Fatalf("member %d carries no reason for the decline", i)
		}
	}
	if got := cl.accepted.Load(); got != 0 {
		t.Fatalf("the target accepted %d connections from a declined group", got)
	}
	if single.Sent() != 0 {
		t.Fatalf("sent = %d after a pacing decline, want 0", single.Sent())
	}

	// A group-capable pacer whose pool cannot admit the group declines the same way, with the
	// limiter's own reason.
	blocked := NewAuthorisedSender(sc, NewSender(DefaultSenderConfig()), host, port, false).
		WithPace(groupPaceFunc(func(ctx context.Context, n int) (func(), error) {
			return nil, errGroupAdmit
		}))
	if _, err := blocked.SendSynchronizedGroup(context.Background(), groupRaws(host, 2)); !errors.Is(err, errGroupAdmit) {
		t.Fatalf("want the limiter's decline reason, got %v", err)
	}
}

var errGroupAdmit = errors.New("declined: the pool cannot admit 2 requests at once")

type paceFunc func(ctx context.Context) (func(), error)

func (f paceFunc) Pace(ctx context.Context) (func(), error) { return f(ctx) }

type groupPaceFunc func(ctx context.Context, n int) (func(), error)

func (f groupPaceFunc) Pace(ctx context.Context) (func(), error) { return func() {}, nil }
func (f groupPaceFunc) PaceN(ctx context.Context, n int) (func(), error) {
	return f(ctx, n)
}
