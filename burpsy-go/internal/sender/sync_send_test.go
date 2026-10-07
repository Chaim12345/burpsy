package sender

// The synchronized send's barrier (burpsy-react-ui-ajp6), pinned where its contract lives.
//
// The group orchestrator's promise is that a member's final byte is written only after every
// member has signalled readiness. That is a property of THIS package's sequencing, so the test
// drives it with a recording conn: the write sequence (head, hold, final byte) is observable
// on a pipe, with no origin scheduling in the loop to blur it — a real TCP origin measures
// its own reading schedule, which is noise on top of the signal (measured while writing the
// web-level version: a handler-stamped origin failed intermittently against the
// correctly-working barrier).

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// recordingConn captures every write with a sequence number, so the test can assert that the
// final byte's write came after the release — and, under the mutation, that it did not.
type recordingConn struct {
	writes  chan []byte
	closed  chan struct{}
	written [][]byte
}

func newRecordingConn() *recordingConn {
	return &recordingConn{writes: make(chan []byte, 16), closed: make(chan struct{})}
}

func (c *recordingConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	c.writes <- cp
	c.written = append(c.written, cp)
	return len(b), nil
}

func (c *recordingConn) Read(b []byte) (int, error) { <-c.closed; return 0, nil }
func (c *recordingConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *recordingConn) LocalAddr() net.Addr                { return nil }
func (c *recordingConn) RemoteAddr() net.Addr               { return nil }
func (c *recordingConn) SetDeadline(t time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(t time.Time) error { return nil }

// A send in hold mode writes everything but the final byte, signals, and writes the last byte
// only after release. The recording proves the two events happened in that order.
func TestASynchronizedSendHoldsItsFinalByteUntilRelease(t *testing.T) {
	s := &Sender{}
	conn := newRecordingConn()
	defer conn.Close()
	ready := make(chan struct{}, 1)
	release := make(chan struct{})
	sync := SyncPoints{Ready: ready, Release: release}

	raw := []byte("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc")
	done := make(chan error, 1)
	go func() {
		_, _, err := s.sendSynchronizedOn(ctxBG(), conn, raw, sync)
		done <- err
	}()

	// Phase 1: the head arrives, readiness is signalled, and the final byte is NOT written.
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("the send never signalled readiness — the orchestrator would wait forever")
	}
	// The head write precedes readiness and is EXPECTED to be queued here — the two-phase
	// write is the design. What must NOT be queued is the FINAL BYTE: a fan-out send writes
	// both halves before signalling, so after draining the head there must be nothing left.
	// The head write is the design's first half: everything but the final byte.
	select {
	case w := <-conn.writes:
		if bytes.Equal(w, raw) {
			t.Fatal("the whole request was written before release: the final byte was not held")
		}
		if !bytes.Equal(w, raw[:len(raw)-1]) {
			t.Fatalf("the held write is not the request-minus-its-last-byte: %q", w)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no head write arrived before readiness")
	}
	// The barrier's guarantee at the readiness moment: nothing more is pending. A fan-out
	// send writes both halves before it signals, so a second queued write here is the exact
	// mutation this test exists to catch.
	select {
	case w := <-conn.writes:
		t.Fatalf("a second write was pending at the readiness signal: %q — the final byte was not held", w)
	default:
	}

	// Release, and the final byte goes out.
	close(release)
	select {
	case w := <-conn.writes:
		if !bytes.Equal(w, raw[len(raw)-1:]) {
			t.Fatalf("the post-release write is %q, want exactly the held final byte %q", w, raw[len(raw)-1:])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the held byte was never written after release")
	}
	// The recording conn's Read returns only on Close, so end the exchange: the read side
	// then fails and the send returns, which is what the recording is for.
	conn.Close()
	if err := <-done; err == nil {
		t.Log("the read returned before close — unexpected but not the property under test")
	}
}

// The mutation detector: if the hold is removed (the byte written before release), the test
// above fails on its first phase — the whole request appears in one write. Conversely, if the
// signal never fires, the orchestrator-side readiness wait times out. Both directions are the
// two failure modes the barrier exists to make impossible.
func TestASynchronizedSendWithoutReleaseCancellationIsReportedNotHung(t *testing.T) {
	s := &Sender{}
	conn := newRecordingConn()
	defer conn.Close()
	ready := make(chan struct{}, 1)
	release := make(chan struct{})
	sync := SyncPoints{Ready: ready, Release: release}

	ctx, cancel := context.WithCancel(ctxBG())
	done := make(chan error, 1)
	go func() {
		_, _, err := s.sendSynchronizedOn(ctx, conn, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n"), sync)
		done <- err
	}()
	<-ready
	// Never release; cancel instead. The send must return with the cancellation error, not
	// hang holding the byte.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled hold returned nil: the caller cannot distinguish a released send from a cancelled one")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled synchronized send never returned — the held byte hangs the group's teardown")
	}
}

func ctxBG() context.Context { return context.Background() }
