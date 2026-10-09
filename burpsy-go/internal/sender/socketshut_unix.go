//go:build linux || darwin || freebsd || netbsd || openbsd

package sender

import (
	"crypto/tls"
	"net"
	"syscall"
	"time"
)

// socketShut reports whether the peer of an idle connection has already shut its side, by a
// non-blocking MSG_PEEK on the socket itself. The deadline probe in alive cannot be relied on for
// this: Go refuses a read whose deadline has already passed without ever asking the socket, so a
// goroutine descheduled for longer than livenessProbe between setting the deadline and peeking got
// "timed out" — the healthy answer — from a socket whose FIN had long arrived. That handed a dead
// connection to a non-idempotent request, which then failed with EOF instead of being sent fresh.
//
// It answers false whenever it cannot tell: no socket underneath (an upstream proxy's tunnel),
// bytes waiting (a TLS close_notify, say — the deadline probe judges those), or any error. A false
// here only means "ask the deadline probe".
func socketShut(c net.Conn) bool {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	// A deadline left in the past by an earlier exchange would make RawConn.Read refuse without
	// calling the peek, the very failure this function exists to avoid.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return false
	}
	closed := false
	var b [1]byte
	_ = raw.Read(func(fd uintptr) bool {
		n, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		closed = n == 0 && err == nil
		return true // never wait: this is a probe, not a read
	})
	return closed
}
