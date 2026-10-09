//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package sender

import "net"

// socketShut cannot peek at the socket on this platform; alive falls back to its deadline probe
// alone. See socketshut_unix.go.
func socketShut(net.Conn) bool { return false }
