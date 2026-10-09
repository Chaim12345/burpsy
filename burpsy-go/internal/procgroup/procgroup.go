// Package procgroup makes a context-bounded exec.Cmd bound the whole process
// tree it starts, not only the process it execs (burpsy-react-ui-9bzh).
//
// exec.CommandContext kills the direct child when its context ends. A tool that
// is a wrapper script, or that forks workers, leaves those descendants running
// with the command's stdout/stderr pipes still open, and exec.Cmd.Wait reads
// those pipes to EOF — so the "timed out" call returns only when the last
// descendant exits on its own. A 50ms timeout around `sh -c "sleep 5"` took five
// seconds, and a hung grandchild stalled a scan for as long as it lived.
//
// Contain fixes that in two layers:
//
//   - on unix the command runs as the leader of its own process group, and
//     cancellation SIGKILLs the whole group, so every descendant that stayed
//     in it dies with the call;
//   - on every platform WaitDelay is set, so a descendant that escaped the
//     group (setsid, a daemon) or a platform with no group kill (windows)
//     still cannot hold Wait open: after the delay the pipes are closed and
//     Wait returns exec.ErrWaitDelay.
//
// Only for calls a timeout or cancellation is meant to bound. A process that is
// deliberately left running (the launched browser) must not be contained.
package procgroup

import (
	"os/exec"
	"time"
)

// WaitDelay is how long Wait keeps reading a contained command's pipes after
// its context ends or it exits, before closing them. Long enough that a tool
// which exited normally has its last buffered output copied; short enough that
// it is a small multiple of nothing on the timeout path.
const WaitDelay = time.Second

// Contain prepares cmd, built with exec.CommandContext and not yet started, so
// that its context ending kills the process tree it starts and Wait returns
// within WaitDelay of that.
func Contain(cmd *exec.Cmd) {
	contain(cmd)
	cmd.WaitDelay = WaitDelay
}
