//go:build !unix

package procgroup

import "os/exec"

// contain is a no-op where there is no process-group kill this package uses:
// exec.CommandContext's default Cancel kills the direct process, and WaitDelay
// (set by Contain on every platform) stops a surviving descendant from holding
// Wait open. A descendant may outlive the call here; it cannot stall it.
func contain(cmd *exec.Cmd) {}
