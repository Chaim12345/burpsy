//go:build unix

package procgroup

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func contain(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// Pgid 0 with Setpgid: the child's group id is its own pid, so -pid names
	// exactly the group this command and its non-detaching descendants are in.
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0
	cmd.Cancel = func() error { return killGroup(cmd.Process) }
}

// killGroup SIGKILLs the process group p leads.
//
// The leader is checked first through os.Process, which knows whether Wait has
// already reaped it (a pidfd on Linux). While the leader is unreaped, even as a
// zombie, its pid cannot be handed to another process, so -pid still names this
// group. Once reaped, the number could be reused, and signalling it as a group
// could reach an unrelated one: ErrProcessDone is returned instead, which
// exec.Cmd treats as "already finished", and WaitDelay remains the backstop for
// any descendant still holding a pipe.
func killGroup(p *os.Process) error {
	if p == nil {
		return os.ErrProcessDone
	}
	if err := p.Signal(syscall.Signal(0)); errors.Is(err, os.ErrProcessDone) {
		return err
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
