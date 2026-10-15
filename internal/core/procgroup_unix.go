//go:build unix

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killProcessGroup starts cmd in its own process group and makes a context timeout or cancel
// SIGKILL the whole group, so no grandchild keeps running with the lease (audit L2).
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Once Go has reaped the child, its pid (the group id) is free for reuse: kill nothing.
		if err := cmd.Process.Signal(syscall.Signal(0)); errors.Is(err, os.ErrProcessDone) {
			return err
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != syscall.ESRCH {
			return err
		}
		return os.ErrProcessDone
	}
}
