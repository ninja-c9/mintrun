//go:build unix

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// forkSettle is how long Cancel lets a fork the stopped child is in finish before it kills the
// group. On macOS 27.0, 10 ms left no process running in 2000 kills during a fork, and 1 ms left 4
// in 600.
var forkSettle = 10 * time.Millisecond

// killProcessGroup starts cmd in its own process group and makes a context timeout or cancel
// SIGKILL the whole group, so no grandchild keeps running with the lease (audit L2). The caller
// must set WaitDelay: a child that has moved to another group is stopped but missed by the group
// kill, and only WaitDelay's kill ends it.
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// A group kill on macOS misses a process the child is still creating. Stopping the child
		// first lets that fork finish, so the kill below reaches the new process, and a stopped
		// child cannot exit, so it stays unreaped. Process.Signal sends nothing once Go has
		// reaped the child. Only the child is stopped: a stopped process anywhere else in the
		// group would stay stopped if the kill below never ran.
		_ = cmd.Process.Signal(syscall.SIGSTOP)
		time.Sleep(forkSettle) // ponytail: a fork slower than this (heavy load) can still be missed
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
