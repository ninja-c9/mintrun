//go:build !unix

package core

import "os/exec"

// killProcessGroup is a no-op off Unix: a timeout kills only the child, and WaitDelay bounds
// the wait for pipes its own children still hold.
func killProcessGroup(*exec.Cmd) {}
