//go:build !linux

package core

import "os/exec"

// LinuxSandboxSysProcAttr configures cmd to run in a new Linux user and mount namespace; off
// Linux it is a no-op, and unit tests on any OS stub LinuxSandboxPath.
var LinuxSandboxSysProcAttr = func(*exec.Cmd) {}
