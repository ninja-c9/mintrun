//go:build linux

package core

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "-mintrun-linux-sandbox-check" {
		os.Exit(checkInsideLinuxSandbox(os.Args[2], os.Args[3]))
	}
}

func checkInsideLinuxSandbox(dir, file string) int {
	const prGetSecurebits = 27
	secbits, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prGetSecurebits, 0, 0, 0, 0, 0)
	if errno != 0 || secbits != secbitsLockedNoRoot {
		fmt.Fprintf(os.Stderr, "secbits=%#x errno=%v\n", secbits, errno)
		return 2
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	for _, capLine := range []string{
		"CapInh:\t0000000000000000",
		"CapPrm:\t0000000000000000",
		"CapEff:\t0000000000000000",
		"CapAmb:\t0000000000000000",
	} {
		if !strings.Contains(string(status), capLine) {
			fmt.Fprintf(os.Stderr, "missing %q in status:\n%s", capLine, status)
			return 4
		}
	}
	if _, err := os.ReadFile(filepath.Join(dir, "secret")); !errors.Is(err, fs.ErrPermission) {
		fmt.Fprintf(os.Stderr, "expected ErrPermission reading hidden dir, got %v\n", err)
		return 5
	}
	if err := os.Chmod(dir, 0o700); !errors.Is(err, syscall.EROFS) {
		fmt.Fprintf(os.Stderr, "expected EROFS chmodding hidden dir, got %v\n", err)
		return 7
	}
	if got, err := os.ReadFile(file); err != nil || len(got) != 0 {
		fmt.Fprintf(os.Stderr, "expected empty /dev/null read on hidden file, got %q err=%v\n", got, err)
		return 8
	}
	return 0
}

func TestLinuxSandboxSysProcAttrAndHelper(t *testing.T) {
	var cmd exec.Cmd
	LinuxSandboxSysProcAttr(&cmd)
	if cmd.SysProcAttr == nil ||
		cmd.SysProcAttr.Cloneflags != syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS ||
		!slices.Equal(cmd.SysProcAttr.AmbientCaps, []uintptr{capSysAdmin, capSetpcap}) ||
		cmd.SysProcAttr.GidMappingsEnableSetgroups {
		t.Fatalf("unexpected SysProcAttr: %+v", cmd.SysProcAttr)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = devNull
	badCases := [][]string{
		nil,
		{"--"},
		{"-hide-dir"},
		{"-bad", "/tmp", "--"},
		{"-hide-dir", "/tmp"},
	}
	if os.Geteuid() != 0 {
		badCases = append(badCases, []string{"-hide-dir", "/tmp", "-hide-file", "/dev/null", "--"})
	}
	for _, args := range badCases {
		if got := runLinuxSandbox(args); got != 126 {
			t.Errorf("runLinuxSandbox(%q) = %d, want 126", args, got)
		}
	}
	os.Stderr = origStderr
	_ = devNull.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(t.TempDir(), "sock")
	if err := errors.Join(
		os.WriteFile(filepath.Join(dir, "secret"), []byte("top-secret"), 0o600),
		os.WriteFile(file, []byte("bus-bytes"), 0o600),
	); err != nil {
		t.Fatal(err)
	}

	runHelper := func(workDir string, args ...string) (int, string, string) {
		t.Helper()
		c := exec.Command(exe, append([]string{"-mintrun-linux-sandbox"}, args...)...)
		c.Dir = workDir
		LinuxSandboxSysProcAttr(c)
		var out, errBuf bytes.Buffer
		c.Stdout, c.Stderr = &out, &errBuf
		err := c.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("helper failed to start: %v", err)
		}
		return code, out.String(), errBuf.String()
	}

	// Dry-run probe with an existing directory and a not-yet-created directory.
	if code, _, stderr := runHelper("", "-hide-dir", dir, "-hide-file", file, "--"); code != 0 {
		t.Skipf("unprivileged user+mount namespaces unavailable on this host (exit %d: %s)", code, strings.TrimSpace(stderr))
	}
	missingHome := filepath.Join(t.TempDir(), "not-created-yet")
	if code, _, stderr := runHelper("", "-hide-dir", missingHome, "--"); code != 0 {
		t.Errorf("probe with missing dirs[0]: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Lstat(missingHome); !os.IsNotExist(err) {
		t.Errorf("probe created missing dirs[0]: err=%v", err)
	}

	// Inside the sandbox: securebits locked, all capability masks zeroed, mounts private,
	// hidden directory unreadable and read-only (EROFS), and hidden file bound to /dev/null.
	if code, stdout, stderr := runHelper("", "-hide-dir", dir, "-hide-file", file, "--",
		exe, "-mintrun-linux-sandbox-check", dir, file); code != 0 {
		t.Fatalf("sandbox check exited %d: stdout=%q stderr=%q", code, stdout, stderr)
	}

	// A working directory inside a hidden directory fails closed after Chdir("/") + mount + Chdir(cwd).
	if code, _, stderr := runHelper(dir, "-hide-dir", dir, "--", exe, "-mintrun-linux-sandbox-check", dir, file); code != 126 || !strings.Contains(stderr, "permission denied") {
		t.Errorf("cwd inside hidden dir: exit %d, stderr %q, want 126 with permission denied", code, stderr)
	}

	// A missing target binary after "--" exits 127 without leaking a path.
	missingBin := filepath.Join(t.TempDir(), "no-such-bin")
	if code, _, stderr := runHelper("", "-hide-dir", dir, "--", missingBin); code != 127 || strings.Contains(stderr, missingBin) {
		t.Errorf("missing target binary: exit %d, stderr %q", code, stderr)
	}
}
