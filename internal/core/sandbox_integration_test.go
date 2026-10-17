//go:build integration

package core_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

// sandboxed runs command through ExecBlind on rt, with or without the sandbox, under the real
// /usr/bin/sandbox-exec. These tests are opt-in (`go test -tags integration`) so `go test ./...`
// stays hermetic (rule 22).
func sandboxed(t *testing.T, rt *core.Runtime, sandbox bool, command ...string) *core.ExecResult {
	t.Helper()
	req := core.ExecRequest{MintRequest: core.MintRequest{Provider: "probe"}, Command: command, Sandbox: sandbox}
	res, err := rt.ExecBlind(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestSandboxHidesHome shows that a sandboxed command cannot read, list, or write mintrun's home
// or the Keychain folder by its path, or read mintrun's home through a symlink or in other letter
// case, while the rest still works: a folder outside both, a hard link made beforehand (a known
// gap), the network, the environment, and the exit code. Each read has a positive control, the
// same read without the sandbox; listing and writing are checked against a listing of mintrun's
// home without it and a write outside both with it.
func TestSandboxHidesHome(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec is macOS only")
	}
	t.Setenv("MINTRUN_APPROVE", "")
	rt, home := probeRuntime(t, "sandbox_integration_master")
	userHome, outside := t.TempDir(), t.TempDir()
	keychains := filepath.Join(userHome, "Library", "Keychains")
	canary := "sandbox-canary-" + rand.Text()
	file := filepath.Join(home, "canary")
	symlink, hardLink := filepath.Join(outside, "symlink"), filepath.Join(outside, "hardlink")
	if err := errors.Join(
		os.MkdirAll(keychains, 0o700),
		os.WriteFile(file, []byte(canary), 0o600),
		os.WriteFile(filepath.Join(keychains, "canary"), []byte(canary), 0o600),
		os.WriteFile(filepath.Join(outside, "canary"), []byte(canary), 0o600),
		os.Symlink(file, symlink),
		os.Link(file, hardLink),
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	denied := func(res *core.ExecResult) bool {
		return res.ExitCode != 0 && !strings.Contains(res.Stdout, canary) && strings.Contains(res.Stderr, "Operation not permitted")
	}

	// Reads. The upper-cased path assumes the default case-insensitive volume.
	for _, c := range []struct {
		name, path string
		hidden     bool
	}{
		{"mintrun's home", file, true},
		{"the Keychain folder", filepath.Join(keychains, "canary"), true},
		{"a symlink into mintrun's home", symlink, true},
		{"mintrun's home upper-cased", strings.ToUpper(file), true},
		{"a hard link made beforehand", hardLink, false},
		{"a folder outside both", filepath.Join(outside, "canary"), false},
	} {
		if res := sandboxed(t, rt, false, "/bin/cat", c.path); res.ExitCode != 0 || res.Stdout != canary {
			t.Errorf("%s without the sandbox (positive control): %+v", c.name, res)
		}
		if res := sandboxed(t, rt, true, "/bin/cat", c.path); denied(res) != c.hidden || !c.hidden && res.Stdout != canary {
			t.Errorf("%s with the sandbox (hidden: %v): %+v", c.name, c.hidden, res)
		}
	}

	// Listing and writing.
	if res := sandboxed(t, rt, false, "/bin/ls", home); res.ExitCode != 0 || !strings.Contains(res.Stdout, "canary") {
		t.Errorf("listing mintrun's home without the sandbox (positive control): %+v", res)
	}
	write := func(path string) (*core.ExecResult, error) {
		res := sandboxed(t, rt, true, "/bin/sh", "-c", `echo x >"$1"`, "_", path)
		_, err := os.Lstat(path)
		return res, err
	}
	if res, err := write(filepath.Join(outside, "written")); res.ExitCode != 0 || err != nil {
		t.Errorf("a write outside both with the sandbox (positive control): %+v %v", res, err)
	}
	for _, dir := range []string{home, keychains} {
		if res := sandboxed(t, rt, true, "/bin/ls", dir); !denied(res) {
			t.Errorf("listing %s with the sandbox: %+v", dir, res)
		}
		if res, err := write(filepath.Join(dir, "written")); !denied(res) || !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a write into %s with the sandbox: %+v %v", dir, res, err)
		}
	}

	// The exit code and the environment (where a lease travels) are the command's, and the
	// network is open (a known gap).
	if res := sandboxed(t, rt, true, "/bin/sh", "-c", "exit 7"); res.ExitCode != 7 {
		t.Errorf("exit code with the sandbox: %+v", res)
	}
	t.Setenv("SANDBOX_ENV_CANARY", canary)
	if res := sandboxed(t, rt, true, "/bin/sh", "-c", `printf %s "$SANDBOX_ENV_CANARY"`); res.ExitCode != 0 || res.Stdout != canary {
		t.Errorf("the environment with the sandbox: %+v", res)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, canary) }))
	defer srv.Close()
	if res := sandboxed(t, rt, true, "/usr/bin/curl", "-sS", "--noproxy", "*", srv.URL); res.ExitCode != 0 || res.Stdout != canary {
		t.Errorf("loopback HTTP with the sandbox: %+v", res)
	}
}

// TestSandboxHidesKeychainItem stores a throwaway secret in the real login Keychain the way
// mintrun does, and removes it afterwards. Without the sandbox, a child reads it with `security`
// and reads the login Keychain file (the positive controls; rule 23); with it, it can do neither.
func TestSandboxHidesKeychainItem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Keychain only")
	}
	t.Setenv("MINTRUN_APPROVE", "")
	rt, _ := probeRuntime(t, "sandbox_integration_master")
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	kv := &builtin.KeychainVault{HomeDir: t.TempDir()}
	key, canary := "sandbox-test-"+strings.ToLower(rand.Text()), "sandbox-canary-"+rand.Text()
	t.Cleanup(func() {
		err := kv.DeleteSecret(ctx, key)
		if _, gone := kv.GetSecret(ctx, key); err != nil || !errors.Is(gone, builtin.ErrSecretNotFound) {
			t.Errorf("the throwaway Keychain item mintrun:%s may remain (delete: %v, read back: %v)", key, err, gone)
		}
	})
	if err := kv.SetSecret(ctx, key, canary); err != nil {
		t.Fatal(err)
	}

	item := []string{"/usr/bin/security", "find-generic-password", "-s", "mintrun:" + key, "-w"}
	if res := sandboxed(t, rt, false, item...); res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != canary {
		t.Errorf("security without the sandbox (positive control): %+v", res)
	}
	if res := sandboxed(t, rt, true, item...); res.ExitCode == 0 || strings.Contains(res.Stdout+res.Stderr, canary) {
		t.Errorf("security with the sandbox: %+v", res)
	} else {
		t.Logf("security with the sandbox: exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	db := []string{"/bin/sh", "-c", `cat -- "$1" >/dev/null`, "_", filepath.Join(userHome, "Library", "Keychains", "login.keychain-db")}
	if res := sandboxed(t, rt, false, db...); res.ExitCode != 0 {
		t.Errorf("reading the login Keychain file without the sandbox (positive control): %+v", res)
	}
	if res := sandboxed(t, rt, true, db...); res.ExitCode == 0 || !strings.Contains(res.Stderr, "Operation not permitted") {
		t.Errorf("reading the login Keychain file with the sandbox: %+v", res)
	}
}
