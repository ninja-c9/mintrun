//go:build integration

package core_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

// sandboxed runs command through ExecBlind on rt, with or without the sandbox, under the real
// platform sandbox (/usr/bin/sandbox-exec on macOS, user+mount namespaces on Linux). These tests
// are opt-in (`go test -tags integration`) so `go test ./...` stays hermetic (rule 22).
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
// or the keystore folder by its path, read mintrun's home through a symlink (or in other letter
// case on macOS), or on Linux read /proc/$PPID/environ, while the rest still works: a folder
// outside both, a hard link made beforehand (a known gap), the network, the environment, and the
// exit code. Each read has a positive control, the same read without the sandbox; listing and
// writing are checked against a listing of mintrun's home without it and a write outside both
// with it.
func TestSandboxHidesHome(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("sandbox is macOS and Linux only")
	}
	t.Setenv("MINTRUN_APPROVE", "")
	rt, home := probeRuntime(t, "sandbox_integration_master")
	userHome, outside := t.TempDir(), t.TempDir()
	keychains := filepath.Join(userHome, "Library", "Keychains")
	errWord := "Operation not permitted"
	if runtime.GOOS == "linux" {
		keychains = filepath.Join(userHome, ".local", "share", "keyrings")
		errWord = "Permission denied"
	}
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
		return res.ExitCode != 0 && !strings.Contains(res.Stdout, canary) && strings.Contains(res.Stderr, errWord)
	}

	type readCase struct {
		name, path string
		hidden     bool
	}
	cases := []readCase{
		{"mintrun's home", file, true},
		{"the keystore folder", filepath.Join(keychains, "canary"), true},
		{"a symlink into mintrun's home", symlink, true},
		{"a hard link made beforehand", hardLink, false},
		{"a folder outside both", filepath.Join(outside, "canary"), false},
	}
	if runtime.GOOS == "darwin" {
		// Assumes the default case-insensitive volume on macOS.
		cases = append(cases, readCase{"mintrun's home upper-cased", strings.ToUpper(file), true})
	}
	for _, c := range cases {
		if res := sandboxed(t, rt, false, "/bin/cat", c.path); res.ExitCode != 0 || res.Stdout != canary {
			t.Errorf("%s without the sandbox (positive control): %+v", c.name, res)
		}
		if res := sandboxed(t, rt, true, "/bin/cat", c.path); denied(res) != c.hidden || !c.hidden && res.Stdout != canary {
			t.Errorf("%s with the sandbox (hidden: %v): %+v", c.name, c.hidden, res)
		}
	}

	if runtime.GOOS == "linux" {
		// On Linux, /proc/$PPID/environ holds mintrun's initial environment (MINTRUN_VAULT_KEY
		// included) and is readable without the sandbox (rule 23); the child user namespace blocks
		// ptrace_may_access on the parent.
		parentEnv, err := os.ReadFile("/proc/self/environ")
		if err != nil || len(parentEnv) == 0 {
			t.Fatalf("/proc/self/environ: %v (%d bytes)", err, len(parentEnv))
		}
		if res := sandboxed(t, rt, false, "/bin/sh", "-c", "cat /proc/$PPID/environ"); res.ExitCode != 0 || res.Stdout != string(parentEnv) {
			t.Errorf("/proc/$PPID/environ without the sandbox (positive control): %+v", res)
		}
		if res := sandboxed(t, rt, true, "/bin/sh", "-c", "cat /proc/$PPID/environ"); !denied(res) || res.Stdout != "" {
			t.Errorf("/proc/$PPID/environ with the sandbox: %+v", res)
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

// TestSandboxHidesSecretTool starts a throwaway D-Bus session bus and unlocked gnome-keyring-daemon
// on Linux, stores a throwaway secret through KeychainVault (secret-tool), and checks that a child
// without the sandbox reads it over DBUS_SESSION_BUS_ADDRESS and over $XDG_RUNTIME_DIR/bus, reads
// login.keyring, and lists $XDG_RUNTIME_DIR/keyring (the positive controls), while a sandboxed
// child can do none of the four, and the host session bus and keyring still work afterwards.
func TestSandboxHidesSecretTool(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux libsecret only")
	}
	t.Setenv("MINTRUN_APPROVE", "")
	t.Setenv("MINTRUN_FILE_VAULT", "")
	rt, _ := probeRuntime(t, "sandbox_integration_master")
	userHome, runDir := t.TempDir(), t.TempDir()
	if err := errors.Join(os.Chmod(userHome, 0o700), os.Chmod(runDir, 0o700)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	t.Setenv("XDG_RUNTIME_DIR", runDir)

	out, err := exec.Command("/usr/bin/dbus-daemon", "--session", "--fork", "--print-address=1", "--print-pid=1").Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("dbus-daemon output: %q", out)
	}
	busAddr := lines[0]
	pid, err := strconv.Atoi(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if proc, err := os.FindProcess(pid); err == nil {
		t.Cleanup(func() { _ = proc.Kill() })
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", busAddr)
	sock, _, _ := strings.Cut(strings.TrimPrefix(busAddr, "unix:path="), ",")
	if err := os.Link(sock, filepath.Join(runDir, "bus")); err != nil {
		t.Fatal(err)
	}

	gkd := exec.Command("/usr/bin/gnome-keyring-daemon", "--unlock", "--components=secrets")
	gkd.Stdin = strings.NewReader("\n")
	if err := gkd.Run(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	kv := builtin.NewKeychainVault(t.TempDir())
	key, canary := "sandbox-test-"+strings.ToLower(rand.Text()), "sandbox-canary-"+rand.Text()
	t.Cleanup(func() {
		err := kv.DeleteSecret(ctx, key)
		if _, gone := kv.GetSecret(ctx, key); err != nil || !errors.Is(gone, builtin.ErrSecretNotFound) {
			t.Errorf("the throwaway libsecret item mintrun:%s may remain (delete: %v, read back: %v)", key, err, gone)
		}
	})
	if err := kv.SetSecret(ctx, key, canary); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		cmd  []string
	}{
		{"secret-tool over DBUS_SESSION_BUS_ADDRESS", []string{"/usr/bin/secret-tool", "lookup", "service", "mintrun:" + key, "account", "mintrun"}},
		{"secret-tool over XDG_RUNTIME_DIR/bus", []string{"/bin/sh", "-c", `unset DBUS_SESSION_BUS_ADDRESS; exec /usr/bin/secret-tool "$@"`, "_", "lookup", "service", "mintrun:" + key, "account", "mintrun"}},
	} {
		if res := sandboxed(t, rt, false, c.cmd...); res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != canary {
			t.Errorf("%s without the sandbox (positive control): %+v", c.name, res)
		}
		if res := sandboxed(t, rt, true, c.cmd...); res.ExitCode == 0 || strings.Contains(res.Stdout+res.Stderr, canary) {
			t.Errorf("%s with the sandbox: %+v", c.name, res)
		} else {
			t.Logf("%s with the sandbox: exit %d, stderr %q", c.name, res.ExitCode, res.Stderr)
		}
	}

	db := []string{"/bin/sh", "-c", `cat -- "$1" >/dev/null`, "_", filepath.Join(userHome, ".local", "share", "keyrings", "login.keyring")}
	if res := sandboxed(t, rt, false, db...); res.ExitCode != 0 {
		t.Errorf("reading login.keyring without the sandbox (positive control): %+v", res)
	}
	if res := sandboxed(t, rt, true, db...); res.ExitCode == 0 || !strings.Contains(res.Stderr, "Permission denied") {
		t.Errorf("reading login.keyring with the sandbox: %+v", res)
	}

	ctrl := []string{"/bin/ls", filepath.Join(runDir, "keyring")}
	if res := sandboxed(t, rt, false, ctrl...); res.ExitCode != 0 || !strings.Contains(res.Stdout, "control") {
		t.Errorf("listing XDG_RUNTIME_DIR/keyring without the sandbox (positive control): %+v", res)
	}
	if res := sandboxed(t, rt, true, ctrl...); res.ExitCode == 0 || !strings.Contains(res.Stderr, "Permission denied") {
		t.Errorf("listing XDG_RUNTIME_DIR/keyring with the sandbox: %+v", res)
	}

	if got, err := kv.GetSecret(ctx, key); err != nil || got != canary {
		t.Errorf("host secret-tool lookup after sandboxed runs: got %q, err %v", got, err)
	}
}

func runNetProbe(kind, target string) {
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch kind {
	case "tcp":
		cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
		resp, err := cl.Get(target)
		if err != nil {
			fail(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			fail(err)
		}
		_, _ = os.Stdout.Write(body)
	case "udp":
		conn, err := net.DialTimeout("udp", target, 2*time.Second)
		if err != nil {
			fail(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(conn, "ping"); err != nil {
			fail(err)
		}
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			fail(err)
		}
		_, _ = os.Stdout.Write(buf[:n])
	case "unix":
		conn, err := net.DialTimeout("unix", target, 2*time.Second)
		if err != nil {
			fail(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		out, err := io.ReadAll(conn)
		if err != nil {
			fail(err)
		}
		_, _ = os.Stdout.Write(out)
	case "dns":
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", target)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ips, err := r.LookupIP(ctx, "ip4", "probe.example")
		if err != nil || len(ips) == 0 {
			fail(fmt.Errorf("LookupIP: %v (%v)", err, ips))
		}
		_, _ = io.WriteString(os.Stdout, ips[0].String())
	case "local":
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			fail(err)
		}
		if _, err := syscall.Write(fds[0], []byte("pair-ok")); err != nil {
			fail(err)
		}
		_ = syscall.Close(fds[0])
		buf := make([]byte, 7)
		n, err := syscall.Read(fds[1], buf)
		_ = syscall.Close(fds[1])
		if err != nil || string(buf[:n]) != "pair-ok" {
			fail(fmt.Errorf("socketpair read %q (%v)", buf[:n], err))
		}
		if err := os.WriteFile(target, buf[:n], 0o600); err != nil {
			fail(err)
		}
		if runtime.GOOS == "linux" {
			ns, err := os.Readlink("/proc/self/ns/net")
			if err != nil {
				fail(err)
			}
			status, err := os.ReadFile("/proc/self/status")
			if err != nil {
				fail(err)
			}
			fmt.Printf("%s\n%s", ns, status)
		} else {
			_, _ = io.WriteString(os.Stdout, "pair-ok")
		}
	default:
		fail(fmt.Errorf("unknown probe %q", kind))
	}
	os.Exit(0)
}

func init() {
	if len(os.Args) == 4 && os.Args[1] == "-mintrun-net-probe" {
		runNetProbe(os.Args[2], os.Args[3])
	}
}

// TestSandboxBlocksNetwork verifies that NoNetwork blocks TCP, UDP, pathname Unix domain sockets,
// and DNS (plus mDNSResponder via dns-sd on macOS) while still allowing local file writes and
// anonymous socketpair(AF_UNIX), and that on Linux /proc/self/ns/net is isolated and Seccomp:\t2
// is active. Every blocked check has a positive control with NoNetwork: false (rule 23).
func TestSandboxBlocksNetwork(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("sandbox is macOS and Linux only")
	}
	t.Setenv("MINTRUN_APPROVE", "")
	rt, _ := probeRuntime(t, "sandbox_integration_master")
	userHome, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(userHome, "Library", "Keychains"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", userHome)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	canary := "net-canary-" + rand.Text()
	tcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, canary)
	}))
	defer tcpSrv.Close()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 32)
		for {
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "ping" {
				_, _ = udpConn.WriteTo([]byte(canary), addr)
			}
		}
	}()

	sockDir, err := os.MkdirTemp("/tmp", "mr-net-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "s")
	unixLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixLn.Close()
	go func() {
		for {
			c, err := unixLn.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, canary)
			_ = c.Close()
		}
	}()

	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsConn.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := dnsConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end := bytes.IndexByte(buf[12:n], 0)
			if end < 0 || 12+end+5 > n {
				continue
			}
			qEnd := 12 + end + 5
			resp := []byte{buf[0], buf[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
			resp = append(resp, buf[12:qEnd]...)
			resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 127, 0, 0, 42)
			_, _ = dnsConn.WriteTo(resp, addr)
		}
	}()

	run := func(sandbox, noNet bool, cmd ...string) *core.ExecResult {
		t.Helper()
		res, err := rt.ExecBlind(context.Background(), core.ExecRequest{
			MintRequest: core.MintRequest{Provider: "probe"},
			Command:     cmd,
			Sandbox:     sandbox,
			NoNetwork:   noNet,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	probe := func(sandbox, noNet bool, kind, target string) *core.ExecResult {
		t.Helper()
		return run(sandbox, noNet, exe, "-mintrun-net-probe", kind, target)
	}

	for _, c := range []struct {
		kind, target, want string
	}{
		{"tcp", tcpSrv.URL, canary},
		{"udp", udpConn.LocalAddr().String(), canary},
		{"unix", sockPath, canary},
		{"dns", dnsConn.LocalAddr().String(), "127.0.0.42"},
	} {
		if res := probe(true, false, c.kind, c.target); res.ExitCode != 0 || res.Stdout != c.want {
			t.Errorf("%s with Sandbox=true NoNetwork=false (positive control): %+v", c.kind, res)
		}
		if res := probe(false, true, c.kind, c.target); res.ExitCode == 0 || strings.Contains(res.Stdout, c.want) {
			t.Errorf("%s with NoNetwork=true: %+v", c.kind, res)
		}
	}

	if runtime.GOOS == "darwin" {
		dnsSD := []string{"/usr/bin/dns-sd", "-t", "1", "-G", "v4", "localhost"}
		if res := run(true, false, dnsSD...); res.ExitCode != 0 || !strings.Contains(res.Stdout, "127.0.0.1") {
			t.Errorf("dns-sd with Sandbox=true NoNetwork=false (positive control): %+v", res)
		}
		if res := run(false, true, dnsSD...); res.ExitCode == 0 || strings.Contains(res.Stdout, "127.0.0.1") {
			t.Errorf("dns-sd with NoNetwork=true: %+v", res)
		}
	}

	localFile := filepath.Join(outside, "local-ok")
	res := probe(false, true, "local", localFile)
	if res.ExitCode != 0 {
		t.Fatalf("local write + socketpair with NoNetwork=true: %+v", res)
	}
	if got, err := os.ReadFile(localFile); err != nil || string(got) != "pair-ok" {
		t.Errorf("local file after NoNetwork=true: got %q (%v)", got, err)
	}
	if runtime.GOOS == "linux" {
		parentNS, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		netNS, status, _ := strings.Cut(res.Stdout, "\n")
		if netNS == parentNS || !strings.Contains(status, "Seccomp:\t2") || !strings.Contains(status, "NoNewPrivs:\t1") {
			t.Errorf("Linux NoNetwork=true netns=%q (parent %q), status:\n%s", netNS, parentNS, status)
		}
		openRes := probe(true, false, "local", filepath.Join(outside, "local-open"))
		openNS, openStatus, _ := strings.Cut(openRes.Stdout, "\n")
		if openRes.ExitCode != 0 || openNS != parentNS || !strings.Contains(openStatus, "Seccomp:\t0") {
			t.Errorf("Linux Sandbox=true NoNetwork=false (positive control) netns=%q (parent %q), status:\n%s", openNS, parentNS, openStatus)
		}
	}
}
