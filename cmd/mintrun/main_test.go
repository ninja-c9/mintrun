package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ninja-c9/mintrun/internal/core"
)

type exitPanic int

func withMockExit(t *testing.T, fn func()) (exitCode int, exited bool) {
	t.Helper()
	origExit := exitFunc
	exitFunc = func(code int) {
		panic(exitPanic(code))
	}
	defer func() {
		exitFunc = origExit
		if r := recover(); r != nil {
			if c, ok := r.(exitPanic); ok {
				exitCode = int(c)
				exited = true
				return
			}
			panic(r)
		}
	}()
	fn()
	return 0, false
}

func runMainWithArgs(t *testing.T, stdin string, args ...string) (code int, exited bool) {
	t.Helper()
	origArgs := os.Args
	os.Args = append([]string{"mintrun"}, args...)
	defer func() { os.Args = origArgs }()

	if stdin != "" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteString(stdin)
		_ = w.Close()
		origStdin := os.Stdin
		os.Stdin = r
		defer func() {
			os.Stdin = origStdin
			_ = r.Close()
		}()
	}

	return withMockExit(t, func() {
		main()
	})
}

func TestCLISubcommandsEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MINTRUN_HOME", home)
	t.Setenv("MINTRUN_FILE_VAULT", "1")
	t.Setenv("MINTRUN_VAULT", "keychain")

	// Static (non-JIT) mode must be explicitly allowed by policy (audit finding H2).
	if err := os.WriteFile(filepath.Join(home, "policy.json"), []byte(`{"cloudflare":{"allow_static":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. defaultHomeDir with and without MINTRUN_HOME
	if got := defaultHomeDir(); got != home {
		t.Fatalf("expected %q, got %q", home, got)
	}
	t.Setenv("MINTRUN_HOME", "")
	if got := defaultHomeDir(); !strings.HasSuffix(got, ".mintrun") {
		t.Fatalf("expected .mintrun suffix, got %q", got)
	}
	t.Setenv("MINTRUN_HOME", home)

	// 2. No args -> usage + exit(1)
	if code, exited := runMainWithArgs(t, ""); !exited || code != 1 {
		t.Fatalf("expected exit 1 on no args, got code=%d exited=%v", code, exited)
	}

	// 3. Help command & unknown command
	if _, exited := runMainWithArgs(t, "", "help"); exited {
		t.Fatal("help should not exit non-zero")
	}
	if code, exited := runMainWithArgs(t, "", "unknown-subcmd"); !exited || code != 1 {
		t.Fatalf("expected exit 1 on unknown subcommand, got %d %v", code, exited)
	}

	// 4. Audit before any execution -> "No audit entries yet."
	if _, exited := runMainWithArgs(t, "", "audit"); exited {
		t.Fatal("audit should succeed when no file exists")
	}

	// 5. Secret lifecycle: set via arg, set via stdin, check, delete, and error cases
	if code, exited := runMainWithArgs(t, "", "secret"); !exited || code != 1 {
		t.Fatal("expected exit 1 on missing secret args")
	}
	if code, exited := runMainWithArgs(t, "", "secret", "check", "cloudflare"); !exited || code != 1 {
		t.Fatal("expected exit 1 when secret not yet set")
	}
	if _, exited := runMainWithArgs(t, "", "secret", "set", "cloudflare", "cf_cli_secret_9999"); exited {
		t.Fatal("secret set via arg failed")
	}
	if _, exited := runMainWithArgs(t, "gh_stdin_secret_8888\n", "secret", "set", "github"); exited {
		t.Fatal("secret set via stdin failed")
	}
	if _, exited := runMainWithArgs(t, "", "secret", "check", "cloudflare"); exited {
		t.Fatal("secret check failed")
	}
	// A piped multi-line secret (a pretty-printed GCP service-account key) is stored whole.
	saKey := "{\n  \"type\": \"service_account\",\n  \"client_email\": \"ci@example.iam.gserviceaccount.com\"\n}"
	if _, exited := runMainWithArgs(t, saKey+"\n", "secret", "set", "gcp"); exited {
		t.Fatal("secret set gcp via piped stdin failed")
	}
	rt, err := bootRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Registry.Provider("gcp"); err != nil {
		t.Fatalf("gcp provider not registered: %v", err)
	}
	kv, _ := rt.Registry.Vault("keychain")
	if got, err := kv.GetSecret(context.Background(), "gcp"); err != nil || got != saKey {
		t.Fatalf("multi-line secret truncated: %q %v", got, err)
	}
	// A failed stdin read (read(2) on a directory fd) is fatal and keeps the stored secret intact.
	dirIn, err := os.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	origStdin := os.Stdin
	os.Stdin = dirIn
	code, exited := runMainWithArgs(t, "", "secret", "set", "gcp")
	os.Stdin = origStdin
	_ = dirIn.Close()
	if got, _ := kv.GetSecret(context.Background(), "gcp"); !exited || code != 1 || got != saKey {
		t.Fatalf("unreadable stdin: exit %d (exited=%v), stored secret intact=%v", code, exited, got == saKey)
	}
	if _, exited := runMainWithArgs(t, "", "secret", "delete", "github"); exited {
		t.Fatal("secret delete failed")
	}
	if code, exited := runMainWithArgs(t, "", "secret", "bad-action", "cloudflare"); !exited || code != 1 {
		t.Fatal("expected exit 1 on bad secret action")
	}
	if code, exited := runMainWithArgs(t, "", "secret", "set", "cloudflare", "   "); !exited || code != 1 {
		t.Fatal("expected exit 1 on empty secret value")
	}
	t.Setenv("MINTRUN_VAULT", "nonexistent_vault")
	if code, exited := runMainWithArgs(t, "", "secret", "check", "cloudflare"); !exited || code != 1 {
		t.Fatal("expected exit 1 on invalid vault")
	}
	t.Setenv("MINTRUN_VAULT", "keychain")

	// 6. Exec with `--` separator and without `--` separator, plus error cases
	if code, exited := runMainWithArgs(t, "", "exec"); !exited || code != 1 {
		t.Fatal("expected exit 1 on exec without command")
	}
	if code, exited := runMainWithArgs(t, "", "exec", "-provider", "cloudflare", "-perms", "static", "--", "sh", "-c", "echo out && echo err >&2"); !exited || code != 0 {
		t.Fatalf("expected exit 0 on exec, got code=%d exited=%v", code, exited)
	}
	if code, exited := runMainWithArgs(t, "", "run", "-provider", "cloudflare", "-perms", "static", "echo", "no-dash-sep"); !exited || code != 0 {
		t.Fatalf("expected exit 0 on run without --, got code=%d exited=%v", code, exited)
	}
	if code, exited := runMainWithArgs(t, "", "exec", "-provider", "unknown_prov", "--", "echo", "fail"); !exited || code != 1 {
		t.Fatal("expected exit 1 on unknown provider")
	}
	// -clean-env strips ambient host variables but keeps PATH and the lease credential.
	t.Setenv("MINTRUN_TEST_AMBIENT", "ambient_host_value")
	if code, exited := runMainWithArgs(t, "", "exec", "-provider", "cloudflare", "-perms", "static", "--", "sh", "-c", `test -n "$MINTRUN_TEST_AMBIENT"`); !exited || code != 0 {
		t.Fatalf("expected the ambient var to be inherited by default, got code=%d", code)
	}
	if code, exited := runMainWithArgs(t, "", "exec", "-clean-env", "-provider", "cloudflare", "-perms", "static", "--", "sh", "-c", `test -z "$MINTRUN_TEST_AMBIENT" && test -n "$PATH" && test -n "$CF_API_TOKEN"`); !exited || code != 0 {
		t.Fatalf("expected -clean-env to strip ambient vars only, got code=%d", code)
	}

	// 7. Audit after executions -> prints audit.jsonl & supports filtering flags
	if _, exited := runMainWithArgs(t, "", "audit"); exited {
		t.Fatal("audit should succeed after exec")
	}
	if _, exited := runMainWithArgs(t, "", "audit", "-provider", "cloudflare", "-limit", "1"); exited {
		t.Fatal("audit with -provider and -limit should succeed")
	}
	if _, exited := runMainWithArgs(t, "", "audit", "-failed"); exited {
		t.Fatal("audit with -failed should succeed")
	}

	// 8. Plugin list / install / remove + error cases
	if _, exited := runMainWithArgs(t, "", "plugin"); exited {
		t.Fatal("plugin default list failed")
	}
	pluginSrc := t.TempDir()
	_ = os.WriteFile(filepath.Join(pluginSrc, "plugin.json"), []byte(`{"name":"demo","version":"0.1.0","kind":"provider","entrypoint":"run"}`), 0o600)
	_ = os.WriteFile(filepath.Join(pluginSrc, "run"), []byte("#!/bin/sh\necho '{}'\n"), 0o700)

	if _, exited := runMainWithArgs(t, "", "plugin", "install", pluginSrc); exited {
		t.Fatal("plugin install failed")
	}
	if _, exited := runMainWithArgs(t, "", "plugin", "list"); exited {
		t.Fatal("plugin list with external plugin failed")
	}
	if _, exited := runMainWithArgs(t, "", "plugin", "remove", "demo"); exited {
		t.Fatal("plugin remove failed")
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "remove", "demo"); !exited || code != 1 {
		t.Fatal("expected exit 1 removing already-removed plugin")
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "install", "/nonexistent_dir_xyz"); !exited || code != 1 {
		t.Fatal("expected exit 1 installing nonexistent dir")
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "install"); !exited || code != 1 {
		t.Fatal("expected exit 1 on missing install arg")
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "remove"); !exited || code != 1 {
		t.Fatal("expected exit 1 on missing remove arg")
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "unknown"); !exited || code != 1 {
		t.Fatal("expected exit 1 on unknown plugin subcommand")
	}

	// 9. MCP command over stdio
	mcpReq := fmt.Sprintf("%s\n", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if _, exited := runMainWithArgs(t, mcpReq, "mcp"); exited {
		t.Fatal("mcp command failed")
	}
	if code, exited := runMainWithArgs(t, "", "mcp", "nonexistent_bridge"); !exited || code != 1 {
		t.Fatal("expected exit 1 on unknown mcp bridge")
	}
}

// TestCLISecretArgvWarning: a secret given on the command line still works, but warns that argv is
// visible in shell history and `ps` (audit M5); a piped secret stays quiet.
func TestCLISecretArgvWarning(t *testing.T) {
	t.Setenv("MINTRUN_HOME", t.TempDir())
	t.Setenv("MINTRUN_FILE_VAULT", "1")
	t.Setenv("MINTRUN_VAULT", "keychain")
	stderrOf := func(stdin string, args ...string) string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stderr
		os.Stderr = w
		_, exited := runMainWithArgs(t, stdin, args...)
		os.Stderr = orig
		_ = w.Close()
		out, _ := io.ReadAll(r)
		if exited {
			t.Fatalf("%v exited: %s", args, out)
		}
		return string(out)
	}
	if out := stderrOf("", "secret", "set", "cloudflare", "cf_argv_secret_4242"); !strings.Contains(out, "visible in shell history") || strings.Contains(out, "cf_argv_secret_4242") {
		t.Fatalf("expected an argv warning without the secret, got %q", out)
	}
	if out := stderrOf("gh_piped_secret_4242\n", "secret", "set", "github"); out != "" {
		t.Fatalf("a piped secret must not warn, got %q", out)
	}
}

// TestCLISecretCheckReportsVaultError: a miss shows the vault's hint once, and a vault that cannot
// be read (a wrong MINTRUN_VAULT_KEY, or a vault.json that links to a missing file) says so instead
// of calling the secret missing.
func TestCLISecretCheckReportsVaultError(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, home string)
		want  string
	}{
		{"miss", nil, `secret "cloudflare" is NOT configured in vault "keychain": secret "cloudflare" not found in vault (run mintrun init cloudflare)`},
		{"wrong passphrase", func(t *testing.T, home string) {
			setSecret(t, "cloudflare", "cf-"+leak)
			t.Setenv("MINTRUN_VAULT_KEY", "wrong-"+leak)
		}, `could not read vault "keychain" to check secret "cloudflare": decrypt vault (wrong MINTRUN_VAULT_KEY?): cipher: message authentication failed`},
		{"vault.json links to a missing file", func(t *testing.T, home string) {
			p := filepath.Join(home, ".mintrun", "vault.json")
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".missing", p); err != nil {
				t.Fatal(err)
			}
		}, `could not read vault "keychain" to check secret "cloudflare": read vault.json: no such file or directory`},
		{"empty value", func(t *testing.T, home string) {
			dir := filepath.Join(home, ".mintrun", "plugins", "emptyvault")
			writeFile(t, filepath.Join(dir, "plugin.json"), `{"name":"emptyvault","kind":"vault"}`)
			writeFile(t, filepath.Join(dir, "run"), "#!/bin/sh\necho '{\"value\":\"\"}'\n")
			if err := os.Chmod(filepath.Join(dir, "run"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("MINTRUN_VAULT", "emptyvault")
		}, `secret "cloudflare" is NOT configured in vault "emptyvault"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, _ := setupEnv(t)
			if c.setup != nil {
				c.setup(t, home)
			}
			r := runCLI(t, "", nil, "secret", "check", "cloudflare")
			if !r.exited || r.code != 1 || r.out != "" || r.err != c.want+"\n" {
				t.Fatalf("got exit %d (exited %v), stdout %q, stderr %q; want exit 1 and stderr %q", r.code, r.exited, r.out, r.err, c.want)
			}
			if strings.Contains(r.out+r.err, leak) {
				t.Fatal("secret check printed a planted secret or passphrase")
			}
		})
	}
}

// TestCLISecretCheckConfigured: a stored secret prints one line that names the key and the vault,
// and nothing derived from the value, not even its length.
func TestCLISecretCheckConfigured(t *testing.T) {
	setupEnv(t)
	setSecret(t, "cloudflare", "cf-"+leak)
	r := runCLI(t, "", nil, "secret", "check", "cloudflare")
	want := `Secret "cloudflare" is configured in vault "keychain" (value hidden).` + "\n"
	if r.code != 0 || r.out != want || r.err != "" {
		t.Fatalf("got exit %d, stdout %q, stderr %q; want exit 0 and stdout %q", r.code, r.out, r.err, want)
	}
}

// TestCLIExecSandbox: -sandbox runs the command behind sandbox-exec (or the Linux namespace
// sandbox when SandboxExecPath is empty), which hands back the command's exit code, and exec
// without it runs the command directly.
func TestCLIExecSandbox(t *testing.T) {
	home, _ := setupEnv(t)
	writeFile(t, filepath.Join(home, ".mintrun", "policy.json"), `{"cloudflare":{"allow_static":true}}`)
	setSecret(t, "cloudflare", "cf-"+leak)
	stub := filepath.Join(home, "bin", "sandbox-exec")
	linuxStub := filepath.Join(home, "bin", "mintrun-linux-sandbox")
	writeFile(t, stub, stubLog+"while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n")
	writeFile(t, linuxStub, "#!/bin/sh\nfor last; do :; done\nif [ \"$last\" = \"--\" ]; then exit 0; fi\n"+
		strings.TrimPrefix(stubLog, "#!/bin/sh\n")+"while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n")
	if err := errors.Join(
		os.Chmod(stub, 0o755),
		os.Chmod(linuxStub, 0o755),
		os.MkdirAll(filepath.Join(home, "Library", "Keychains"), 0o700),
	); err != nil {
		t.Fatal(err)
	}
	defer func(p, lp string, fn func(*exec.Cmd)) {
		core.SandboxExecPath, core.LinuxSandboxPath, core.LinuxSandboxSysProcAttr = p, lp, fn
	}(core.SandboxExecPath, core.LinuxSandboxPath, core.LinuxSandboxSysProcAttr)
	core.SandboxExecPath = stub
	for _, flags := range [][]string{{"-sandbox"}, nil} {
		r := runCLI(t, "", nil, append(append([]string{"exec"}, flags...), "-provider", "cloudflare", "-perms", "static", "--", "/bin/sh", "-c", "exit 7")...)
		calls := takeCalls(t, home)
		sandboxed := strings.HasPrefix(calls, "sandbox-exec -p (version 1)\n") && strings.HasSuffix(calls, " -- /bin/sh -c exit 7\n")
		if r.code != 7 || !r.exited || sandboxed != (flags != nil) || flags == nil && calls != "" {
			t.Errorf("%v: exit %d (exited %v), stderr %q, stub calls %q", flags, r.code, r.exited, r.err, calls)
		}
	}
	core.SandboxExecPath, core.LinuxSandboxPath, core.LinuxSandboxSysProcAttr = "", linuxStub, func(*exec.Cmd) {}
	for _, flags := range [][]string{{"-sandbox"}, nil} {
		r := runCLI(t, "", nil, append(append([]string{"exec"}, flags...), "-provider", "cloudflare", "-perms", "static", "--", "/bin/sh", "-c", "exit 7")...)
		calls := takeCalls(t, home)
		sandboxed := strings.HasPrefix(calls, "mintrun-linux-sandbox -mintrun-linux-sandbox -hide-dir ") && strings.HasSuffix(calls, " -- /bin/sh -c exit 7\n")
		if r.code != 7 || !r.exited || sandboxed != (flags != nil) || flags == nil && calls != "" {
			t.Errorf("linux %v: exit %d (exited %v), stderr %q, stub calls %q", flags, r.code, r.exited, r.err, calls)
		}
	}
}

// TestCLISecretPromptHidesEcho drives the interactive prompt (stdin is a character device) with a
// stub stty: echo goes off before the read and back on after it, unless stty failed to turn it off.
func TestCLISecretPromptHidesEcho(t *testing.T) {
	t.Setenv("MINTRUN_HOME", t.TempDir())
	t.Setenv("MINTRUN_FILE_VAULT", "1")
	t.Setenv("MINTRUN_VAULT", "keychain")
	dir := t.TempDir()
	stub, sttyLog := filepath.Join(dir, "stty"), filepath.Join(dir, "stty.log")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$MOCK_STTY_LOG\"\nexit \"$MOCK_STTY_EXIT\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_STTY_LOG", sttyLog)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	origStdin, origStty := os.Stdin, sttyPath
	os.Stdin, sttyPath = null, stub
	defer func() { os.Stdin, sttyPath = origStdin, origStty; _ = null.Close() }()

	for _, c := range []struct{ exit, log, prompt string }{
		{"0", "-echo\necho\n", "Enter master secret for \"cloudflare\": \n{"},
		{"1", "-echo\n", "Enter master secret for \"cloudflare\": {"},
	} {
		t.Setenv("MOCK_STTY_EXIT", c.exit)
		_ = os.Remove(sttyLog)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		origErr := os.Stderr
		os.Stderr = w
		code, exited := runMainWithArgs(t, "", "secret", "set", "cloudflare")
		os.Stderr = origErr
		_ = w.Close()
		out, _ := io.ReadAll(r)
		got, _ := os.ReadFile(sttyLog)
		if !exited || code != 1 || string(got) != c.log || !strings.HasPrefix(string(out), c.prompt) || !strings.Contains(string(out), "secret value cannot be empty") {
			t.Fatalf("stty exit %s: code %d (exited %v), stty calls %q, stderr %q", c.exit, code, exited, got, out)
		}
	}
}

// TestMain supplies a deterministic file-vault passphrase for the suite. The
// AES-256-GCM fallback now mandates MINTRUN_VAULT_KEY (audit C3); tests that need
// the "no passphrase" error path override it locally with t.Setenv.
func TestMain(m *testing.M) {
	if os.Getenv("MINTRUN_VAULT_KEY") == "" {
		os.Setenv("MINTRUN_VAULT_KEY", "mintrun-unit-test-passphrase")
	}
	os.Exit(m.Run())
}
