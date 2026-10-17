package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
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

// lastAudit returns the newest entry in <home>/audit.jsonl.
func lastAudit(t *testing.T, home string) core.AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var e core.AuditEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// appLine is one line mintrun sends the app.
type appLine struct {
	Type    string `json:"type"`
	Task    string `json:"task"`
	Request struct {
		Command []string `json:"command"`
		Via     string   `json:"via"`
	} `json:"request"`
	Entry core.AuditEntry `json:"entry"`
}

// fakeApp listens on <home>/app.sock as the macOS app does and passes on the first line of each
// connection. It answers an approve line with decision, or not at all when decision is empty, and
// drops a connection after 10 s, so a deadline that is not wired fails instead of hanging.
func fakeApp(t *testing.T, home, decision string) <-chan appLine {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(home, "app.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	lines := make(chan appLine, 8)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(conn)
				raw, err := r.ReadBytes('\n')
				var line appLine
				if err != nil || json.Unmarshal(raw, &line) != nil {
					return
				}
				lines <- line
				if line.Type == "approve" && decision != "" {
					fmt.Fprintf(conn, "{\"task\":%q,\"decision\":%q}\n", line.Task, decision)
				}
				_, _ = io.Copy(io.Discard, r) // until mintrun closes the connection
			}()
		}
	}()
	return lines
}

func nextLine(t *testing.T, lines <-chan appLine) appLine {
	t.Helper()
	select {
	case l := <-lines:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("the app got no line")
		return appLine{}
	}
}

// TestBootRuntimeSettings: settings.json, which the macOS app writes, picks the vault and the
// approval deadline; MINTRUN_VAULT and MINTRUN_FILE_VAULT=1 win over its vault; and a file that is
// there but unusable stops boot with an error that names the cause, never the path (rule 36).
func TestBootRuntimeSettings(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("MINTRUN_HOME", home)
		// On Linux, "file" turns off the secret-tool found here, which never runs.
		bin := t.TempDir()
		writeFile(t, filepath.Join(bin, "secret-tool"), "#!/bin/sh\nexit 1\n")
		if err := os.Chmod(filepath.Join(bin, "secret-tool"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
		force, tool := runtime.GOOS != "darwin", "" // the keychain vault when nothing picks its store
		if runtime.GOOS == "linux" {
			tool = filepath.Join(bin, "secret-tool")
		}
		p := filepath.Join(home, "settings.json")
		for _, c := range []struct {
			settings, vaultEnv, fileEnv string // settings "-" is no file
			vault                       string
			force                       bool
			tool                        string
			timeout                     time.Duration
		}{
			{"-", "", "", "keychain", force, tool, 0},
			{`{"vault":null,"approval_timeout_seconds":null}`, "", "", "keychain", force, tool, 0},
			{`{"vault":"keychain","approval_timeout_seconds":600}`, "", "", "keychain", force, tool, 10 * time.Minute},
			{`{"vault":"file","approval_timeout_seconds":90,"theme":"dark"}`, "", "", "keychain", true, "", 90 * time.Second},
			{`{"vault":"1password","approval_timeout_seconds":1}`, "", "", "1password", force, tool, time.Second},
			{`{"vault":"1password","approval_timeout_seconds":90}`, "keychain", "", "keychain", force, tool, 90 * time.Second},
			{`{"vault":"file"}`, "1password", "", "1password", force, tool, 0},
			{`{"vault":"1password"}`, "", "1", "keychain", true, "", 0},
		} {
			t.Setenv("MINTRUN_VAULT", c.vaultEnv)
			t.Setenv("MINTRUN_FILE_VAULT", c.fileEnv)
			_ = os.Remove(p)
			if c.settings != "-" {
				writeFile(t, p, c.settings)
			}
			rt, err := bootRuntime()
			if err != nil {
				t.Fatalf("%s: %v", c.settings, err)
			}
			v, err := rt.Registry.Vault("keychain")
			if err != nil {
				t.Fatal(err)
			}
			kv := v.(*builtin.KeychainVault)
			if rt.DefaultVault != c.vault || kv.ForceFile != c.force || kv.SecretTool != c.tool || rt.ApprovalTimeout != c.timeout {
				t.Errorf("%s with MINTRUN_VAULT=%q MINTRUN_FILE_VAULT=%q: vault %q, ForceFile %v, SecretTool %q, timeout %s; want %q, %v, %q, %s",
					c.settings, c.vaultEnv, c.fileEnv, rt.DefaultVault, kv.ForceFile, kv.SecretTool, rt.ApprovalTimeout, c.vault, c.force, c.tool, c.timeout)
			}
		}

		t.Setenv("MINTRUN_VAULT", "")
		t.Setenv("MINTRUN_FILE_VAULT", "")
		boot := func(what, want string) {
			t.Helper()
			if _, err := bootRuntime(); err == nil || err.Error() != want {
				t.Errorf("%s: err = %v, want %s", what, err, want)
			}
		}
		const malformed = "settings.json is malformed ("
		for _, c := range []struct{ settings, err string }{
			{`{"vault":"File"}`, `settings.json: vault must be "keychain", "1password" or "file"`},
			{`{"vault":""}`, `settings.json: vault must be "keychain", "1password" or "file"`},
			{`{"approval_timeout_seconds":0}`, "settings.json: approval_timeout_seconds must be 1 to 600"},
			{`{"approval_timeout_seconds":601}`, "settings.json: approval_timeout_seconds must be 1 to 600"},
			{`{"approval_timeout_seconds":-1}`, "settings.json: approval_timeout_seconds must be 1 to 600"},
			{`{"vault":1}`, malformed + "json: cannot unmarshal number into Go struct field settings.vault of type string)"},
			{`{"approval_timeout_seconds":1.5}`, malformed + "json: cannot unmarshal number 1.5 into Go struct field settings.approval_timeout_seconds of type int)"},
			{`{"approval_timeout_seconds":"60"}`, malformed + "json: cannot unmarshal string into Go struct field settings.approval_timeout_seconds of type int)"},
			{"[]", malformed + "json: cannot unmarshal array into Go value of type main.settings)"},
			{"{", malformed + "unexpected end of JSON input)"},
		} {
			writeFile(t, p, c.settings)
			boot(c.settings, c.err)
		}
		// main stops before any command runs.
		if r := runCLI(t, "", nil, "audit"); !r.exited || r.code != 1 || r.err != "boot runtime: settings.json is malformed (unexpected end of JSON input)\n" {
			t.Errorf("audit with a malformed settings.json: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
		}

		// Only a missing file means no settings.
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		boot("a directory", "settings.json cannot be read (is a directory)")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(home, "missing.json"), p); err != nil {
			t.Fatal(err)
		}
		boot("a dangling symlink", "settings.json cannot be read (no such file or directory)")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 0 { // root reads it anyway
			writeFile(t, p, "{}")
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			boot("mode 000", "settings.json cannot be read (permission denied)")
		}
	})

	// The app answers instead of the dialog and learns of each run, and settings.json sets how long
	// it has to answer. The home is short because a socket path holds at most 104 bytes on macOS.
	t.Run("app", func(t *testing.T) {
		home, err := os.MkdirTemp("", "mr")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(home) })
		t.Setenv("MINTRUN_HOME", home)
		t.Setenv("MINTRUN_FILE_VAULT", "1")
		t.Setenv("MINTRUN_VAULT", "keychain")
		writeFile(t, filepath.Join(home, "policy.json"), `{"cloudflare":{"allow_static":true}}`)
		setSecret(t, "cloudflare", "cf_app_secret")
		// A dialog, if mintrun shows one, logs that it ran and answers Deny.
		osa := filepath.Join(home, "osascript")
		writeFile(t, osa, "#!/bin/sh\necho ran >> \"$0.log\"\necho 'User canceled. (-128)' >&2\nexit 1\n")
		if err := os.Chmod(osa, 0o755); err != nil {
			t.Fatal(err)
		}
		origOsa := core.OsascriptPath
		core.OsascriptPath = osa
		t.Cleanup(func() { core.OsascriptPath = origOsa })
		dialogRan := func() bool { _, err := os.Stat(osa + ".log"); return err == nil }
		marker := filepath.Join(home, "ran")
		run := func() cliResult {
			return runCLI(t, "", nil, "exec", "-approve", "-provider", "cloudflare", "-perms", "static", "--", "touch", marker)
		}

		t.Run("allow", func(t *testing.T) {
			lines := fakeApp(t, home, "allow")
			if r := run(); !r.exited || r.code != 0 {
				t.Fatalf("exec: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
			}
			approve, started := nextLine(t, lines), nextLine(t, lines)
			if approve.Type != "approve" || approve.Task == "" || approve.Request.Via != "cli" || !slices.Equal(approve.Request.Command, []string{"touch", marker}) {
				t.Errorf("approve line = %+v", approve)
			}
			if started.Type != "started" || started.Entry.Task != approve.Task || started.Entry.Via != "cli" {
				t.Errorf("started line = %+v", started)
			}
			if e := lastAudit(t, home); e.Outcome != "done" || e.Task != approve.Task || e.Via != "cli" || e.DecidedAt == "" {
				t.Errorf("audit entry = %+v", e)
			}
			if _, err := os.Stat(marker); err != nil || dialogRan() {
				t.Errorf("the command did not run (%v), or the dialog ran (%v)", err, dialogRan())
			}
		})

		t.Run("no answer", func(t *testing.T) {
			_ = os.Remove(marker)
			writeFile(t, filepath.Join(home, "settings.json"), `{"approval_timeout_seconds":1}`)
			t.Cleanup(func() { os.Remove(filepath.Join(home, "settings.json")) })
			lines := fakeApp(t, home, "")
			if r := run(); !r.exited || r.code != 1 || r.err != "policy denied: no answer within 1s\n" {
				t.Fatalf("exec: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
			}
			if l := nextLine(t, lines); l.Type != "approve" {
				t.Errorf("first line = %+v, want an approve line", l)
			}
			if e := lastAudit(t, home); e.Outcome != "no_answer" || e.Via != "cli" {
				t.Errorf("audit entry = %+v", e)
			}
			if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) || dialogRan() {
				t.Errorf("the command ran (%v), or the dialog ran (%v)", err, dialogRan())
			}
		})

		t.Run("no app", func(t *testing.T) {
			if runtime.GOOS != "darwin" {
				t.Skip("the dialog runs on macOS only")
			}
			if r := run(); !r.exited || r.code != 1 || r.err != "policy denied: human-in-the-loop approval rejected (denied)\n" {
				t.Fatalf("exec: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
			}
			if log, err := os.ReadFile(osa + ".log"); err != nil || string(log) != "ran\n" {
				t.Errorf("dialog log = %q (%v), want one run", log, err)
			}
		})
	})
}

// TestCLIExecPaused: the pause file the app writes stops `mintrun exec`, and both the denial and
// the run after resume are audited as coming from the CLI.
func TestCLIExecPaused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MINTRUN_HOME", home)
	t.Setenv("MINTRUN_FILE_VAULT", "1")
	t.Setenv("MINTRUN_VAULT", "keychain")
	writeFile(t, filepath.Join(home, "policy.json"), `{"cloudflare":{"allow_static":true}}`)
	setSecret(t, "cloudflare", "cf_paused_secret")
	marker := filepath.Join(home, "ran")
	run := func() cliResult {
		return runCLI(t, "", nil, "exec", "-provider", "cloudflare", "-perms", "static", "--", "touch", marker)
	}

	writeFile(t, filepath.Join(home, "paused"), "")
	if r := run(); !r.exited || r.code != 1 || r.err != "policy denied: mintrun is paused\n" {
		t.Fatalf("paused exec: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the command ran while paused (%v)", err)
	}
	if e := lastAudit(t, home); e.Outcome != "blocked" || e.BlockedBy != "paused" || e.Via != "cli" {
		t.Errorf("audit entry = %+v", e)
	}

	if err := os.Remove(filepath.Join(home, "paused")); err != nil {
		t.Fatal(err)
	}
	if r := run(); !r.exited || r.code != 0 {
		t.Fatalf("exec after resume: code %d, exited %v\n%s%s", r.code, r.exited, r.out, r.err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the command did not run after resume: %v", err)
	}
	if e := lastAudit(t, home); e.Outcome != "done" || e.Via != "cli" {
		t.Errorf("audit entry = %+v", e)
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
