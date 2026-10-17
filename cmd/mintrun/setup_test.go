package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

// leak goes into every secret, token and foreign config value these tests plant, and no output
// may contain it. It never goes into a test name, which t.TempDir paths carry.
const leak = "LEAKCANARY"

// apiTransport serves api.telegram.org and slack.com in-process. Any other host, or a nil
// handler, is an error, so no test reaches the network.
type apiTransport func(http.ResponseWriter, *http.Request)

func (h apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if h == nil || (r.URL.Host != "api.telegram.org" && r.URL.Host != "slack.com") {
		return nil, fmt.Errorf("unexpected request to %s", r.URL.Host)
	}
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec.Result(), nil
}

// stubLog starts every stub on the test PATH: it logs the stub's name and arguments.
const stubLog = `#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "$HOME/calls.log"
`

// setupEnv gives a test a fresh HOME, mintrun home and file vault, and a PATH of logging stubs
// only, so nothing real runs. It returns HOME and the resolved path of the stub mintrun, which
// this binary claims to be. Call it inside each t.Run: its swaps end with that test.
func setupEnv(t *testing.T) (home, self string) {
	t.Helper()
	home = t.TempDir()
	bin := filepath.Join(home, "bin")
	for k, v := range map[string]string{"HOME": home, "XDG_CONFIG_HOME": "", "MINTRUN_HOME": filepath.Join(home, ".mintrun"),
		"MINTRUN_FILE_VAULT": "1", "MINTRUN_VAULT": "keychain", "MINTRUN_VAULT_KEY": "vault-" + leak, // never printed either
		"PATH": bin, "MOCK_GIT_URL": "", "MOCK_CLAUDE_EXIT": "0"} {
		t.Setenv(k, v)
	}
	for name, body := range map[string]string{
		"mintrun": "exit 0",
		"git": `[ -n "$MOCK_GIT_URL" ] || exit 1
printf '%s\n' "$MOCK_GIT_URL"`,
		"claude": `exit "$MOCK_CLAUDE_EXIT"`,
		"stty":   "exit 0",
		"open":   "exit 0",
	} {
		writeFile(t, filepath.Join(bin, name), stubLog+body+"\n")
		if err := os.Chmod(filepath.Join(bin, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	origStty, origOpen, origExe, origTransport := sttyPath, openPath, osExecutable, http.DefaultClient.Transport
	t.Cleanup(func() {
		sttyPath, openPath, osExecutable, http.DefaultClient.Transport = origStty, origOpen, origExe, origTransport
	})
	sttyPath, openPath = filepath.Join(bin, "stty"), filepath.Join(bin, "open")
	osExecutable = func() (string, error) { return filepath.Join(bin, "mintrun"), nil }
	http.DefaultClient.Transport = apiTransport(nil)
	self, err := filepath.EvalSymlinks(filepath.Join(bin, "mintrun"))
	if err != nil {
		t.Fatal(err)
	}
	return home, self
}

type cliResult struct {
	out, err string // stdout, and stderr with each {"error": …} line decoded to its message
	code     int
	exited   bool
}

// runCLI runs main with args and answers on stdin, then EOF, which reads as an empty answer.
func runCLI(t *testing.T, answers string, watch func(string), args ...string) cliResult {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	if _, err := inW.WriteString(answers); err != nil {
		t.Fatal(err)
	}
	inW.Close()
	origArgs := os.Args
	os.Args = append([]string{"mintrun"}, args...)
	defer func() { os.Args = origArgs }()
	return capture(t, inR, watch, main)
}

// capture runs fn with stdin swapped for stdin and stdout and stderr for pipes. watch, when set,
// sees all of stdout so far after each read.
func capture(t *testing.T, stdin *os.File, watch func(string), fn func()) cliResult {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := outR.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				if watch != nil {
					watch(out.String())
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { defer wg.Done(); _, _ = io.Copy(&stderr, errR) }()

	var r cliResult
	func() {
		origIn, origOut, origErr := os.Stdin, os.Stdout, os.Stderr
		os.Stdin, os.Stdout, os.Stderr = stdin, outW, errW
		defer func() { os.Stdin, os.Stdout, os.Stderr = origIn, origOut, origErr }()
		r.code, r.exited = withMockExit(t, fn)
	}()
	outW.Close()
	errW.Close()
	wg.Wait()
	outR.Close()
	errR.Close()

	r.out = out.String()
	for _, l := range strings.SplitAfter(stderr.String(), "\n") {
		var e struct {
			Error *string `json:"error"`
		}
		if json.Unmarshal([]byte(l), &e) == nil && e.Error != nil {
			l = *e.Error + "\n"
		}
		r.err += l
	}
	return r
}

// testVault is the default vault, booted as main boots it.
func testVault(t *testing.T) core.VaultPlugin {
	t.Helper()
	rt, err := bootRuntime()
	if err != nil {
		t.Fatal(err)
	}
	v, err := rt.Registry.Vault(rt.DefaultVault)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// getSecret returns the stored value of key, or "" when there is none.
func getSecret(t *testing.T, key string) string {
	t.Helper()
	s, err := testVault(t).GetSecret(context.Background(), key)
	if errors.Is(err, builtin.ErrSecretNotFound) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func setSecret(t *testing.T, key, val string) {
	t.Helper()
	if err := testVault(t).SetSecret(context.Background(), key, val); err != nil {
		t.Fatal(err)
	}
}

// takeCalls returns the stubs' call log and clears it.
func takeCalls(t *testing.T, home string) string {
	t.Helper()
	p := filepath.Join(home, "calls.log")
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(b))
}

func readJSON(t *testing.T, p string) any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type obj = map[string]any

// idePaths lists the IDE configs mcpConfigs knows under setupEnv's HOME: Claude Code, Cursor,
// Claude Desktop, then Antigravity's two.
func idePaths() []string {
	var ps []string
	for _, c := range mcpConfigs() {
		ps = append(ps, c.path)
	}
	return ps
}

// snapshot maps every path under dir to its contents ("<dir>" for a directory, "-> target" for
// a symlink).
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			m[p] = "<dir>"
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			m[p] = "-> " + target
			return err
		}
		b, err := os.ReadFile(p)
		m[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestCLIDoctor runs doctor on fresh, configured and broken setups. It must name each problem,
// never print a secret or another server's config, change no file, run no command, and exit 1
// exactly when it printed a FAIL.
func TestCLIDoctor(t *testing.T) {
	tgToken, slackToken := "12345:AAH"+leak, "xox"+"b-1-"+leak
	policy := func(home string) string { return filepath.Join(home, ".mintrun", "policy.json") }
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, home, self string)
		code  int
		want  []string
	}{
		{"fresh", nil, 0, []string{"ok    PATH: mintrun runs this binary", "ok    vault: encrypted file vault", "warn  vault: an IDE started from the Dock",
			"-     secret github: not set", "warn  secret: no provider has a master secret yet", "-     approval: approval-telegram not set",
			"warn  policy: no policy.json", "warn  IDE: no IDE has a mintrun MCP entry"}},
		{"configured", func(t *testing.T, home, self string) {
			setSecret(t, "github", "1:2:"+leak)
			setSecret(t, builtin.TelegramApprovalKey, "4242:"+tgToken)
			setSecret(t, builtin.SlackApprovalKey, "U0TEST:"+slackToken)
			writeFile(t, policy(home), `{"github":{"allowed_scopes":["acme/widgets"],"clean_env":true}}`)
			writeJSON(t, idePaths()[0], obj{"mcpServers": obj{"mintrun": obj{"command": self, "args": []string{"mcp"}},
				"other": obj{"command": "x", "env": obj{"API_KEY": leak}}}})
		}, 0, []string{"ok    secret github: set\n", "-     secret aws: not set\n", "ok    approval: approval-telegram set\n", "ok    approval: approval-slack set\n", // names only
			"ok    policy: 1 rule(s) in ", "ok    Claude Code: runs this binary"}},
		{"unknown policy field", func(t *testing.T, home, self string) {
			writeFile(t, policy(home), `{"github":{"allowed_scope":["acme/*"]}}`)
		}, 1, []string{`FAIL  policy: json: unknown field "allowed_scope"; exec ignores that field`}},
		{"malformed policy", func(t *testing.T, home, self string) {
			writeFile(t, policy(home), `{"github":`)
		}, 1, []string{"FAIL  policy: ", "is malformed (unexpected end of JSON input), so exec denies every request",
			"mintrun: WARNING: policy.json is malformed (unexpected end of JSON input); denying all exec until fixed"}},
		{"unreadable policy", func(t *testing.T, home, self string) {
			if err := os.MkdirAll(policy(home), 0o700); err != nil {
				t.Fatal(err)
			}
		}, 1, []string{"FAIL  policy: ", "is a directory, so exec denies every request",
			"mintrun: WARNING: policy.json cannot be read (is a directory); denying all exec until fixed"}},
		{"policy links to a missing file", func(t *testing.T, home, self string) {
			if err := os.MkdirAll(filepath.Dir(policy(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(policy(home)+".missing", policy(home)); err != nil {
				t.Fatal(err)
			}
		}, 1, []string{"FAIL  policy: ", "no such file or directory, so exec denies every request",
			"mintrun: WARNING: policy.json cannot be read (no such file or directory); denying all exec until fixed"}},
		{"rule for no provider", func(t *testing.T, home, self string) {
			setSecret(t, "github", "1:2:"+leak)
			writeFile(t, policy(home), `{"nosuch":{}}`)
		}, 0, []string{`warn  policy: no provider is named "nosuch", so its rule never applies`, "warn  policy: no rule for github, so exec allows any scope for it"}},
		{"vault key in an IDE env", func(t *testing.T, home, self string) {
			writeJSON(t, idePaths()[1], obj{"mcpServers": obj{"mintrun": obj{"command": self, "args": []string{"mcp"}, "env": obj{"MINTRUN_VAULT_KEY": leak}},
				"other": obj{"command": "x", "env": obj{"API_KEY": leak}}}})
		}, 1, []string{"FAIL  Cursor: ", "hands MINTRUN_VAULT_KEY to mintrun", "ok    Cursor: runs this binary"}},
		{"vault key in IDE args", func(t *testing.T, home, self string) {
			writeJSON(t, idePaths()[4], obj{"mcpServers": obj{"mintrun": obj{"command": "/bin/sh", "args": []string{"-c", "MINTRUN_VAULT_KEY=" + leak + " exec mintrun mcp"}}}})
		}, 1, []string{"FAIL  Antigravity: ", "hands MINTRUN_VAULT_KEY to mintrun", "warn  Antigravity: the mintrun entry runs /bin/sh, not this binary",
			`warn  Antigravity: the mintrun entry's arguments are not just "mcp"`}},
		{"missing command", func(t *testing.T, home, self string) {
			writeJSON(t, idePaths()[2], obj{"mcpServers": obj{"mintrun": obj{"command": filepath.Join(home, "gone", "mintrun"), "args": []string{"mcp"}}}})
		}, 1, []string{"FAIL  Claude Desktop: the mintrun entry runs ", "which does not exist (run mintrun init mcp)"}},
		{"relative command", func(t *testing.T, home, self string) {
			writeJSON(t, idePaths()[3], obj{"mcpServers": obj{"mintrun": obj{"command": "mintrun", "args": []string{"mcp"}}}})
		}, 0, []string{"warn  Antigravity: the mintrun entry's command is not an absolute path"}},
		{"broken IDE config", func(t *testing.T, home, self string) {
			writeFile(t, idePaths()[0], `{"mcpServers": `+leak)
		}, 0, []string{"warn  Claude Code: ", ": cannot parse it as an MCP config", "warn  IDE: no IDE has a mintrun MCP entry"}},
		{"bad Telegram setting", func(t *testing.T, home, self string) {
			setSecret(t, builtin.TelegramApprovalKey, leak)
		}, 1, []string{"FAIL  approval: approval-telegram must be <user_id>:<bot_token>"}},
		{"go run binary", func(t *testing.T, home, self string) {
			p := filepath.Join(home, "go-build123", "b001", "exe", "mintrun")
			writeFile(t, p, "")
			osExecutable = func() (string, error) { return p, nil }
		}, 1, []string{"FAIL  binary: ", "is a temporary `go run` binary"}},
		{"no passphrase", func(t *testing.T, home, self string) {
			t.Setenv("MINTRUN_VAULT_KEY", "")
		}, 1, []string{"FAIL  vault: the encrypted file vault needs MINTRUN_VAULT_KEY"}},
		{"wrong passphrase", func(t *testing.T, home, self string) {
			setSecret(t, "github", "1:2:"+leak)
			t.Setenv("MINTRUN_VAULT_KEY", "another-passphrase")
		}, 1, []string{"FAIL  secret github: decrypt vault (wrong MINTRUN_VAULT_KEY?)"}},
		{"nothing on PATH", func(t *testing.T, home, self string) {
			t.Setenv("PATH", t.TempDir())
		}, 0, []string{"warn  PATH: no mintrun on it"}},
		{"another mintrun on PATH", func(t *testing.T, home, self string) {
			p := filepath.Join(home, "other", "mintrun")
			writeFile(t, p, "#!/bin/sh\n")
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", filepath.Dir(p))
		}, 0, []string{"warn  PATH: mintrun there is ", ", not this binary"}},
		{"unknown vault", func(t *testing.T, home, self string) {
			t.Setenv("MINTRUN_VAULT", "nosuch")
		}, 1, []string{`FAIL  vault: vault plugin "nosuch" not found (check MINTRUN_VAULT)`}},
		{"1Password vault", func(t *testing.T, home, self string) {
			t.Setenv("MINTRUN_VAULT", "1password")
		}, 0, []string{"-     vault 1password: not checked, since reading it can prompt"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, self := setupEnv(t)
			if c.setup != nil {
				c.setup(t, home, self)
			}
			before := snapshot(t, home)
			r := runCLI(t, "", nil, "doctor")
			all := r.out + r.err
			if r.exited != (c.code != 0) || r.code != c.code || strings.Contains(r.out, "FAIL ") != (c.code == 1) {
				t.Errorf("code %d (exited %v), want %d:\n%s", r.code, r.exited, c.code, all)
			}
			for _, w := range c.want {
				if !strings.Contains(all, w) {
					t.Errorf("missing %q in:\n%s", w, all)
				}
			}
			if strings.Contains(all, leak) {
				t.Errorf("printed a secret:\n%s", all)
			}
			if !reflect.DeepEqual(snapshot(t, home), before) {
				t.Errorf("doctor changed a file or ran a command under %s", home)
			}
		})
	}
	t.Run("usage", func(t *testing.T) {
		setupEnv(t)
		if r := runCLI(t, "", nil, "doctor", "extra"); !r.exited || r.code != 1 || r.out != "" || r.err != "usage: mintrun doctor\n" {
			t.Errorf("doctor extra: code %d (exited %v):\n%s%s", r.code, r.exited, r.out, r.err)
		}
	})
}

// TestCLIInit drives every init step with typed answers against stubs and fake chat APIs: bad
// input is refused before anything is stored, nothing secret is printed, an existing secret or
// policy is replaced only on a yes, and IDE configs keep everything else.
func TestCLIInit(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// Encoded at run time, so no private key block sits in this file.
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8}))
	secrets := []string{leak, strings.Split(pkcs1, "\n")[1], strings.Split(pkcs8, "\n")[1]}
	tgToken, slackToken := "12345:AAH"+leak, "xox"+"b-1-"+leak

	noLeak := func(t *testing.T, r cliResult) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(r.out+r.err, s) {
				t.Errorf("printed a secret:\n%s%s", r.out, r.err)
			}
		}
	}
	// fails wants init to exit 1 with msg on stderr.
	fails := func(t *testing.T, answers, msg string, args ...string) cliResult {
		t.Helper()
		r := runCLI(t, answers, nil, append([]string{"init"}, args...)...)
		if !r.exited || r.code != 1 || !strings.Contains(r.err, msg) {
			t.Errorf("init %v: code %d (exited %v), want 1 with %q:\n%s%s", args, r.code, r.exited, msg, r.out, r.err)
		}
		noLeak(t, r)
		return r
	}
	// runs wants init to finish, and its stdout to hold each of want.
	runs := func(t *testing.T, answers string, args []string, want ...string) cliResult {
		t.Helper()
		r := runCLI(t, answers, nil, append([]string{"init"}, args...)...)
		if r.exited {
			t.Errorf("init %v: exit %d:\n%s%s", args, r.code, r.out, r.err)
		}
		for _, w := range want {
			if !strings.Contains(r.out, w) {
				t.Errorf("init %v: missing %q in:\n%s", args, w, r.out)
			}
		}
		noLeak(t, r)
		return r
	}
	stored := func(t *testing.T, key, want string) {
		t.Helper()
		if got := getSecret(t, key); got != want {
			t.Errorf("%s stored as %q, want %q", key, got, want)
		}
	}

	t.Run("usage", func(t *testing.T) {
		home, _ := setupEnv(t)
		usage := "usage: mintrun init [github|aws|gcp|cloudflare|telegram|slack|policy|mcp]"
		fails(t, "", usage, "github", "aws")
		fails(t, "", usage, "nope")
		before := snapshot(t, home)
		r := runs(t, "", nil, "Set up GitHub (a GitHub App's private key)? [y/N]: ", "Set up mintrun in your IDEs? [y/N]: ", "Next: mintrun doctor")
		if n := strings.Count(r.out, "? [y/N]: "); n != len(initSteps) {
			t.Errorf("asked %d questions, want %d", n, len(initSteps))
		}
		if !reflect.DeepEqual(snapshot(t, home), before) {
			t.Errorf("init with no yes changed a file or ran a command")
		}
		// A yes to a step whose secret is stored still asks before replacing it.
		keys := []string{"github", "aws", "gcp", "cloudflare", builtin.TelegramApprovalKey, builtin.SlackApprovalKey}
		for _, k := range keys {
			setSecret(t, k, "old-"+k)
		}
		r = runs(t, strings.Repeat("y\nn\n", len(keys)), nil, "Next: mintrun doctor")
		if n := strings.Count(r.out, "is already stored. Replace it? [y/N]: Left unchanged."); n != len(keys) {
			t.Errorf("left %d secrets unchanged, want %d:\n%s", n, len(keys), r.out)
		}
		for _, k := range keys {
			stored(t, k, "old-"+k)
		}
		t.Setenv("MINTRUN_VAULT", "nosuch")
		fails(t, "", `vault plugin "nosuch" not found`, "github")
	})

	t.Run("github", func(t *testing.T) {
		home, _ := setupEnv(t)
		bad, p1 := filepath.Join(home, "bad.pem"), filepath.Join(home, "key.pem")
		writeFile(t, bad, "not a key "+leak)
		writeFile(t, p1, pkcs1)
		writeFile(t, filepath.Join(home, "my key.pem"), pkcs8)
		fails(t, "abc\n", "an App ID is digits only", "github")
		fails(t, "123\nx1\n", "an Installation ID is digits only", "github")
		fails(t, "123\n456\n"+bad+"\n", "private key: invalid PEM block", "github")
		fails(t, "123\n456\n"+filepath.Join(home, "gone.pem")+"\n", "no such file or directory", "github")
		stored(t, "github", "")

		runs(t, "123\n456\n"+p1+"\n", []string{"github"}, `Stored "github" in vault "keychain".`, "-provider github")
		stored(t, "github", "123:456:"+strings.TrimSpace(pkcs1))
		runs(t, "n\n", []string{"github"}, "github is already stored. Replace it? [y/N]: ", "Left unchanged.")
		stored(t, "github", "123:456:"+strings.TrimSpace(pkcs1))
		// A path dragged into a terminal: escaped spaces, under ~.
		runs(t, "y\n123\n\n~/my\\ key.pem\n", []string{"github"}, "No installation is pinned")
		stored(t, "github", "123::"+strings.TrimSpace(pkcs8))
		if r := runs(t, "y\n77\n88\n\""+p1+"\"\n", []string{"github"}); strings.Contains(r.out, "No installation is pinned") {
			t.Errorf("pinned installation reported as unpinned:\n%s", r.out)
		}
		stored(t, "github", "77:88:"+strings.TrimSpace(pkcs1))
	})

	t.Run("aws", func(t *testing.T) {
		home, _ := setupEnv(t)
		id, asia := "AKIA"+strings.Repeat("X", 16), "ASIA"+strings.Repeat("Y", 16)
		secret, token := leak+strings.Repeat("s", 26)+"/+0a", leak+"tok=="
		fails(t, "AKIA123\n", "an access key ID is AKIA or ASIA followed by 16 capital letters or digits", "aws")
		fails(t, id+"\nshort"+leak+"\n", "a secret access key is 40 letters, digits, / or +", "aws")
		fails(t, asia+"\n"+secret+"\nbad token!\n", "a session token is letters, digits, /, + or =", "aws")
		stored(t, "aws", "")
		takeCalls(t, home)
		runs(t, id+"\n"+secret+"\n", []string{"aws"}, "Secret access key (typing stays hidden): ", `Stored "aws"`)
		stored(t, "aws", id+":"+secret)
		if c := takeCalls(t, home); c != "stty -echo\nstty echo\n" {
			t.Errorf("stty calls %q", c)
		}
		runs(t, "y\n"+asia+"\n"+secret+"\n"+token+"\n", []string{"aws"}, "Session token (an ASIA key is temporary and needs one)")
		stored(t, "aws", asia+":"+secret+":"+token)
	})

	t.Run("gcp", func(t *testing.T) {
		home, _ := setupEnv(t)
		p := filepath.Join(home, "sa.json")
		for _, c := range []struct{ content, msg string }{
			{`{"client_email":"mintrun-test"}`, "not a service-account key file: it needs client_email and private_key"},
			{`{"client_email":"mintrun-test","private_key":"` + leak + `"}`, "private_key: invalid PEM block"},
			{"not json " + leak, "not a service-account key file"},
		} {
			writeFile(t, p, c.content)
			fails(t, p+"\n", c.msg, "gcp")
		}
		stored(t, "gcp", "")
		raw, err := json.MarshalIndent(obj{"type": "service_account", "client_email": "mintrun-test", "private_key": pkcs8}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, string(raw)+"\n")
		runs(t, p+"\n", []string{"gcp"}, `Stored "gcp"`, "-provider gcp")
		stored(t, "gcp", string(raw))
	})

	t.Run("cloudflare", func(t *testing.T) {
		home, _ := setupEnv(t)
		fails(t, "bad token "+leak+"\n", "a Cloudflare API token is letters, digits, _ or -", "cloudflare")
		takeCalls(t, home)
		tok := "cf_" + leak + "-1"
		runs(t, tok+"\n", []string{"cloudflare"}, "API token (typing stays hidden): ", `Stored "cloudflare"`)
		stored(t, "cloudflare", tok)
		if c := takeCalls(t, home); c != "stty -echo\nstty echo\n" {
			t.Errorf("stty calls %q", c)
		}
		// No passphrase: stop before asking for anything.
		t.Setenv("MINTRUN_VAULT_KEY", "")
		fails(t, tok+"\n", "the encrypted file vault needs a passphrase", "cloudflare")
		if c := takeCalls(t, home); c != "" {
			t.Errorf("ran %q", c)
		}
	})

	t.Run("interrupt", func(t *testing.T) {
		home, _ := setupEnv(t)
		rt, err := bootRuntime()
		if err != nil {
			t.Fatal(err)
		}
		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer inR.Close()
		defer inW.Close() // ends the read the wizard left waiting
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := capture(t, inR, nil, func() { cmdInit(ctx, rt, []string{"cloudflare"}) })
		if !r.exited || r.code != 1 || r.err != "interrupted\n" {
			t.Errorf("code %d (exited %v):\n%s%s", r.code, r.exited, r.out, r.err)
		}
		// Echo comes back on even though the hidden read never finished.
		if c := takeCalls(t, home); c != "stty -echo\nstty echo\n" {
			t.Errorf("stty calls %q", c)
		}
	})

	t.Run("telegram", func(t *testing.T) {
		setupEnv(t)
		codeRe := regexp.MustCompile(`start=([A-Z2-7]+)\n`)
		// run answers init telegram against a fake Bot API: a stranger's /start with a wrong code
		// comes first, then the linking user's, then that user's tap on Allow.
		run := func(t *testing.T, answers string) (cliResult, []string) {
			t.Helper()
			codes := make(chan string, 1)
			var once sync.Once
			var calls []string
			var code, nonce string
			http.DefaultClient.Transport = apiTransport(func(w http.ResponseWriter, r *http.Request) {
				method, ok := strings.CutPrefix(r.URL.Path, "/bot"+tgToken+"/")
				if !ok {
					t.Errorf("request to an unexpected path")
					return
				}
				calls = append(calls, method)
				var body struct {
					ChatID      int64 `json:"chat_id"`
					ReplyMarkup struct {
						InlineKeyboard [][]struct {
							CallbackData string `json:"callback_data"`
						} `json:"inline_keyboard"`
					} `json:"reply_markup"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				result := "true"
				switch {
				case method == "getMe":
					result = `{"username":"mintrun_test_bot"}`
				case method == "sendMessage":
					if body.ChatID != 4242 {
						t.Errorf("sendMessage to %d", body.ChatID)
					}
					nonce = strings.TrimPrefix(body.ReplyMarkup.InlineKeyboard[0][0].CallbackData, "allow:")
					result = `{"message_id":7}`
				case method == "getUpdates" && nonce == "":
					if code == "" {
						select {
						case code = <-codes:
						case <-time.After(5 * time.Second):
							fmt.Fprint(w, `{"ok":false,"description":"Conflict: can't use getUpdates method while webhook is active"}`)
							return
						}
					}
					result = `[{"update_id":1,"message":{"text":"/start WRONGCODE","from":{"id":666}}},` +
						`{"update_id":2,"message":{"text":"/start ` + code + `","from":{"id":4242,"first_name":"Ada","last_name":"Lovelace","username":"ada"}}}]`
				case method == "getUpdates":
					result = fmt.Sprintf(`[{"update_id":3,"callback_query":{"id":"cb","data":"allow:%s","from":{"id":4242},"message":{"date":%d}}}]`, nonce, time.Now().Unix())
				}
				fmt.Fprintf(w, `{"ok":true,"result":%s}`, result)
			})
			r := runCLI(t, answers, func(out string) {
				if m := codeRe.FindStringSubmatch(out); m != nil {
					once.Do(func() { codes <- m[1] })
				}
			}, "init", "telegram")
			noLeak(t, r)
			return r, calls
		}

		if r, calls := run(t, "nope\n"); r.code != 1 || !strings.Contains(r.err, "telegram: a bot token looks like <digits>:<letters, digits, _ or ->") || len(calls) != 0 {
			t.Errorf("bad token: code %d, calls %v:\n%s", r.code, calls, r.err)
		}
		if r, calls := run(t, tgToken+"\nn\n"); r.code != 1 || !strings.Contains(r.err, "not stored: only the person who approves may open the link") ||
			!slices.Equal(calls, []string{"getMe", "getUpdates"}) {
			t.Errorf("not me: code %d, calls %v:\n%s", r.code, calls, r.err)
		}
		stored(t, builtin.TelegramApprovalKey, "")

		r, calls := run(t, tgToken+"\ny\n")
		if r.exited {
			t.Errorf("exit %d:\n%s%s", r.code, r.out, r.err)
		}
		for _, w := range []string{"Bot token (typing stays hidden): ", "https://t.me/mintrun_test_bot?start=",
			`Message from "Ada Lovelace (@ada)" (user ID 4242). Is this you? [y/N]: `, `Stored "approval-telegram"`, "Approval works: the answer was allow."} {
			if !strings.Contains(r.out, w) {
				t.Errorf("missing %q in:\n%s", w, r.out)
			}
		}
		if want := []string{"getMe", "getUpdates", "sendMessage", "getUpdates", "getUpdates", "answerCallbackQuery", "editMessageText"}; !slices.Equal(calls, want) {
			t.Errorf("calls %v, want %v", calls, want)
		}
		stored(t, builtin.TelegramApprovalKey, "4242:"+tgToken)
	})

	t.Run("slack", func(t *testing.T) {
		setupEnv(t)
		// run answers init slack against a fake Web API, where the stored user reacts ✅.
		post := `{"ok":true,"channel":"D1","ts":"1.2"}`
		run := func(t *testing.T, answers string) (cliResult, []string) {
			t.Helper()
			var calls []string
			http.DefaultClient.Transport = apiTransport(func(w http.ResponseWriter, r *http.Request) {
				method := strings.TrimPrefix(r.URL.Path, "/api/")
				calls = append(calls, method)
				if r.Header.Get("Authorization") != "Bearer "+slackToken {
					t.Errorf("%s: wrong bearer", method)
				}
				switch method {
				case "chat.postMessage":
					if ch := r.FormValue("channel"); ch != "U0TEST" {
						t.Errorf("posted to %q", ch)
					}
					fmt.Fprint(w, post)
				case "reactions.get":
					fmt.Fprint(w, `{"ok":true,"message":{"reactions":[{"name":"white_check_mark","users":["UBOT","U0TEST"]},{"name":"x","users":["UBOT"]}]}}`)
				default:
					fmt.Fprint(w, `{"ok":true}`)
				}
			})
			r := runCLI(t, answers, nil, "init", "slack")
			noLeak(t, r)
			return r, calls
		}
		want := []string{"chat.postMessage", "reactions.add", "reactions.add", "reactions.get", "chat.update"}

		if r, calls := run(t, slackToken+"\nbad\n"); r.code != 1 || !strings.Contains(r.err, "approval-slack must be <user_id>:<bot_token>") || len(calls) != 0 {
			t.Errorf("bad member ID: code %d, calls %v:\n%s", r.code, calls, r.err)
		}
		stored(t, builtin.SlackApprovalKey, "")
		// Someone else answered: the setting is removed again.
		if r, calls := run(t, slackToken+"\nU0TEST\nn\n"); r.code != 1 || !strings.Contains(r.err, "removed approval-slack: that member ID is someone else's") ||
			!slices.Equal(calls, want) {
			t.Errorf("not me: code %d, calls %v:\n%s", r.code, calls, r.err)
		}
		stored(t, builtin.SlackApprovalKey, "")

		r, calls := run(t, slackToken+"\nU0TEST\ny\n")
		if r.exited || !strings.Contains(r.out, "Approval works: the answer was allow.") || !slices.Equal(calls, want) {
			t.Errorf("exit %d (exited %v), calls %v:\n%s%s", r.code, r.exited, calls, r.out, r.err)
		}
		stored(t, builtin.SlackApprovalKey, "U0TEST:"+slackToken)

		// A failed test fails init, and the setting stays stored, as the error says.
		post = `{"ok":false,"error":"channel_not_found"}`
		if r, calls := run(t, "y\n"+slackToken+"\nU0TEST\n"); r.code != 1 || !slices.Equal(calls, []string{"chat.postMessage"}) ||
			!strings.Contains(r.err, "test approval failed: slack chat.postMessage: HTTP 200: channel_not_found (the settings stay stored; run mintrun init slack to replace them)") {
			t.Errorf("failed test: code %d, calls %v:\n%s", r.code, calls, r.err)
		}
		stored(t, builtin.SlackApprovalKey, "U0TEST:"+slackToken)
	})

	t.Run("policy", func(t *testing.T) {
		home, _ := setupEnv(t)
		p := filepath.Join(home, ".mintrun", "policy.json")
		read := func() string { b, _ := os.ReadFile(p); return string(b) }
		// The remote URL carries a token, so it is never printed.
		t.Setenv("MOCK_GIT_URL", "https://x-access-token:"+leak+"@github.com/acme/widgets.git")
		want := "{\n  \"github\": {\n    \"allowed_scopes\": [\n      \"acme/widgets\"\n    ],\n    \"clean_env\": true\n  }\n}\n"
		runs(t, "\ny\n", []string{"policy"}, "(owner/repo, or owner/* for all of owner's) [acme/widgets]: ", "Wrote "+p+".")
		if got := read(); got != want {
			t.Errorf("policy.json:\n%s\nwant:\n%s", got, want)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("policy.json mode: %v %v", fi, err)
		}
		if c := takeCalls(t, home); c != "git remote get-url origin\n" {
			t.Errorf("calls %q", c)
		}

		// Never changes an existing policy.json, only shows the rule.
		runs(t, "\n", []string{"policy"}, "already has a github rule; left unchanged. The suggested rule:\n\"github\": {")
		if got := read(); got != want {
			t.Errorf("policy.json changed:\n%s", got)
		}
		writeFile(t, p, `{"aws":{}}`)
		runs(t, "\n", []string{"policy"}, "exists, so it is left unchanged. Add this key to it:\n\"github\": {")
		if got := read(); got != `{"aws":{}}` {
			t.Errorf("policy.json changed:\n%s", got)
		}

		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		fails(t, "acme\n", "expected owner/repo or owner/*", "policy")
		runs(t, "acme/widgets\nn\n", []string{"policy"})
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("wrote policy.json after a no: %v", err)
		}
		runs(t, "acme/*\ny\n", []string{"policy"})
		if got := read(); !strings.Contains(got, `"acme/*"`) {
			t.Errorf("policy.json:\n%s", got)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		t.Setenv("MOCK_GIT_URL", "") // no remote: no default to accept
		fails(t, "\n", "expected owner/repo or owner/*", "policy")
	})

	t.Run("mcp", func(t *testing.T) {
		home, self := setupEnv(t)
		ide := idePaths()
		other := `"other":{"command":"x","env":{"API_KEY":"` + leak + `"}}`
		claudeJSON := `{"mcpServers":{` + other + `}}`
		desktop := `{"globalShortcut":"Alt+Space","mcpServers":{` + other + `},"preferences":{"a&b":"<x>"}}`
		writeFile(t, ide[0], claudeJSON)
		writeFile(t, ide[2], desktop)
		if err := os.Chmod(ide[2], 0o640); err != nil {
			t.Fatal(err)
		}
		writeFile(t, ide[3], `{"mcpServers":{}}`)
		if err := os.MkdirAll(filepath.Dir(ide[1]), 0o700); err != nil { // Cursor is installed
			t.Fatal(err)
		}
		// Every offer declined: no command runs, no link opens, no file changes.
		runs(t, "", []string{"mcp"}, "Add mintrun to Claude Code (claude mcp add -s user)? [y/N]: ",
			"Claude Desktop: this entry goes under \"mcpServers\" in "+ide[2]+":", "Add it (a backup of the file is kept)? [y/N]: ")
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("ran without a yes: %q", calls)
		}
		for p, want := range map[string]string{ide[2]: desktop, ide[3]: `{"mcpServers":{}}`} {
			if b, _ := os.ReadFile(p); string(b) != want {
				t.Errorf("%s changed without a yes:\n%s", p, b)
			}
		}
		if baks, _ := filepath.Glob(ide[2] + ".bak-*"); len(baks) != 0 {
			t.Errorf("backups %v", baks)
		}

		answers := "y\ny\ny\n" // claude mcp add, Claude Desktop, Antigravity
		if runtime.GOOS == "darwin" {
			answers += "y\n" // and open the Cursor link
		}
		r := runs(t, answers, []string{"mcp"}, "Added. Quit and reopen Claude Desktop to load it.", "Added. Quit and reopen Antigravity to load it.",
			"Any other MCP client: add this under \"mcpServers\":", "Note: "+ideEnvWarning+".")
		if strings.Contains(r.out, "Antigravity: open Manage MCP Servers") {
			t.Errorf("told to edit an Antigravity config it just edited:\n%s", r.out)
		}
		calls := takeCalls(t, home)
		if !strings.Contains(calls, "claude mcp add -s user mintrun -- "+self+" mcp\n") {
			t.Errorf("calls %q", calls)
		}
		if runtime.GOOS == "darwin" && !strings.Contains(calls, "open cursor://anysphere.cursor-deeplink/mcp/install?") {
			t.Errorf("calls %q", calls)
		}

		entry := obj{"command": self, "args": []any{"mcp"}} // never an env
		m := regexp.MustCompile(`cursor://anysphere\.cursor-deeplink/mcp/install\?(\S+)`).FindStringSubmatch(r.out)
		if m == nil {
			t.Fatalf("no Cursor link in:\n%s", r.out)
		}
		q, err := url.ParseQuery(m[1])
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := base64.StdEncoding.DecodeString(q.Get("config"))
		var got any
		if err == nil {
			err = json.Unmarshal(cfg, &got)
		}
		if err != nil || q.Get("name") != "mintrun" || !reflect.DeepEqual(got, any(entry)) {
			t.Errorf("Cursor link %s: %v %v", m[0], got, err)
		}

		var want obj
		if err := json.Unmarshal([]byte(desktop), &want); err != nil {
			t.Fatal(err)
		}
		want["mcpServers"].(obj)["mintrun"] = entry
		if got := readJSON(t, ide[2]); !reflect.DeepEqual(got, any(want)) {
			t.Errorf("Claude Desktop config: %v", got)
		}
		if b, _ := os.ReadFile(ide[2]); !strings.Contains(string(b), `"a&b": "<x>"`) {
			t.Errorf("other keys re-escaped:\n%s", b)
		}
		if fi, err := os.Stat(ide[2]); err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("Claude Desktop config mode: %v %v", fi, err)
		}
		baks, _ := filepath.Glob(ide[2] + ".bak-*")
		if len(baks) != 1 {
			t.Fatalf("backups %v", baks)
		}
		if b, _ := os.ReadFile(baks[0]); string(b) != desktop {
			t.Errorf("backup:\n%s", b)
		}
		if got := readJSON(t, ide[3]); !reflect.DeepEqual(got, any(obj{"mcpServers": obj{"mintrun": entry}})) {
			t.Errorf("Antigravity config: %v", got)
		}
		if b, _ := os.ReadFile(ide[0]); string(b) != claudeJSON {
			t.Errorf("Claude Code's config was edited:\n%s", b)
		}

		// Again: entries already there are left alone, with no new backup.
		runs(t, "", []string{"mcp"}, "Claude Desktop: "+ide[2]+" already has a mintrun entry.", "Antigravity: "+ide[3]+" already has a mintrun entry.",
			"Add mintrun to Claude Code (claude mcp add -s user)? [y/N]: ")
		if baks, _ := filepath.Glob(ide[2] + ".bak-*"); len(baks) != 1 {
			t.Errorf("backups %v", baks)
		}
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("ran without a yes: %q", calls)
		}

		writeFile(t, ide[2], "{"+leak)
		runs(t, "", []string{"mcp"}, "Claude Desktop: "+ide[2]+": cannot parse it as an MCP config; left unchanged.")
		if b, _ := os.ReadFile(ide[2]); string(b) != "{"+leak {
			t.Errorf("unparsable config changed:\n%s", b)
		}

		t.Setenv("MOCK_CLAUDE_EXIT", "1")
		runs(t, "y\n", []string{"mcp"}, "claude mcp add failed (exit status 1); run it yourself:\n  claude mcp add -s user mintrun -- "+shellQuote(self)+" mcp")
		if err := os.Remove(filepath.Join(home, "bin", "claude")); err != nil {
			t.Fatal(err)
		}
		runs(t, "", []string{"mcp"}, "Claude Code: run  claude mcp add -s user mintrun -- "+shellQuote(self)+" mcp")
		if err := os.Remove(ide[3]); err != nil {
			t.Fatal(err)
		}
		runs(t, "", []string{"mcp"}, "Antigravity: open Manage MCP Servers → View raw config, and add the entry below.")

		gob := filepath.Join(home, "go-build1", "b001", "exe", "mintrun")
		writeFile(t, gob, "")
		osExecutable = func() (string, error) { return gob, nil }
		fails(t, "", "is a temporary `go run` binary", "mcp")
	})
}

// TestCLIInitAddMCPEntry pins the config edit itself: a file that is not a JSON object, or whose
// mcpServers is not one, is left alone; an existing mintrun entry is never replaced; a missing
// file is created 0600; a linked file is changed where it lives.
func TestCLIInitAddMCPEntry(t *testing.T) {
	dir := t.TempDir()
	entry := mcpEntry{Command: "/opt/mintrun/mintrun", Args: []string{"mcp"}}
	check := func(p string, wantAdded bool) {
		t.Helper()
		if added, err := addMCPEntry(p, entry); added != wantAdded || err != nil {
			t.Fatalf("%s: added %v, %v", p, added, err)
		}
		if e, err := readMCPEntry(p); err != nil || !reflect.DeepEqual(e, &entry) && wantAdded {
			t.Errorf("%s: entry %+v, %v", p, e, err)
		}
	}

	p := filepath.Join(dir, "c.json")
	for _, bad := range []string{"null", "[1]", `{"mcpServers":[1]}`} {
		writeFile(t, p, bad)
		if added, err := addMCPEntry(p, entry); added || err == nil {
			t.Errorf("%s: added %v, %v", bad, added, err)
		}
		if b, _ := os.ReadFile(p); string(b) != bad {
			t.Errorf("%s: changed to %s", bad, b)
		}
	}
	writeFile(t, p, `{"mcpServers":null}`)
	check(p, true)

	kept := `{"mcpServers":{"mintrun":{"command":"/elsewhere","args":["mcp"]}}}`
	q := filepath.Join(dir, "kept", "c.json")
	writeFile(t, q, kept)
	check(q, false)
	if b, _ := os.ReadFile(q); string(b) != kept {
		t.Errorf("existing entry replaced:\n%s", b)
	}
	if baks, _ := filepath.Glob(q + ".bak-*"); len(baks) != 0 {
		t.Errorf("backed up an unchanged file: %v", baks)
	}

	fresh := filepath.Join(dir, "new", "dir", "c.json")
	check(fresh, true)
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("new config mode: %v %v", fi, err)
	}

	target, link := filepath.Join(dir, "dotfiles", "c.json"), filepath.Join(dir, "link.json")
	writeFile(t, target, `{}`)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	check(link, true)
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("link replaced by a file: %v %v", fi, err)
	}
	if e, err := readMCPEntry(target); err != nil || !reflect.DeepEqual(e, &entry) {
		t.Errorf("target entry %+v, %v", e, err)
	}
}
