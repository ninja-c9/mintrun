package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

// mcpEntry is an MCP client's server entry. mintrun writes only Command and Args; Env is read to
// catch an entry that hands MINTRUN_VAULT_KEY to everyone who can read the config.
type mcpEntry struct {
	Command string                     `json:"command"`
	Args    []string                   `json:"args"`
	Env     map[string]json.RawMessage `json:"env,omitempty"`
}

type mcpConfig struct{ name, path string }

// mcpConfigs lists the MCP config files of the IDEs mintrun knows. Claude Code's is only ever
// read: `claude mcp add` changes it.
func mcpConfigs() []mcpConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	conf, err := os.UserConfigDir()
	if err != nil {
		conf = filepath.Join(home, ".config")
	}
	return []mcpConfig{
		{"Claude Code", filepath.Join(home, ".claude.json")},
		{"Cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"Claude Desktop", filepath.Join(conf, "Claude", "claude_desktop_config.json")},
		{"Antigravity", filepath.Join(home, ".gemini", "antigravity", "mcp_config.json")},
		{"Antigravity", filepath.Join(home, ".gemini", "config", "mcp_config.json")},
	}
}

// readMCPEntry returns the mintrun entry of the MCP config at path, or nil when there is none.
// No error quotes the file, which can hold other servers' API keys.
func readMCPEntry(path string) (*mcpEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, errors.New("cannot parse it as an MCP config")
	}
	e, ok := cfg.MCPServers["mintrun"]
	if !ok {
		return nil, nil
	}
	var entry mcpEntry
	if json.Unmarshal(e, &entry) != nil {
		return nil, errors.New("cannot parse its mintrun entry")
	}
	return &entry, nil
}

// addMCPEntry adds entry as the mintrun server of the MCP config at path and keeps every other
// key. It never replaces an existing mintrun entry (it returns false), copies the file to a
// timestamped backup first, and writes atomically with the file's own mode.
func addMCPEntry(path string, entry mcpEntry) (bool, error) {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p // a linked config (dotfiles) is changed where it lives
	}
	cfg, servers, mode := map[string]json.RawMessage{}, map[string]json.RawMessage{}, os.FileMode(0o600)
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err == nil {
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
		if json.Unmarshal(raw, &cfg) != nil || cfg == nil {
			return false, errors.New("cannot parse it as a JSON object, so it is left unchanged")
		}
		if s, ok := cfg["mcpServers"]; ok && json.Unmarshal(s, &servers) != nil {
			return false, errors.New("its mcpServers is not a JSON object, so it is left unchanged")
		}
		if servers == nil { // "mcpServers": null
			servers = map[string]json.RawMessage{}
		}
		if _, ok := servers["mintrun"]; ok {
			return false, nil
		}
		if err := os.WriteFile(path+".bak-"+time.Now().Format("20060102-150405"), raw, mode); err != nil {
			return false, fmt.Errorf("back up: %v", err)
		}
	}
	servers["mintrun"], _ = marshalJSON(entry, "") // strings only: cannot fail
	if cfg["mcpServers"], err = marshalJSON(servers, ""); err != nil {
		return false, err
	}
	out, err := marshalJSON(cfg, "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	return true, builtin.WriteFileAtomic(path, append(out, '\n'), mode)
}

// marshalJSON is json.Marshal without HTML escaping, so a config's other entries keep their text
// (an & in a URL stays an &), indented when indent is set.
func marshalJSON(v any, indent string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	err := enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), err
}

// mintrunPath is this binary's absolute path, symlinks resolved, for an IDE to launch. A `go run`
// binary lives in a temporary build directory that is deleted on exit, so it is refused.
func mintrunPath() (string, error) {
	p, err := osExecutable()
	if err == nil {
		p, err = filepath.EvalSymlinks(p)
	}
	if err != nil {
		return "", err
	}
	if strings.Contains(p, string(filepath.Separator)+"go-build") {
		return "", fmt.Errorf("%s is a temporary `go run` binary; build one first: go build -trimpath -o mintrun ./cmd/mintrun", p)
	}
	return p, nil
}

// fileVaultOnly reports whether kv keeps every secret in the encrypted file vault, which needs
// MINTRUN_VAULT_KEY in the environment of every process that reads it, IDEs included.
func fileVaultOnly(kv *builtin.KeychainVault) bool { return kv.SecretTool == "" && kv.ForceFile }

const ideEnvWarning = "an IDE started from the Dock or an app launcher may not get this shell's MINTRUN_VAULT_KEY, and mintrun never writes it into an IDE config: start the IDE from a shell that has it, or use the macOS Keychain or libsecret, which need no passphrase"

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type reportFunc func(status, format string, a ...any)

// cmdDoctor checks the setup without changing anything: the binary, the vault and which keys it
// holds, the approval channels, policy.json, and the IDEs' entries. It prints names, never a
// secret or its length, nor an IDE config's contents (other servers' entries can hold API keys),
// and exits 1 after any FAIL.
func cmdDoctor(ctx context.Context, rt *core.Runtime, args []string) {
	if len(args) > 0 {
		fatal("usage: mintrun doctor")
	}
	failed := false
	report := func(status, format string, a ...any) {
		failed = failed || status == "FAIL"
		fmt.Printf("%-5s %s\n", status, fmt.Sprintf(format, a...))
	}
	self := doctorBinary(report)
	doctorPolicy(rt, doctorVault(ctx, rt, report), report)
	doctorIDEs(self, report)
	if failed {
		exitFunc(1)
	}
}

func doctorBinary(report reportFunc) string {
	self, err := mintrunPath()
	if err != nil {
		report("FAIL", "binary: %v", err)
		return ""
	}
	report("ok", "binary: %s", self)
	p, err := exec.LookPath("mintrun")
	if err == nil {
		p, err = filepath.EvalSymlinks(p)
	}
	switch {
	case err != nil:
		report("warn", "PATH: no mintrun on it, so a shell cannot run it by name")
	case p != self:
		report("warn", "PATH: mintrun there is %s, not this binary", p)
	default:
		report("ok", "PATH: mintrun runs this binary")
	}
	return self
}

// doctorVault reports the default vault, which providers have a master secret in it, and the
// approval channels. It returns the providers that have one.
func doctorVault(ctx context.Context, rt *core.Runtime, report reportFunc) map[string]bool {
	stored := map[string]bool{}
	v, err := rt.Registry.Vault(rt.DefaultVault)
	if err != nil {
		report("FAIL", "vault: %v (check MINTRUN_VAULT)", err)
		return stored
	}
	kv, ok := v.(*builtin.KeychainVault)
	if !ok {
		report("-", "vault %s: not checked, since reading it can prompt", rt.DefaultVault)
		return stored
	}
	switch {
	case kv.SecretTool != "":
		report("ok", "vault: libsecret, with the encrypted file vault as fallback")
	case !kv.ForceFile:
		report("ok", "vault: macOS Keychain")
	case os.Getenv("MINTRUN_VAULT_KEY") == "":
		report("FAIL", "vault: the encrypted file vault needs MINTRUN_VAULT_KEY, which is not set, so no secret can be stored or read")
		return stored
	default:
		report("ok", "vault: encrypted file vault")
		report("warn", "vault: %s", ideEnvWarning)
	}
	for _, m := range rt.Registry.Manifests() {
		if m.Kind != core.KindProvider {
			continue
		}
		switch _, err := kv.GetSecret(ctx, m.Name); {
		case err == nil:
			stored[m.Name] = true
			report("ok", "secret %s: set", m.Name)
		case errors.Is(err, builtin.ErrSecretNotFound):
			report("-", "secret %s: not set", m.Name)
		default:
			report("FAIL", "secret %s: %v", m.Name, err)
		}
	}
	if len(stored) == 0 {
		report("warn", "secret: no provider has a master secret yet (run mintrun init)")
	}

	if runtime.GOOS == "darwin" {
		report("ok", "approval: macOS dialog")
	}
	for _, c := range []struct {
		key   string
		parse func(string) error
	}{
		{builtin.TelegramApprovalKey, func(s string) error { _, _, err := builtin.ParseTelegramConfig(s); return err }},
		{builtin.SlackApprovalKey, func(s string) error { _, _, err := builtin.ParseSlackConfig(s); return err }},
	} {
		cfg, err := kv.GetSecret(ctx, c.key)
		if err == nil {
			err = c.parse(cfg)
		}
		switch {
		case err == nil:
			report("ok", "approval: %s set", c.key)
		case errors.Is(err, builtin.ErrSecretNotFound):
			report("-", "approval: %s not set", c.key)
		default:
			report("FAIL", "approval: %v", err)
		}
	}
	return stored
}

// doctorPolicy reads policy.json as exec does, then strictly: exec ignores a field it does not
// know, so a misspelled one silently drops the limit it was meant to set.
func doctorPolicy(rt *core.Runtime, stored map[string]bool, report reportFunc) {
	p := filepath.Join(rt.HomeDir, "policy.json")
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		report("warn", "policy: no policy.json, so exec allows any scope and permission (run mintrun init policy)")
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		report("FAIL", "policy: %v, so exec denies every request", err)
		return
	}
	var rules map[string]core.PolicyRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		report("FAIL", "policy: %s is malformed (%v), so exec denies every request", p, err)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&map[string]core.PolicyRule{}); err != nil {
		report("FAIL", "policy: %v; exec ignores that field, so its rule may allow more than intended", err)
	} else {
		report("ok", "policy: %d rule(s) in %s", len(rules), p)
	}
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		if _, err := rt.Registry.Provider(name); err != nil {
			report("warn", "policy: no provider is named %q, so its rule never applies", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(stored)) {
		if _, ok := rules[name]; !ok {
			report("warn", "policy: no rule for %s, so exec allows any scope for it", name)
		}
	}
}

// doctorIDEs reports each IDE's mintrun entry. It never prints a config's contents, nor the
// entry's arguments or env values.
func doctorIDEs(self string, report reportFunc) {
	found := false
	for _, c := range mcpConfigs() {
		e, err := readMCPEntry(c.path)
		if err != nil {
			report("warn", "%s: %s: %v", c.name, c.path, err)
			continue
		}
		if e == nil {
			continue
		}
		found = true
		leak := false
		for k := range e.Env {
			leak = leak || strings.EqualFold(k, "MINTRUN_VAULT_KEY")
		}
		for _, a := range e.Args {
			leak = leak || strings.Contains(a, "MINTRUN_VAULT_KEY")
		}
		if leak {
			report("FAIL", "%s: %s hands MINTRUN_VAULT_KEY to mintrun, so anyone who can read that file can decrypt the vault; remove it", c.name, c.path)
		}
		switch _, err := os.Stat(e.Command); {
		case !filepath.IsAbs(e.Command):
			report("warn", "%s: the mintrun entry's command is not an absolute path, so it depends on the IDE's PATH", c.name)
		case err != nil:
			report("FAIL", "%s: the mintrun entry runs %s, which does not exist (run mintrun init mcp)", c.name, e.Command)
		case e.Command != self:
			report("warn", "%s: the mintrun entry runs %s, not this binary", c.name, e.Command)
		default:
			report("ok", "%s: runs this binary", c.name)
		}
		if !slices.Equal(e.Args, []string{"mcp"}) {
			report("warn", "%s: the mintrun entry's arguments are not just \"mcp\"", c.name)
		}
	}
	if !found {
		report("warn", "IDE: no IDE has a mintrun MCP entry (run mintrun init mcp)")
	}
}

// wizard asks on stdout and reads answers from stdin. A read waits in a goroutine, so Ctrl-C,
// which main's signal.NotifyContext turns into a cancelled ctx, still ends a prompt.
type wizard struct {
	ctx   context.Context
	rt    *core.Runtime
	vault core.VaultPlugin
	in    *bufio.Reader
}

func (w *wizard) read(hidden bool) string {
	got := make(chan string, 1)
	go func() {
		s, _ := w.in.ReadString('\n')
		got <- strings.TrimSpace(s)
	}()
	select {
	case s := <-got:
		return s
	case <-w.ctx.Done():
		if hidden {
			setEcho(true)
		}
		fmt.Println()
		fatal("interrupted")
		return ""
	}
}

func (w *wizard) ask(prompt string) string {
	fmt.Print(prompt + ": ")
	return w.read(false)
}

func (w *wizard) askHidden(prompt string) string {
	fmt.Print(prompt + " (typing stays hidden): ")
	hidden := setEcho(false)
	s := w.read(hidden)
	if hidden {
		setEcho(true) // not deferred: fatal exits without running defers
		fmt.Println()
	}
	return s
}

func (w *wizard) confirm(prompt string) bool {
	a := strings.ToLower(w.ask(prompt + " [y/N]"))
	return a == "y" || a == "yes"
}

// begin reports whether to go on and store key: one the vault already holds is replaced only on
// a yes. A file vault without its passphrase stops here, before anything is typed.
func (w *wizard) begin(key string) bool {
	if kv, ok := w.vault.(*builtin.KeychainVault); ok && fileVaultOnly(kv) && os.Getenv("MINTRUN_VAULT_KEY") == "" {
		fatal("the encrypted file vault needs a passphrase: export MINTRUN_VAULT_KEY in this shell, then run mintrun init again")
	}
	if _, err := w.vault.GetSecret(w.ctx, key); err == nil && !w.confirm(key+" is already stored. Replace it?") {
		fmt.Println("Left unchanged.")
		return false
	}
	return true
}

func (w *wizard) store(key, val string) {
	if err := w.vault.SetSecret(w.ctx, key, val); err != nil {
		fatal("store %s: %v", key, err)
	}
	fmt.Printf("Stored %q in vault %q.\n", key, w.vault.Manifest().Name)
}

// readFile asks for a file's path, as typed or dragged into a terminal (quoted, or with escaped
// spaces), and returns its contents.
func (w *wizard) readFile(prompt string) string {
	p := strings.ReplaceAll(strings.Trim(w.ask(prompt), `'"`), `\ `, " ")
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, rest)
		}
	}
	f, err := os.Open(p)
	if err != nil {
		fatal("%v", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		fatal("read %s: %v", p, err)
	}
	return string(b)
}

var initSteps = []struct {
	name, label string
	run         func(*wizard)
}{
	{"github", "GitHub (a GitHub App's private key)", (*wizard).github},
	{"aws", "AWS (an access key)", (*wizard).aws},
	{"gcp", "Google Cloud (a service-account key file)", (*wizard).gcp},
	{"cloudflare", "Cloudflare (an API token)", (*wizard).cloudflare},
	{"telegram", "approval through Telegram", (*wizard).telegram},
	{"slack", "approval through Slack", (*wizard).slack},
	{"policy", "a policy for GitHub", (*wizard).policy},
	{"mcp", "mintrun in your IDEs", (*wizard).mcp},
}

// cmdInit sets mintrun up step by step: master secrets, checked before they are stored, approval
// channels, a starting policy, and the IDEs' MCP entries. `mintrun init <step>` runs one step.
func cmdInit(ctx context.Context, rt *core.Runtime, args []string) {
	var names []string
	for _, s := range initSteps {
		names = append(names, s.name)
	}
	usage := "usage: mintrun init [" + strings.Join(names, "|") + "]"
	if len(args) > 1 {
		fatal("%s", usage)
	}
	vault, err := rt.Registry.Vault(rt.DefaultVault)
	if err != nil {
		fatal("%v", err)
	}
	w := &wizard{ctx: ctx, rt: rt, vault: vault, in: bufio.NewReader(os.Stdin)}
	for _, s := range initSteps {
		switch {
		case len(args) == 1 && args[0] == s.name:
			s.run(w)
			return
		case len(args) == 0 && w.confirm("Set up "+s.label+"?"):
			s.run(w)
		}
	}
	if len(args) == 1 {
		fatal("%s", usage)
	}
	fmt.Println("Next: mintrun doctor")
}

var (
	digitsRe       = regexp.MustCompile(`^[0-9]+$`)
	awsKeyIDRe     = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)
	awsSecretRe    = regexp.MustCompile(`^[A-Za-z0-9/+]{40}$`)
	awsTokenRe     = regexp.MustCompile(`^[A-Za-z0-9/+=]+$`)
	cfTokenRe      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	githubRemoteRe = regexp.MustCompile(`github\.com[:/]([A-Za-z0-9-]+/[A-Za-z0-9._-]+?)(?:\.git)?/?$`)
	githubScopeRe  = regexp.MustCompile(`^[A-Za-z0-9-]+/([A-Za-z0-9._-]+|\*)$`)
)

// github stores <app_id>:<installation_id>:<pem>. An empty installation ID stores <app_id>::<pem>,
// which pins none, so each request names one in params.installation_id.
func (w *wizard) github() {
	if !w.begin("github") {
		return
	}
	fmt.Println("mintrun mints a short-lived installation token per command from a GitHub App's private key.")
	app := w.ask("App ID (digits, on the App's settings page)")
	if !digitsRe.MatchString(app) {
		fatal("an App ID is digits only")
	}
	inst := w.ask("Installation ID (the digits at the end of the installation's settings URL; empty to pick one per request)")
	if inst != "" && !digitsRe.MatchString(inst) {
		fatal("an Installation ID is digits only")
	}
	pem := strings.TrimSpace(w.readFile("Path to the App's private key (.pem)"))
	if _, err := builtin.ParseRSAPrivateKey(pem); err != nil {
		fatal("private key: %v", err)
	}
	w.store("github", app+":"+inst+":"+pem)
	fmt.Println("Run commands with -provider github -scope owner/repo -perms <permission:access, e.g. contents:read>.")
	if inst == "" {
		fmt.Println(`No installation is pinned, so each request picks one in params.installation_id. List the allowed ones in policy.json: "github": {"allowed_installations": ["<id>"]}`)
	}
}

func (w *wizard) aws() {
	if !w.begin("aws") {
		return
	}
	fmt.Println("mintrun signs an STS AssumeRole request with this key, so each command gets a short-lived role session.")
	id := w.ask("Access key ID (AKIA… or ASIA…)")
	if !awsKeyIDRe.MatchString(id) {
		fatal("an access key ID is AKIA or ASIA followed by 16 capital letters or digits")
	}
	secret := w.askHidden("Secret access key")
	if !awsSecretRe.MatchString(secret) {
		fatal("a secret access key is 40 letters, digits, / or +")
	}
	master := id + ":" + secret
	if strings.HasPrefix(id, "ASIA") {
		token := w.askHidden("Session token (an ASIA key is temporary and needs one)")
		if !awsTokenRe.MatchString(token) {
			fatal("a session token is letters, digits, /, + or =")
		}
		master += ":" + token
	}
	w.store("aws", master)
	fmt.Println("Run commands with -provider aws -scope arn:aws:iam::<account>:role/<name> -perms <IAM actions, e.g. s3:ListBucket>.")
}

func (w *wizard) gcp() {
	if !w.begin("gcp") {
		return
	}
	raw := w.readFile("Path to the service account's JSON key file")
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if json.Unmarshal([]byte(raw), &sa) != nil || sa.ClientEmail == "" || sa.PrivateKey == "" {
		fatal("not a service-account key file: it needs client_email and private_key")
	}
	if _, err := builtin.ParseRSAPrivateKey(sa.PrivateKey); err != nil {
		fatal("private_key: %v", err)
	}
	w.store("gcp", raw)
	fmt.Println("Run commands with -provider gcp -perms cloud-platform.read-only (or another OAuth scope).")
}

func (w *wizard) cloudflare() {
	if !w.begin("cloudflare") {
		return
	}
	fmt.Println(`mintrun creates a short-lived token per command, so this API token needs "User → API Tokens → Edit" (the "Create Additional Tokens" template).`)
	tok := w.askHidden("API token")
	if !cfTokenRe.MatchString(tok) {
		fatal("a Cloudflare API token is letters, digits, _ or -")
	}
	w.store("cloudflare", tok)
	fmt.Println("Run commands with -provider cloudflare -scope <zone, e.g. example.com>.")
}

// telegram links the bot to whoever opens a one-time link, never to anyone who merely messages it,
// and stores the pair only after a yes to the sender's name.
func (w *wizard) telegram() {
	if !w.begin(builtin.TelegramApprovalKey) {
		return
	}
	fmt.Println("Create a bot for mintrun alone with @BotFather (/newbot): a bot with a webhook cannot be used.")
	token := w.askHidden("Bot token")
	id, name, err := builtin.TelegramLink(w.ctx, token, func(link string) {
		fmt.Println("On the phone that should approve, open this link and tap Start:\n  " + link + "\nWaiting…")
	})
	if err != nil {
		fatal("%v", err)
	}
	if !w.confirm(fmt.Sprintf("Message from %q (user ID %d). Is this you?", name, id)) {
		fatal("not stored: only the person who approves may open the link; run mintrun init telegram again")
	}
	w.store(builtin.TelegramApprovalKey, fmt.Sprintf("%d:%s", id, token))
	w.testApproval("telegram", builtin.TelegramApproval(w.rt))
}

// slack has no link to tie a member ID to the person typing it, so after the test request it
// asks who answered, and removes the setting when it was someone else.
func (w *wizard) slack() {
	if !w.begin(builtin.SlackApprovalKey) {
		return
	}
	fmt.Println("Create a Slack app for mintrun alone, give its bot the scopes chat:write, reactions:read and reactions:write, install it, and copy its Bot User OAuth Token (xoxb-…).")
	token := w.askHidden("Bot token")
	cfg := w.ask("Your member ID (your profile's ⋮ menu → Copy member ID)") + ":" + token
	if _, _, err := builtin.ParseSlackConfig(cfg); err != nil {
		fatal("%v", err)
	}
	w.store(builtin.SlackApprovalKey, cfg)
	w.testApproval("slack", builtin.SlackApproval(w.rt))
	if !w.confirm("Did you answer it yourself?") {
		if err := w.vault.DeleteSecret(w.ctx, builtin.SlackApprovalKey); err != nil {
			fatal("delete %s: %v", builtin.SlackApprovalKey, err)
		}
		fatal("removed %s: that member ID is someone else's; run mintrun init slack again", builtin.SlackApprovalKey)
	}
}

// testApproval sends one request through the channel just stored, the path exec takes, so a wrong
// token or user shows up now rather than at the first exec.
func (w *wizard) testApproval(channel string, ask func(context.Context, core.ExecRequest) (bool, error)) {
	fmt.Println("Sending a test approval request; answer it either way.")
	ok, err := ask(w.ctx, core.ExecRequest{MintRequest: core.MintRequest{Provider: "test"}, Command: []string{"mintrun", "init", channel}})
	if err != nil {
		fatal("test approval failed: %v (the settings stay stored; run mintrun init %s to replace them)", err, channel)
	}
	answer := "deny"
	if ok {
		answer = "allow"
	}
	fmt.Printf("Approval works: the answer was %s.\n", answer)
}

// policy suggests a fail-closed rule for GitHub: one repository (one owner's, only if asked), a
// clean environment, and never allow_static. It never changes an existing policy.json.
func (w *wizard) policy() {
	def := ""
	if out, err := exec.Command("git", "remote", "get-url", "origin").Output(); err == nil {
		if m := githubRemoteRe.FindStringSubmatch(strings.TrimSpace(string(out))); m != nil {
			def = m[1] // never print the URL: it can carry a token
		}
	}
	prompt := "GitHub repository that commands may get tokens for (owner/repo, or owner/* for all of owner's)"
	if def != "" {
		prompt += " [" + def + "]"
	}
	scope := w.ask(prompt)
	if scope == "" {
		scope = def
	}
	if !githubScopeRe.MatchString(scope) {
		fatal("expected owner/repo or owner/*")
	}
	rule := core.PolicyRule{AllowedScopes: []string{scope}, CleanEnv: true}
	p := filepath.Join(w.rt.HomeDir, "policy.json")
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		entry, _ := json.MarshalIndent(rule, "", "  ")
		if _, ok := w.rt.Policies["github"]; ok {
			fmt.Printf("%s already has a github rule; left unchanged. The suggested rule:\n\"github\": %s\n", p, entry)
		} else {
			fmt.Printf("%s exists, so it is left unchanged. Add this key to it:\n\"github\": %s\n", p, entry)
		}
		return
	}
	js, _ := json.MarshalIndent(map[string]core.PolicyRule{"github": rule}, "", "  ")
	fmt.Printf("%s:\n%s\n", p, js)
	if !w.confirm("Write it?") {
		return
	}
	if err := os.MkdirAll(w.rt.HomeDir, 0o700); err != nil {
		fatal("%v", err)
	}
	// O_EXCL: a policy.json made since the check above is never replaced. A partial write leaves
	// malformed JSON, which exec reads as deny-all.
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fatal("%v", err)
	}
	_, err = f.Write(append(js, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fatal("write %s: %v", p, err)
	}
	fmt.Println("Wrote " + p + ".")
}

// mcp adds mintrun to each IDE found, the way that IDE expects: `claude mcp add` for Claude Code,
// an install link for Cursor, and a file edit after a yes, with a backup, for Claude Desktop and
// Antigravity. No entry carries MINTRUN_VAULT_KEY: anyone who can read the config could then
// decrypt the vault.
func (w *wizard) mcp() {
	self, err := mintrunPath()
	if err != nil {
		fatal("%v", err)
	}
	entry := mcpEntry{Command: self, Args: []string{"mcp"}}
	server, _ := marshalJSON(entry, "")
	home, _ := os.UserHomeDir()
	antigravity := isDir(filepath.Join(home, ".gemini", "antigravity"))
	for _, c := range mcpConfigs() {
		_, statErr := os.Stat(c.path)
		exists := statErr == nil
		antigravity = antigravity && !(c.name == "Antigravity" && exists)
		switch e, err := readMCPEntry(c.path); {
		case err != nil:
			fmt.Printf("%s: %s: %v; left unchanged.\n", c.name, c.path, err)
		case e != nil:
			fmt.Printf("%s: %s already has a mintrun entry.\n", c.name, c.path)
		case c.name == "Claude Code":
			w.claudeCode(self, exists)
		case c.name == "Cursor":
			if isDir(filepath.Dir(c.path)) {
				w.cursor(server)
			}
		case exists, c.name == "Claude Desktop" && isDir(filepath.Dir(c.path)):
			w.offerFile(c.name, c.path, entry)
		}
	}
	if antigravity {
		fmt.Println("Antigravity: open Manage MCP Servers → View raw config, and add the entry below.")
	}
	fmt.Printf("Any other MCP client: add this under \"mcpServers\":\n\"mintrun\": %s\n", server)
	if kv, ok := w.vault.(*builtin.KeychainVault); ok && fileVaultOnly(kv) {
		fmt.Println("Note: " + ideEnvWarning + ".")
	}
}

func (w *wizard) claudeCode(self string, configured bool) {
	args := []string{"mcp", "add", "-s", "user", "mintrun", "--", self, "mcp"}
	claude, err := exec.LookPath("claude")
	if err != nil {
		if configured {
			fmt.Printf("Claude Code: run  claude mcp add -s user mintrun -- %s mcp\n", shellQuote(self))
		}
		return
	}
	if !w.confirm("Add mintrun to Claude Code (claude mcp add -s user)?") {
		return
	}
	cmd := exec.CommandContext(w.ctx, claude, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("claude mcp add failed (%v); run it yourself:\n  claude mcp add -s user mintrun -- %s mcp\n", err, shellQuote(self))
	}
}

func (w *wizard) cursor(server []byte) {
	link := "cursor://anysphere.cursor-deeplink/mcp/install?" + url.Values{"name": {"mintrun"}, "config": {base64.StdEncoding.EncodeToString(server)}}.Encode()
	fmt.Println("Cursor: open this link, and Cursor asks before it adds mintrun:\n  " + link)
	if runtime.GOOS == "darwin" && w.confirm("Open it now?") {
		if err := exec.Command(openPath, link).Run(); err != nil {
			fmt.Printf("open failed (%v); open the link yourself.\n", err)
		}
	}
}

// offerFile shows the entry, and after a yes adds it to the IDE's config file.
func (w *wizard) offerFile(name, path string, entry mcpEntry) {
	js, _ := marshalJSON(entry, "  ")
	fmt.Printf("%s: this entry goes under \"mcpServers\" in %s:\n\"mintrun\": %s\n", name, path, js)
	if !w.confirm("Add it (a backup of the file is kept)?") {
		return
	}
	switch added, err := addMCPEntry(path, entry); {
	case err != nil:
		fmt.Printf("%s: %s: %v\n", name, path, err)
	case added:
		fmt.Printf("Added. Quit and reopen %s to load it.\n", name)
	default:
		fmt.Printf("%s already has a mintrun entry.\n", path)
	}
}
