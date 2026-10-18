package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const RedactedPlaceholder = "[MINTRUN:REDACTED]"

// ExecRequest defines a blind command execution request.
type ExecRequest struct {
	MintRequest
	Vault      string   `json:"vault,omitempty"` // Defaults to Runtime.DefaultVault
	Command    []string `json:"command"`         // e.g. ["wrangler", "deploy"]
	WorkingDir string   `json:"cwd,omitempty"`   // Optional working directory
	TimeoutSec int      `json:"timeout_seconds,omitempty"`
	Approve    bool     `json:"approve,omitempty"`   // Require interactive human-in-the-loop approval
	CleanEnv   bool     `json:"clean_env,omitempty"` // Child gets only the base env + policy allowed_env + Lease.Env (can only tighten policy)
	Sandbox    bool     `json:"sandbox,omitempty"`   // Run under sandbox-exec (macOS), away from mintrun's home and the Keychain (can only tighten policy)
	Purpose    string   `json:"purpose,omitempty"`   // The agent's reason in plain words: shown to the approver, never trusted
	// Set by mintrun, never by an agent: MCP arguments unmarshal straight into ExecRequest.
	Client    string `json:"-"` // MCP clientInfo name, self-reported by the AI app
	Via       string `json:"-"` // "cli" or "mcp"
	Task      string `json:"-"` // ExecBlind's per-call handle (rand.Text): opaque, never a secret
	FromAgent bool   `json:"-"` // Set by the MCP bridge after decoding: CheckPolicy then refuses any Vault or TimeoutSec, neither of which an agent picks
}

// ExecResult contains the scrubbed output of a blind command execution.
type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	LeaseID    string `json:"lease_id"`
	Ephemeral  bool   `json:"ephemeral"`
	Revoked    bool   `json:"revoked"`
	DurationMs int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated,omitempty"` // stdout or stderr passed MaxOutputBytes and was cut
}

// AuditEntry is written to `~/.mintrun/audit.jsonl` once for every ExecBlind call.
// Secrets the runner holds are scrubbed; an entry written before the master secret loads (a
// denial, an unknown vault or provider, a missing master) keeps the raw command, client, and
// purpose (no secret is loaded yet to scrub against), so MCP mintrun_audit hands agents argv[0] only.
type AuditEntry struct {
	Timestamp   string   `json:"ts"`
	Task        string   `json:"task,omitempty"`
	Via         string   `json:"via,omitempty"`
	Client      string   `json:"client,omitempty"`
	Provider    string   `json:"provider"`
	Scope       string   `json:"scope,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Command     []string `json:"command,omitempty"`
	Purpose     string   `json:"purpose,omitempty"`
	// Outcome is blocked (CheckPolicy denied; see BlockedBy), denied (a human said no), no_answer
	// (nobody answered within ApprovalTimeout), failed (every approval channel failed, or the
	// vault, provider, mint, or command did), stopped (Track stopped the run), interrupted (the
	// caller's context ended), timed_out (the exec timeout), or done (a clean exit). Entries
	// written before it existed have none.
	Outcome    string `json:"outcome,omitempty"`
	BlockedBy  string `json:"blocked_by,omitempty"` // PolicyDecision.BlockedBy
	DecidedAt  string `json:"decided_at,omitempty"` // When a human answered the approval
	LeaseID    string `json:"lease_id,omitempty"`
	Ephemeral  bool   `json:"ephemeral"`
	ExpiresAt  string `json:"expires_at,omitempty"` // Ephemeral leases only: a static lease is the master, whose expiry is unknown
	Revoked    bool   `json:"revoked"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated,omitempty"`
	// Sandbox is whether the command runs under sandbox-exec, from the verdict that asked a human
	// or allowed the request. A request the gate blocked first has none, and one it blocked after
	// an approval keeps what the human was shown.
	Sandbox bool   `json:"sandbox,omitempty"`
	Error   string `json:"error,omitempty"`
}

// PolicyRule controls which scopes, permissions, and commands are permitted for a provider.
type PolicyRule struct {
	AllowedScopes        []string `json:"allowed_scopes,omitempty"`        // Empty = allow all scopes (supports '*' wildcard)
	AllowedPermissions   []string `json:"allowed_permissions,omitempty"`   // Empty = allow all permissions (supports '*' wildcard)
	BlockedCommands      []string `json:"blocked_commands,omitempty"`      // Substrings or binary names to reject
	MaxTTLSeconds        int      `json:"max_ttl_seconds,omitempty"`       // Caps requested TTL
	RequireApproval      bool     `json:"require_approval,omitempty"`      // Prompt human via native OS dialog before minting
	AllowStatic          bool     `json:"allow_static,omitempty"`          // Permit non-JIT static mode (params.mode=static or "static" perm)
	CleanEnv             bool     `json:"clean_env,omitempty"`             // Force clean-env for every exec of this provider (audit M1)
	AllowedEnv           []string `json:"allowed_env,omitempty"`           // Host env names (globs) a clean-env child keeps; non-empty implies clean_env
	AllowedInstallations []string `json:"allowed_installations,omitempty"` // Exact params.installation_id values; non-empty requires a listed one
	Sandbox              bool     `json:"sandbox,omitempty"`               // Run every exec of this provider under sandbox-exec (macOS only; denied elsewhere)
}

func matchPattern(pattern, value string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	v := strings.ToLower(strings.TrimSpace(value))
	if p == "*" || p == v {
		return true
	}
	if strings.HasSuffix(p, "*") && strings.HasPrefix(v, strings.TrimSuffix(p, "*")) {
		return true
	}
	if strings.HasPrefix(p, "*") && strings.HasSuffix(v, strings.TrimPrefix(p, "*")) {
		return true
	}
	return false
}

// hasToken reports whether list contains tok (case-insensitive, whitespace-trimmed).
func hasToken(list []string, tok string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), tok) {
			return true
		}
	}
	return false
}

// Runtime coordinates Vaults, Providers, Bridges, Policy enforcement, Blind Execution, and Audit Logging.
type Runtime struct {
	HomeDir      string
	DefaultVault string
	Registry     *Registry
	ApprovalFunc func(ctx context.Context, req ExecRequest) (bool, error)
	// ApprovalTimeout bounds the wait for a human. 0, or more than 10 minutes, means 10 minutes,
	// because Telegram and Slack stop at their own 10.
	ApprovalTimeout time.Duration
	// Track, if set, learns of each run once its lease is minted, before the command starts.
	// Closing the channel it returns stops the run; its ctx ends once the run's final audit entry
	// is written.
	Track func(ctx context.Context, started AuditEntry) <-chan struct{}
}

// errStopped is the cause a Track stop cancels a run with.
var errStopped = errors.New("stopped")

func NewRuntime(homeDir, defaultVault string, reg *Registry) *Runtime {
	if defaultVault == "" {
		defaultVault = "keychain"
	}
	rt := &Runtime{
		HomeDir:      homeDir,
		DefaultVault: defaultVault,
		Registry:     reg,
		ApprovalFunc: OSApproval,
	}
	if _, err := rt.LoadPolicies(); err != nil {
		what := "cannot be read"
		switch err.(type) {
		case *json.SyntaxError, *json.UnmarshalTypeError:
			what = "is malformed"
		}
		fmt.Fprintf(os.Stderr, "mintrun: WARNING: policy.json %s (%v); denying all exec until fixed\n", what, err)
	}
	return rt
}

func (rt *Runtime) PluginsDir() string {
	return filepath.Join(rt.HomeDir, "plugins")
}

// LoadPolicies reads <home>/policy.json, which CheckPolicy does on every call, so a saved rule
// applies to the next request. No file means no rules. A file that cannot be read or parsed
// (a dangling symlink too) is an error, and CheckPolicy then denies every exec: a broken policy
// must not degrade to allow-all.
func (rt *Runtime) LoadPolicies() (map[string]PolicyRule, error) {
	p := filepath.Join(rt.HomeDir, "policy.json")
	// Only a missing policy.json means no rules. Lstat, so a symlink to a missing file still
	// counts as a policy that cannot be read.
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, pathCause(err) // the path must never reach an agent
	}
	var rules map[string]PolicyRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// PolicyDecision is the static verdict of the exec gate for one ExecRequest (MCP mintrun_policy_check).
type PolicyDecision struct {
	Allowed          bool   `json:"allowed"`
	Reason           string `json:"reason,omitempty"`     // Denial reason: the exact error ExecBlind returns
	BlockedBy        string `json:"blocked_by,omitempty"` // Which check denied: invalid_request, paused, purpose, policy_file, env_dump, static, scope, permission, installation, command, sandbox
	ApprovalRequired bool   `json:"approval_required"`    // ExecBlind would ask a human (approve, require_approval, MINTRUN_APPROVE=1)
	TTLSeconds       int    `json:"ttl_seconds"`          // Lease TTL requested from the provider after max_ttl_seconds and the 600s default
	CleanEnv         bool   `json:"clean_env"`            // Child gets the clean env (request, policy clean_env, or allowed_env)
	Sandbox          bool   `json:"sandbox"`              // Child runs under sandbox-exec (request or policy sandbox)
}

// CheckPolicy runs every static rule of the exec gate: request validation, the fail-closed
// policy.json load, the anti-exfiltration guard, the provider's policy rule, and whether a
// sandbox that is on can be set up. It never opens a vault, mints, executes, or prompts a human.
// ExecBlind enforces this same verdict, so a dry run and a real exec cannot drift.
func (rt *Runtime) CheckPolicy(req ExecRequest) PolicyDecision {
	d, _, _ := rt.decide(req)
	return d
}

// decide is CheckPolicy plus the rule's allowed_env, so ExecBlind builds the child env from the
// policy.json it checked, and the sandbox-exec argv prefix ExecBlind runs the command behind (nil
// when the sandbox is off), built here so nothing about it can fail after the mint. (A slice
// field would make PolicyDecision incomparable.)
func (rt *Runtime) decide(req ExecRequest) (PolicyDecision, []string, []string) {
	deny := func(by, format string, a ...any) (PolicyDecision, []string, []string) {
		return PolicyDecision{Reason: fmt.Sprintf(format, a...), BlockedBy: by}, nil, nil
	}
	if len(req.Command) == 0 {
		return deny("invalid_request", "exec requires a non-empty command")
	}
	if req.Provider == "" {
		return deny("invalid_request", "exec requires a provider name")
	}
	// The vault is the operator's choice (MINTRUN_VAULT, or the CLI's -vault), never an agent's.
	if req.FromAgent && req.Vault != "" {
		return deny("invalid_request", "policy denied: an agent cannot pick the vault (got %q); omit it to use the vault mintrun was started with (MINTRUN_VAULT)", req.Vault)
	}
	// Nor is the timeout an agent's: its timeout_seconds would lift the 5-minute limit to any length.
	if req.FromAgent && req.TimeoutSec != 0 {
		return deny("invalid_request", "policy denied: an agent cannot set timeout_seconds (got %d); omit it to run with the 5-minute limit", req.TimeoutSec)
	}
	// The app's Pause creates <home>/paused. Lstat, so a dangling symlink pauses too; any error
	// but "not there" fails closed.
	if _, err := os.Lstat(filepath.Join(rt.HomeDir, "paused")); !errors.Is(err, os.ErrNotExist) {
		return deny("paused", "policy denied: mintrun is paused")
	}
	// The purpose is agent text a human reads before approving: short, one line, and nothing
	// that hides or reorders the text around it.
	if len(req.Purpose) > 300 || !utf8.ValidString(req.Purpose) || strings.IndexFunc(req.Purpose, func(r rune) bool {
		return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
	}) >= 0 {
		return deny("purpose", "policy denied: purpose must be at most 300 bytes of plain text (no control, format, or line-break characters)")
	}

	rules, err := rt.LoadPolicies()
	if err != nil {
		return deny("policy_file", "policy denied: policy.json failed to load (%v)", err)
	}

	// Built-in guardrail: block trivial secret-dumping shell commands in blind runner.
	if len(req.Command) > 0 {
		bin := filepath.Base(req.Command[0])
		joined := strings.ToLower(strings.Join(req.Command, " "))
		if bin == "env" || bin == "printenv" || bin == "export" ||
			strings.Contains(joined, "printenv") || strings.Contains(joined, "/proc/self/environ") {
			return deny("env_dump", "policy denied: command %q attempts to dump environment variables", req.Command[0])
		}
	}

	rule, hasRule := rules[req.Provider]

	// Non-JIT static mode (direct long-lived secret, no ephemeral token or revoke) must be
	// explicitly opted into via policy; an agent cannot silently downgrade by requesting it.
	if req.Params["mode"] == "static" || hasToken(req.Permissions, "static") {
		if !(hasRule && rule.AllowStatic) {
			return deny("static", "policy denied: static (non-JIT) mode for provider %q requires \"allow_static\": true in policy.json", req.Provider)
		}
	}

	if hasRule {
		// Scope allowlist is fail-closed: an empty scope matches only a '*' or empty pattern.
		if len(rule.AllowedScopes) > 0 {
			allowed := false
			for _, s := range rule.AllowedScopes {
				if matchPattern(s, req.Scope) {
					allowed = true
					break
				}
			}
			if !allowed {
				return deny("scope", "policy denied: scope %q is not in allowed_scopes for provider %q", req.Scope, req.Provider)
			}
		}
		if len(rule.AllowedPermissions) > 0 {
			// Fail closed: a request declaring no permissions is denied unless '*' is allowed.
			if len(req.Permissions) == 0 && !hasToken(rule.AllowedPermissions, "*") {
				return deny("permission", "policy denied: provider %q requires declared permissions within allowed_permissions", req.Provider)
			}
			for _, perm := range req.Permissions {
				allowed := false
				for _, ap := range rule.AllowedPermissions {
					if matchPattern(ap, perm) {
						allowed = true
						break
					}
				}
				if !allowed {
					return deny("permission", "policy denied: permission %q is not in allowed_permissions for provider %q", perm, req.Provider)
				}
			}
		}
		// Fail closed and exact (no wildcards): params.installation_id picks the installation a
		// token is minted for. The gate never sees the master, so a request must name a listed ID
		// even when the master pins one.
		if inst := req.Params["installation_id"]; len(rule.AllowedInstallations) > 0 && !hasToken(rule.AllowedInstallations, inst) {
			return deny("installation", "policy denied: params.installation_id %q is not in allowed_installations for provider %q", inst, req.Provider)
		}
		if len(rule.BlockedCommands) > 0 && len(req.Command) > 0 {
			cmdLine := strings.ToLower(strings.Join(req.Command, " "))
			for _, blocked := range rule.BlockedCommands {
				if blocked != "" && strings.Contains(cmdLine, strings.ToLower(blocked)) {
					return deny("command", "policy denied: command matches blocked pattern %q", blocked)
				}
			}
		}
		if rule.MaxTTLSeconds > 0 && (req.TTLSeconds <= 0 || req.TTLSeconds > rule.MaxTTLSeconds) {
			req.TTLSeconds = rule.MaxTTLSeconds
		}
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 600
	}

	d := PolicyDecision{
		Allowed:          true,
		ApprovalRequired: req.Approve || (hasRule && rule.RequireApproval) || os.Getenv("MINTRUN_APPROVE") == "1",
		TTLSeconds:       req.TTLSeconds,
		CleanEnv:         req.CleanEnv || rule.CleanEnv || len(rule.AllowedEnv) > 0,
		Sandbox:          req.Sandbox || rule.Sandbox,
	}
	if !d.Sandbox {
		return d, rule.AllowedEnv, nil
	}
	// Fail closed: a sandbox that is on but cannot be set up denies the request.
	sandbox, err := sandboxArgv(rt.HomeDir)
	if err != nil {
		return deny("sandbox", "policy denied: sandbox is on, but %v", err)
	}
	return d, rule.AllowedEnv, sandbox
}

// SandboxExecPath is the macOS sandbox runner a sandboxed exec goes through, a var so tests can
// stub it; it is empty on every other OS.
var SandboxExecPath = func() string {
	if runtime.GOOS == "darwin" {
		return "/usr/bin/sandbox-exec"
	}
	return ""
}()

// LinuxSandboxPath is the executable re-invoked in a new user and mount namespace on Linux
// (os.Executable() on linux, empty elsewhere), and LinuxRunDir is the per-UID runtime directory
// root ("/run/user"), both vars so tests on any OS can stub them.
var (
	LinuxSandboxPath = func() string {
		if runtime.GOOS == "linux" {
			if p, err := os.Executable(); err == nil {
				return p
			}
		}
		return ""
	}()
	LinuxRunDir = "/run/user"
)

// sandboxProfile allows everything except mintrun's home, the Keychain folder, and the Mach
// services the Security framework reaches the Keychain through.
const sandboxProfile = `(version 1)
(allow default)
(deny file-read* file-write* (subpath (param "MINTRUN_DIR")))
(deny file-read* file-write* (subpath (param "KEYCHAINS")))
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.securityd.general")
  (global-name "com.apple.securityd.ckks")
  (global-name "com.apple.securityd.aps")
  (global-name "com.apple.securityd.sos")
  (global-name "com.apple.security.octagon")
  (global-name "com.apple.security.kcsharing")
  (global-name "com.apple.security.escrow-update"))
`

// sandboxArgv returns the sandbox runner argv the command goes behind. The profile or mount table
// matches real paths, so folders and sockets are made absolute and their symlinks resolved. A
// reason keeps only the error's cause, never a path (rule 36): it reaches agents and audit.jsonl.
func sandboxArgv(homeDir string) ([]string, error) {
	if SandboxExecPath == "" {
		if LinuxSandboxPath != "" {
			return linuxSandboxArgv(homeDir)
		}
		return nil, errors.New("this host has no sandbox-exec (macOS only)")
	}
	if _, err := os.Stat(SandboxExecPath); err != nil {
		return nil, fmt.Errorf("sandbox-exec cannot be used (%v)", pathCause(err))
	}
	dir, err := realDir(homeDir)
	if err != nil {
		return nil, fmt.Errorf("mintrun's home cannot be resolved (%v)", pathCause(err))
	}
	userHome, err := os.UserHomeDir()
	keychains := ""
	if err == nil {
		keychains, err = realDir(filepath.Join(userHome, "Library", "Keychains"))
	}
	if err != nil {
		return nil, fmt.Errorf("the Keychain folder cannot be resolved (%v)", pathCause(err))
	}
	return []string{SandboxExecPath, "-p", sandboxProfile, "-D", "MINTRUN_DIR=" + dir, "-D", "KEYCHAINS=" + keychains, "--"}, nil
}

// linuxSandboxArgv builds and probes the Linux user+mount namespace sandbox prefix: a read-only
// mode-000 tmpfs over mintrun's home and the keyring folders (~/.local/share/keyrings,
// $XDG_DATA_HOME/keyrings, /run/user/<uid>/keyring, $XDG_RUNTIME_DIR/keyring), and /dev/null
// bind-mounted over the D-Bus session bus sockets (/run/user/<uid>/bus, $XDG_RUNTIME_DIR/bus, and
// $DBUS_SESSION_BUS_ADDRESS). Any non-filesystem D-Bus address or blocked user/mount namespace
// fails closed before any vault opens.
func linuxSandboxArgv(homeDir string) ([]string, error) {
	dir, err := realDir(homeDir)
	if err != nil {
		return nil, fmt.Errorf("mintrun's home cannot be resolved (%v)", pathCause(err))
	}
	dirs := []string{dir}
	var files []string
	addDir := func(p string) error {
		real, ok, err := realExisting(p)
		if err != nil || !ok {
			return err
		}
		if info, err := os.Stat(real); err != nil || !info.IsDir() {
			return errors.New("not a directory")
		}
		for i, d := range dirs {
			if subpath(d, real) {
				return nil
			}
			if subpath(real, d) {
				dirs[i] = real
				return nil
			}
		}
		dirs = append(dirs, real)
		return nil
	}
	addFile := func(p string) error {
		real, ok, err := realExisting(p)
		if err != nil || !ok {
			return err
		}
		if info, err := os.Stat(real); err != nil || info.IsDir() {
			return errors.New("is a directory")
		}
		for _, d := range dirs {
			if subpath(d, real) {
				return nil
			}
		}
		if !slices.Contains(files, real) {
			files = append(files, real)
		}
		return nil
	}
	userHome, err := os.UserHomeDir()
	if err == nil {
		userHome, err = filepath.EvalSymlinks(userHome)
	}
	if err == nil {
		err = addDir(filepath.Join(userHome, ".local", "share", "keyrings"))
	}
	if xdgData := os.Getenv("XDG_DATA_HOME"); err == nil && xdgData != "" {
		if !filepath.IsAbs(xdgData) {
			err = errors.New("XDG_DATA_HOME must be an absolute path")
		} else {
			err = addDir(filepath.Join(xdgData, "keyrings"))
		}
	}
	runDirs := []string{filepath.Join(LinuxRunDir, strconv.Itoa(os.Getuid()))}
	if xdgRun := os.Getenv("XDG_RUNTIME_DIR"); err == nil && xdgRun != "" {
		if !filepath.IsAbs(xdgRun) {
			err = errors.New("XDG_RUNTIME_DIR must be an absolute path")
		} else {
			runDirs = append(runDirs, xdgRun)
		}
	}
	for _, rd := range runDirs {
		if err == nil {
			err = addDir(filepath.Join(rd, "keyring"))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("the keyring folder cannot be resolved (%v)", pathCause(err))
	}
	for _, rd := range runDirs {
		if err = addFile(filepath.Join(rd, "bus")); err != nil {
			break
		}
	}
	if bus := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); err == nil && bus != "" {
		var sock string
		sock, err = dbusSocketPath(bus)
		if err == nil {
			err = addFile(sock)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("the D-Bus session bus cannot be hidden (%v)", pathCause(err))
	}
	argv := []string{LinuxSandboxPath, "-mintrun-linux-sandbox"}
	for _, d := range dirs {
		argv = append(argv, "-hide-dir", d)
	}
	for _, f := range files {
		argv = append(argv, "-hide-file", f)
	}
	argv = append(argv, "--")
	probe := exec.Command(argv[0], argv[1:]...)
	LinuxSandboxSysProcAttr(probe)
	var stderr bytes.Buffer
	probe.Stderr = &stderr
	if err := probe.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = pathCause(err).Error()
		}
		return nil, fmt.Errorf("the Linux sandbox cannot be used (%s)", msg)
	}
	return argv, nil
}

// realExisting resolves an absolute path p when it exists on disk. A missing path whose existing
// prefix resolves returns ("", false, nil); a dangling symlink or any other error fails.
func realExisting(p string) (string, bool, error) {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real, true, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	for cur := p; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); !errors.Is(err, fs.ErrNotExist) {
			_, err := filepath.EvalSymlinks(cur)
			return "", false, err
		}
	}
}

// dbusSocketPath extracts and resolves the filesystem socket path from a D-Bus unix:path=...
// address. Any other address (unix:abstract=..., tcp:..., autolaunch:, multiple ";" addresses,
// percent escapes, or a relative path) is refused because a mount namespace cannot hide it.
func dbusSocketPath(addr string) (string, error) {
	rest, ok := strings.CutPrefix(addr, "unix:")
	if !ok || strings.ContainsAny(rest, ";%") {
		return "", errors.New("unsupported DBUS_SESSION_BUS_ADDRESS")
	}
	var path string
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || (k != "path" && k != "guid") || (k == "path" && (path != "" || !filepath.IsAbs(v))) {
			return "", errors.New("unsupported DBUS_SESSION_BUS_ADDRESS")
		}
		if k == "path" {
			path = v
		}
	}
	if path == "" {
		return "", errors.New("unsupported DBUS_SESSION_BUS_ADDRESS")
	}
	return filepath.EvalSymlinks(path)
}

func subpath(parent, p string) bool {
	return p == parent || strings.HasPrefix(p, strings.TrimRight(parent, string(filepath.Separator))+string(filepath.Separator))
}

// pathCause drops the path from a *fs.PathError, keeping only its cause (rule 36).
func pathCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// realDir makes dir absolute and resolves its symlinks. A dir not created yet (a fresh install)
// resolves through its parent; a missing parent or a dangling symlink fails.
func realDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("not set")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); errors.Is(err, fs.ErrNotExist) {
		parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
		return filepath.Join(parent, filepath.Base(abs)), err
	}
	return filepath.EvalSymlinks(abs)
}

// checkPolicy enforces CheckPolicy's verdict on req (effective TTL, clean mode, sandbox) and asks
// a human through ApprovalFunc when the verdict requires approval. It returns the allowed_env of
// the rule it enforced and the sandbox-exec prefix (nil when the sandbox is off); e records
// whether the sandbox is on and why it denied.
func (rt *Runtime) checkPolicy(ctx context.Context, req *ExecRequest, e *AuditEntry) ([]string, []string, error) {
	d, env, sandbox := rt.decide(*req)
	if d.Allowed && d.ApprovalRequired {
		req.TTLSeconds, req.CleanEnv, req.Sandbox = d.TTLSeconds, d.CleanEnv, d.Sandbox
		e.Sandbox = d.Sandbox
		if err := rt.approve(ctx, *req, e); err != nil {
			return nil, nil, err
		}
		// A pause or rule change made while the request waited for a human still applies. Fed
		// the first verdict's TTL, clean mode, and sandbox, the second one can only tighten them.
		d, env, sandbox = rt.decide(*req)
	}
	if !d.Allowed {
		e.Outcome, e.BlockedBy = "blocked", d.BlockedBy
		return nil, nil, errors.New(d.Reason)
	}
	req.TTLSeconds, req.CleanEnv, req.Sandbox = d.TTLSeconds, d.CleanEnv, d.Sandbox
	e.Sandbox = d.Sandbox
	return env, sandbox, nil
}

// approve asks a human through ApprovalFunc. Only an allow returns nil; e records the outcome of
// anything else, and when a human answered. An answer that comes once the deadline passed or the
// caller left is neither an allow nor a deny: a channel can read one just as its context ends.
func (rt *Runtime) approve(ctx context.Context, req ExecRequest, e *AuditEntry) error {
	approveFn := rt.ApprovalFunc
	if approveFn == nil {
		approveFn = OSApproval
	}
	timeout := rt.ApprovalTimeout
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ok, err := approveFn(actx, req)
	if err == nil {
		err = actx.Err()
	}
	switch {
	case err == nil:
		e.DecidedAt = time.Now().UTC().Format(time.RFC3339)
		if ok {
			return nil
		}
		e.Outcome = "denied"
		return errors.New("policy denied: human-in-the-loop approval rejected (denied)")
	case ctx.Err() != nil:
		e.Outcome = "interrupted"
	case actx.Err() != nil:
		e.Outcome = "no_answer"
		return fmt.Errorf("policy denied: no answer within %s", timeout)
	default:
		e.Outcome = "failed" // every channel failed before anyone answered
	}
	return fmt.Errorf("policy denied: human-in-the-loop approval rejected (%v)", err)
}

// OsascriptPath is the AppleScript runner OSApproval calls, a var so tests can stub it.
var OsascriptPath = "/usr/bin/osascript"

// OSApproval asks in a macOS dialog. Deny (or Esc, or Return, since Deny is also the default
// button) is an answer, (false, nil); a dialog that could not be shown is an error, so
// FirstApproval keeps waiting for another channel.
func OSApproval(ctx context.Context, req ExecRequest) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, errors.New("interactive approval requires macOS osascript or custom ApprovalFunc")
	}
	// %q leaves only the \n, \" and \\ escapes AppleScript reads: ApprovalText quotes every field
	// an agent sets, so the text holds nothing unprintable but its own newlines.
	msg := ApprovalText("mintrun HITL Security Gate\n\nAllow AI agent to execute command?", req, 1000)
	script := fmt.Sprintf(`display dialog %q with title "mintrun Security Enclave" buttons {"Deny", "Allow"} default button "Deny" cancel button "Deny" with icon caution`, msg)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, OsascriptPath, "-e", script)
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ctx.Err() == nil && strings.Contains(stderr.String(), "(-128)") { // errAEUserCanceled: Deny, Esc, or Return
		return false, nil
	}
	return false, err
}

// ApprovalText is the request an approver shows a human. Every field an agent sets is quoted, so
// a newline or quote in an argument cannot fake a line or push the command out of view, and text
// longer than limit bytes is cut with a warning. The sandbox line comes before every such field,
// so none can push it out of view either.
func ApprovalText(header string, req ExecRequest, limit int) string {
	quote := func(list []string) string {
		q := make([]string, len(list))
		for i, s := range list {
			q[i] = strconv.Quote(s)
		}
		return strings.Join(q, " ")
	}
	params := make([]string, 0, len(req.Params))
	for k, v := range req.Params {
		params = append(params, strconv.Quote(k)+"="+strconv.Quote(v))
	}
	slices.Sort(params)
	// An empty Vault or WorkingDir shows what applies instead, unquoted, so no agent value can pass for it.
	orUnset := func(s, unset string) string {
		if s == "" {
			return unset
		}
		return strconv.Quote(s)
	}
	sandbox := "off"
	if req.Sandbox {
		sandbox = "on"
	}
	text := fmt.Sprintf("%s\n\nSandbox: %s\nProvider: %q\nVault: %s\nScope: %q\nPermissions: %s\nParams: %s\nCommand: %s\nWorking directory: %s",
		header, sandbox, req.Provider, orUnset(req.Vault, "(not set: the default vault)"), req.Scope, quote(req.Permissions),
		strings.Join(params, " "), quote(req.Command), orUnset(req.WorkingDir, "(not set: mintrun's own)"))
	if req.Purpose != "" {
		text += "\nPurpose: " + strconv.Quote(req.Purpose)
	}
	if req.Client != "" {
		text += "\nClient: " + strconv.Quote(req.Client)
	}
	if len(text) > limit {
		text = strings.ToValidUTF8(text[:limit], "") + "\n\n⚠️ TRUNCATED: the request is longer than this message. Deny unless you know the rest."
	}
	return text
}

// FirstApproval asks every approver at once. The first answer, allow or deny, wins and cancels
// the others; it returns once they have all returned, so none outlives the decision. An approver
// that fails (no GUI, not configured, unreachable) drops out, and only when every one fails is
// their joined error returned. The first answer wins even when ctx ended before it came;
// Runtime.approve, which owns the deadline, drops such an answer.
func FirstApproval(approvers ...func(context.Context, ExecRequest) (bool, error)) func(context.Context, ExecRequest) (bool, error) {
	return func(ctx context.Context, req ExecRequest) (bool, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type answer struct {
			i   int
			ok  bool
			err error
		}
		answers := make(chan answer, len(approvers))
		for i, approve := range approvers {
			go func() {
				ok, err := approve(ctx, req)
				answers <- answer{i, ok, err}
			}()
		}
		decided, allowed := false, false
		errs := make([]string, len(approvers)) // in approver order, whatever order they fail in
		for range approvers {
			switch a := <-answers; {
			case decided:
			case a.err == nil:
				decided, allowed = true, a.ok
				cancel()
			default:
				errs[a.i] = a.err.Error()
			}
		}
		if decided {
			return allowed, nil
		}
		return false, errors.New(strings.Join(errs, "; "))
	}
}

// ExecBlind resolves the master credential from Vault, mints a scoped JIT lease from the Provider,
// executes the target command with injected environment variables, scrubs all secrets from output,
// and immediately revokes the ephemeral lease before returning. Every call writes one audit entry.
func (rt *Runtime) ExecBlind(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	start := time.Now()
	req.Task = rand.Text()
	e := AuditEntry{
		Timestamp: start.UTC().Format(time.RFC3339), Task: req.Task, Via: req.Via, Client: req.Client,
		Provider: req.Provider, Scope: req.Scope, Permissions: req.Permissions, Command: req.Command, Purpose: req.Purpose,
	}
	write := func(exitCode int, errMsg string) {
		e.ExitCode, e.Error, e.DurationMs = exitCode, errMsg, time.Since(start).Milliseconds()
		rt.writeAudit(e)
	}
	failed := func(err error) (*ExecResult, error) {
		e.Outcome = "failed"
		write(1, err.Error())
		return nil, err
	}
	allowedEnv, sandbox, err := rt.checkPolicy(ctx, &req, &e)
	if err != nil {
		write(126, err.Error())
		return nil, err
	}

	vaultName := req.Vault
	if vaultName == "" {
		vaultName = rt.DefaultVault
	}
	vault, err := rt.Registry.Vault(vaultName)
	if err != nil {
		return failed(err)
	}
	provider, err := rt.Registry.Provider(req.Provider)
	if err != nil {
		return failed(err)
	}

	masterSecret, err := vault.GetSecret(ctx, req.Provider)
	if err != nil {
		// No hint here: only the vault can tell a miss from a failure, so a miss names its own fix.
		return failed(fmt.Errorf("vault %q could not load master secret for %q: %w", vaultName, req.Provider, err))
	}

	// From here on the entry is scrubbed of every secret known so far.
	lease, err := provider.Mint(ctx, masterSecret, req.MintRequest)
	secrets := leaseSecrets(masterSecret, lease)
	scrub := func(set []string) {
		e.Command, e.Client, e.Purpose = scrubAll(req.Command, set), Scrub(req.Client, set), Scrub(req.Purpose, set)
	}
	if err != nil {
		// Mint errors may echo the master secret (plugin stderr, API response bodies).
		// Return a scrubbed string, not %w: the raw error must never reach the caller.
		scrub(secrets)
		return failed(fmt.Errorf("provider %q mint failed: %s", req.Provider, Scrub(err.Error(), secrets)))
	}
	// A plugin may (wrongly) use a secret as lease.ID: report it scrubbed, and redact the raw ID everywhere else.
	leaseID := Scrub(lease.ID, secrets)
	redactSet := append(secrets, lease.ID)
	scrub(redactSet)
	e.LeaseID, e.Ephemeral = leaseID, lease.Ephemeral
	if lease.Ephemeral && !lease.ExpiresAt.IsZero() {
		e.ExpiresAt = lease.ExpiresAt.UTC().Format(time.RFC3339)
	}

	revoked := false
	defer func() {
		if lease != nil && lease.Ephemeral {
			revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := provider.Revoke(revokeCtx, masterSecret, lease); err == nil {
				revoked = true
			}
		}
	}()

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	if rt.Track != nil {
		trackCtx, untrack := context.WithCancel(context.WithoutCancel(ctx))
		defer untrack() // after the final write
		stopped := rt.Track(trackCtx, e)
		select {
		case <-stopped: // before the command starts, so Start fails
			stop(errStopped)
		default:
			go func() {
				select {
				case <-stopped:
					stop(errStopped)
				case <-trackCtx.Done():
				}
			}()
		}
	}

	timeout := 5 * time.Minute
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}
	execCtx, cancel := context.WithTimeout(runCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, req.Command[0], req.Command[1:]...)
	killProcessGroup(cmd) // a timeout or cancel kills the child's whole process group (audit L2)
	if sandbox != nil {
		// The sandbox runner execs the resolved command in place, so the pid, the process group,
		// and the exit code are the command's; a failed lookup (cmd.Err) still fails Start first.
		cmd.Args = append(append(sandbox, cmd.Path), req.Command[1:]...)
		cmd.Path = sandbox[0]
		if len(sandbox) > 3 && sandbox[1] == "-mintrun-linux-sandbox" {
			_ = os.MkdirAll(sandbox[3], 0o700)
			LinuxSandboxSysProcAttr(cmd)
		}
	}
	cmd.WaitDelay = PipeWaitDelay
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	// Build child environment (audit M1): clean-env (req.CleanEnv already folds in policy
	// clean_env/allowed_env via CheckPolicy) keeps only the base set plus the checked rule's
	// allowed_env names; otherwise the host env is inherited. Lease.Env always wins.
	cmd.Env = childEnv(req.CleanEnv, allowedEnv, lease.Env)

	stdoutBuf := &cappedBuffer{limit: MaxOutputBytes}
	stderrBuf := &cappedBuffer{limit: MaxOutputBytes}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	runErr := cmd.Run()
	exitCode := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(runErr, &exitErr):
		exitCode = exitErr.ExitCode()
	case runErr != nil && !errors.Is(runErr, exec.ErrWaitDelay): // ErrWaitDelay follows a clean exit
		exitCode = 1
	}
	switch {
	case exitCode == 0:
		e.Outcome = "done"
	case errors.Is(context.Cause(runCtx), errStopped):
		e.Outcome = "stopped"
	case ctx.Err() != nil: // a signal to mintrun, or the MCP server shutting down
		e.Outcome = "interrupted"
	case errors.Is(execCtx.Err(), context.DeadlineExceeded):
		e.Outcome = "timed_out"
	default:
		e.Outcome = "failed"
	}

	// Revoke before returning so we can report accurate revocation status.
	if lease.Ephemeral {
		revokeCtx, cancelRevoke := context.WithTimeout(context.Background(), 10*time.Second)
		if err := provider.Revoke(revokeCtx, masterSecret, lease); err == nil {
			revoked = true
			lease.Ephemeral = false // prevent duplicate revoke in defer
		}
		cancelRevoke()
	}

	stdout, outCut := stdoutBuf.scrubbed(redactSet)
	stderr, errCut := stderrBuf.scrubbed(redactSet)
	res := &ExecResult{
		ExitCode:   exitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		LeaseID:    leaseID,
		Ephemeral:  lease.Ephemeral || revoked,
		Revoked:    revoked,
		DurationMs: time.Since(start).Milliseconds(),
		Truncated:  outCut || errCut,
	}

	errMsg := ""
	if runErr != nil {
		errMsg = Scrub(runErr.Error(), redactSet)
	}
	e.Revoked, e.Truncated = revoked, res.Truncated
	write(exitCode, errMsg)
	return res, nil
}

// cleanEnvBase is the host environment a clean-env child keeps besides policy allowed_env names.
var cleanEnvBase = []string{"PATH", "HOME", "TMPDIR", "USER", "LANG", "TERM", "SSL_CERT_FILE"}

// childEnv returns the blind child's environment, sorted for determinism. The file-vault
// passphrase (MINTRUN_VAULT_KEY) never reaches the child, in any mode.
func childEnv(clean bool, allowed []string, leaseEnv map[string]string) []string {
	env := make(map[string]string)
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "MINTRUN_VAULT_KEY" {
			continue
		}
		if clean && !slices.Contains(cleanEnvBase, k) &&
			!slices.ContainsFunc(allowed, func(p string) bool { return matchPattern(p, k) }) {
			continue
		}
		env[k] = v
	}
	for k, v := range leaseEnv {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// Scrub replaces every non-trivial secret occurrence (including Base64, RawBase64, Hex,
// and URL-encoded representations) in text with RedactedPlaceholder.
func Scrub(text string, secrets []string) string {
	if text == "" {
		return ""
	}
	for _, s := range secrets {
		for _, v := range scrubVariants(s) {
			text = strings.ReplaceAll(text, v, RedactedPlaceholder)
		}
	}
	return text
}

// scrubVariants lists the forms of one secret that Scrub redacts. A secret shorter than 4
// characters after trimming is skipped, so every variant is at least 4 characters long.
func scrubVariants(secret string) []string {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < 4 {
		return nil
	}
	return []string{
		trimmed,
		base64.StdEncoding.EncodeToString([]byte(trimmed)),
		base64.RawStdEncoding.EncodeToString([]byte(trimmed)),
		hex.EncodeToString([]byte(trimmed)),
		url.QueryEscape(trimmed),
	}
}

// Limits on a blind command, as vars so tests can shrink them.
var (
	// MaxOutputBytes caps how much of each child stream ExecBlind keeps (audit L1).
	MaxOutputBytes = 4 << 20
	// PipeWaitDelay bounds the wait, after the command exits or is killed, for output pipes still
	// held by a process it left behind or that escaped the group kill (audit L2).
	PipeWaitDelay = 5 * time.Second
)

// cappedBuffer keeps the first limit bytes written to it and counts the rest. Write never fails,
// so the child is not killed by EPIPE for being chatty.
type cappedBuffer struct {
	buf     bytes.Buffer
	limit   int
	dropped int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := min(len(p), max(c.limit-c.buf.Len(), 0))
	c.buf.Write(p[:n])
	c.dropped += len(p) - n
	return len(p), nil
}

// scrubbed returns the kept output with secrets redacted, and whether the cap cut it. Scrub
// matches whole secrets only, so a cut stream first loses any tail that starts a secret variant.
// Trimming repeats until no tail starts one, because a trimmed tail can expose the start of
// another (or of a whole secret ending exactly at the cap). A marker reports the bytes cut.
func (c *cappedBuffer) scrubbed(secrets []string) (string, bool) {
	out := c.buf.String()
	if c.dropped == 0 {
		return Scrub(out, secrets), false
	}
	end := len(out)
	for trimmed := true; trimmed; {
		trimmed = false
		for _, s := range secrets {
			for _, v := range scrubVariants(s) {
				for k := min(len(v)-1, end); k > 0; k-- {
					if strings.HasSuffix(out[:end], v[:k]) {
						end, trimmed = end-k, true
						break
					}
				}
			}
		}
	}
	return Scrub(out[:end], secrets) + fmt.Sprintf("\n[MINTRUN:TRUNCATED %d bytes]\n", c.dropped+len(out)-end), true
}

// leaseSecrets lists every value that must never leave the enclave: the master secret plus
// the lease's env values, explicit Redact list, and RevokeSecret. lease may be nil.
func leaseSecrets(masterSecret string, lease *Lease) []string {
	secrets := []string{masterSecret}
	if lease == nil {
		return secrets
	}
	for _, v := range lease.Env {
		secrets = append(secrets, v)
	}
	secrets = append(secrets, lease.Redact...)
	return append(secrets, lease.RevokeSecret)
}

// scrubAll returns a scrubbed copy of args (e.g. argv for the audit log).
func scrubAll(args, secrets []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = Scrub(a, secrets)
	}
	return out
}

func (rt *Runtime) writeAudit(entry AuditEntry) {
	if rt.HomeDir == "" {
		return
	}
	_ = os.MkdirAll(rt.HomeDir, 0o700)
	f, err := os.OpenFile(filepath.Join(rt.HomeDir, "audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
}

// TailAudit streams an audit log line by line and calls fn, in log order, for each entry matching
// provider (case-insensitive) and failedOnly; unparseable lines are skipped. With limit > 0 only
// the last limit matches are kept and handed over at the end, so memory stays bounded however
// long the log grows.
// ponytail: reads the whole log each call (O(log) time); seek back from the end if it reaches GBs.
func TailAudit(r io.Reader, provider string, failedOnly bool, limit int, fn func(line string, e AuditEntry)) error {
	type match struct {
		line string
		e    AuditEntry
	}
	var last []match
	br := bufio.NewReader(r) // no line-length cap, unlike bufio.Scanner: an entry holds a full argv
	for {
		line, err := br.ReadString('\n')
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil &&
			(provider == "" || strings.EqualFold(e.Provider, provider)) &&
			(!failedOnly || e.ExitCode != 0 || e.Error != "") {
			line = strings.TrimRight(line, "\r\n")
			if limit <= 0 {
				fn(line, e)
			} else {
				if len(last) == limit {
					last = last[1:]
				}
				last = append(last, match{line, e})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	for _, m := range last {
		fn(m.line, m.e)
	}
	return nil
}
