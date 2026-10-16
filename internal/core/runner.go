package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
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

// AuditEntry is written to `~/.mintrun/audit.jsonl` for every mint/exec action.
// Secrets the runner holds are scrubbed; a policy-denied entry keeps the raw command (no secret
// is loaded yet to scrub against), so MCP mintrun_audit hands agents argv[0] only.
type AuditEntry struct {
	Timestamp   string   `json:"ts"`
	Provider    string   `json:"provider"`
	Scope       string   `json:"scope,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Command     []string `json:"command,omitempty"`
	LeaseID     string   `json:"lease_id,omitempty"`
	Ephemeral   bool     `json:"ephemeral"`
	Revoked     bool     `json:"revoked"`
	ExitCode    int      `json:"exit_code"`
	DurationMs  int64    `json:"duration_ms"`
	Truncated   bool     `json:"truncated,omitempty"`
	Error       string   `json:"error,omitempty"`
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
	Policies     map[string]PolicyRule
	ApprovalFunc func(ctx context.Context, req ExecRequest) (bool, error)
	policyErr    error // Non-nil if policy.json exists but failed to parse → every exec fails closed.
}

func NewRuntime(homeDir, defaultVault string, reg *Registry) *Runtime {
	if defaultVault == "" {
		defaultVault = "keychain"
	}
	rt := &Runtime{
		HomeDir:      homeDir,
		DefaultVault: defaultVault,
		Registry:     reg,
		Policies:     make(map[string]PolicyRule),
		ApprovalFunc: OSApproval,
	}
	rt.loadPolicyFile()
	return rt
}

func (rt *Runtime) PluginsDir() string {
	return filepath.Join(rt.HomeDir, "plugins")
}

func (rt *Runtime) loadPolicyFile() {
	p := filepath.Join(rt.HomeDir, "policy.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if err := json.Unmarshal(raw, &rt.Policies); err != nil {
		// Fail closed: a malformed policy must not silently degrade to allow-all.
		rt.Policies = make(map[string]PolicyRule)
		rt.policyErr = err
		fmt.Fprintf(os.Stderr, "mintrun: WARNING: policy.json is malformed (%v); denying all exec until fixed\n", err)
	}
}

// PolicyDecision is the static verdict of the exec gate for one ExecRequest (MCP mintrun_policy_check).
type PolicyDecision struct {
	Allowed          bool   `json:"allowed"`
	Reason           string `json:"reason,omitempty"`  // Denial reason: the exact error ExecBlind returns
	ApprovalRequired bool   `json:"approval_required"` // ExecBlind would ask a human (approve, require_approval, MINTRUN_APPROVE=1)
	TTLSeconds       int    `json:"ttl_seconds"`       // Lease TTL requested from the provider after max_ttl_seconds and the 600s default
	CleanEnv         bool   `json:"clean_env"`         // Child gets the clean env (request, policy clean_env, or allowed_env)
}

// CheckPolicy runs every static rule of the exec gate: request validation, the fail-closed
// policy.json load, the anti-exfiltration guard, and the provider's policy rule. It never opens
// a vault, mints, executes, or prompts a human. ExecBlind enforces this same verdict, so a dry
// run and a real exec cannot drift.
func (rt *Runtime) CheckPolicy(req ExecRequest) PolicyDecision {
	deny := func(format string, a ...any) PolicyDecision {
		return PolicyDecision{Reason: fmt.Sprintf(format, a...)}
	}
	if len(req.Command) == 0 {
		return deny("exec requires a non-empty command")
	}
	if req.Provider == "" {
		return deny("exec requires a provider name")
	}

	// Fail closed: a policy.json that exists but failed to parse denies everything.
	if rt.policyErr != nil {
		return deny("policy denied: policy.json failed to load (%v)", rt.policyErr)
	}

	// Built-in guardrail: block trivial secret-dumping shell commands in blind runner.
	if len(req.Command) > 0 {
		bin := filepath.Base(req.Command[0])
		joined := strings.ToLower(strings.Join(req.Command, " "))
		if bin == "env" || bin == "printenv" || bin == "export" ||
			strings.Contains(joined, "printenv") || strings.Contains(joined, "/proc/self/environ") {
			return deny("policy denied: command %q attempts to dump environment variables", req.Command[0])
		}
	}

	rule, hasRule := rt.Policies[req.Provider]

	// Non-JIT static mode (direct long-lived secret, no ephemeral token or revoke) must be
	// explicitly opted into via policy; an agent cannot silently downgrade by requesting it.
	if req.Params["mode"] == "static" || hasToken(req.Permissions, "static") {
		if !(hasRule && rule.AllowStatic) {
			return deny("policy denied: static (non-JIT) mode for provider %q requires \"allow_static\": true in policy.json", req.Provider)
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
				return deny("policy denied: scope %q is not in allowed_scopes for provider %q", req.Scope, req.Provider)
			}
		}
		if len(rule.AllowedPermissions) > 0 {
			// Fail closed: a request declaring no permissions is denied unless '*' is allowed.
			if len(req.Permissions) == 0 && !hasToken(rule.AllowedPermissions, "*") {
				return deny("policy denied: provider %q requires declared permissions within allowed_permissions", req.Provider)
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
					return deny("policy denied: permission %q is not in allowed_permissions for provider %q", perm, req.Provider)
				}
			}
		}
		// Fail closed and exact (no wildcards): params.installation_id picks the installation a
		// token is minted for. The gate never sees the master, so a request must name a listed ID
		// even when the master pins one.
		if inst := req.Params["installation_id"]; len(rule.AllowedInstallations) > 0 && !hasToken(rule.AllowedInstallations, inst) {
			return deny("policy denied: params.installation_id %q is not in allowed_installations for provider %q", inst, req.Provider)
		}
		if len(rule.BlockedCommands) > 0 && len(req.Command) > 0 {
			cmdLine := strings.ToLower(strings.Join(req.Command, " "))
			for _, blocked := range rule.BlockedCommands {
				if blocked != "" && strings.Contains(cmdLine, strings.ToLower(blocked)) {
					return deny("policy denied: command matches blocked pattern %q", blocked)
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

	return PolicyDecision{
		Allowed:          true,
		ApprovalRequired: req.Approve || (hasRule && rule.RequireApproval) || os.Getenv("MINTRUN_APPROVE") == "1",
		TTLSeconds:       req.TTLSeconds,
		CleanEnv:         req.CleanEnv || rule.CleanEnv || len(rule.AllowedEnv) > 0,
	}
}

// checkPolicy enforces CheckPolicy's verdict on req (effective TTL, clean mode) and asks a
// human through ApprovalFunc when the verdict requires approval.
func (rt *Runtime) checkPolicy(ctx context.Context, req *ExecRequest) error {
	d := rt.CheckPolicy(*req)
	if !d.Allowed {
		return errors.New(d.Reason)
	}
	req.TTLSeconds, req.CleanEnv = d.TTLSeconds, d.CleanEnv

	if d.ApprovalRequired {
		approveFn := rt.ApprovalFunc
		if approveFn == nil {
			approveFn = OSApproval
		}
		ok, err := approveFn(ctx, *req)
		if err != nil {
			return fmt.Errorf("policy denied: human-in-the-loop approval rejected (%v)", err)
		}
		if !ok {
			return errors.New("policy denied: human-in-the-loop approval rejected (denied)")
		}
	}
	return nil
}

// OsascriptPath is the AppleScript runner OSApproval calls, a var so tests can stub it.
var OsascriptPath = "/usr/bin/osascript"

// OSApproval asks in a macOS dialog. Deny (or Esc) is an answer, (false, nil); a dialog that
// could not be shown is an error, so FirstApproval keeps waiting for another channel.
func OSApproval(ctx context.Context, req ExecRequest) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, errors.New("interactive approval requires macOS osascript or custom ApprovalFunc")
	}
	// %q leaves only the \n, \" and \\ escapes AppleScript reads: ApprovalText quotes every field
	// an agent sets, so the text holds nothing unprintable but its own newlines.
	msg := ApprovalText("mintrun HITL Security Gate\n\nAllow AI agent to execute command?", req, 1000)
	script := fmt.Sprintf(`display dialog %q with title "mintrun Security Enclave" buttons {"Deny", "Allow"} default button "Allow" cancel button "Deny" with icon caution`, msg)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, OsascriptPath, "-e", script)
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ctx.Err() == nil && strings.Contains(stderr.String(), "(-128)") { // errAEUserCanceled: Deny or Esc
		return false, nil
	}
	return false, err
}

// ApprovalText is the request an approver shows a human. Every field an agent sets is quoted, so
// a newline or quote in an argument cannot fake a line or push the command out of view, and text
// longer than limit bytes is cut with a warning.
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
	text := fmt.Sprintf("%s\n\nProvider: %q\nScope: %q\nPermissions: %s\nParams: %s\nCommand: %s",
		header, req.Provider, req.Scope, quote(req.Permissions), strings.Join(params, " "), quote(req.Command))
	if len(text) > limit {
		text = strings.ToValidUTF8(text[:limit], "") + "\n\n⚠️ TRUNCATED: the request is longer than this message. Deny unless you know the rest."
	}
	return text
}

// FirstApproval asks every approver at once. The first answer, allow or deny, wins and cancels
// the others; it returns once they have all returned, so none outlives the decision. An approver
// that fails (no GUI, not configured, unreachable) drops out, and only when every one fails is
// their joined error returned.
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
// and immediately revokes the ephemeral lease before returning.
func (rt *Runtime) ExecBlind(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	start := time.Now()
	if err := rt.checkPolicy(ctx, &req); err != nil {
		rt.writeAudit(AuditEntry{
			Timestamp: start.UTC().Format(time.RFC3339),
			Provider:  req.Provider,
			Scope:     req.Scope,
			Command:   req.Command,
			ExitCode:  126,
			Error:     err.Error(),
		})
		return nil, err
	}

	vaultName := req.Vault
	if vaultName == "" {
		vaultName = rt.DefaultVault
	}
	vault, err := rt.Registry.Vault(vaultName)
	if err != nil {
		return nil, err
	}
	provider, err := rt.Registry.Provider(req.Provider)
	if err != nil {
		return nil, err
	}

	masterSecret, err := vault.GetSecret(ctx, req.Provider)
	if err != nil {
		return nil, fmt.Errorf("vault %q could not load master secret for %q: %w (run `mintrun secret set %s` first)", vaultName, req.Provider, err, req.Provider)
	}

	lease, err := provider.Mint(ctx, masterSecret, req.MintRequest)
	if err != nil {
		// Mint errors may echo the master secret (plugin stderr, API response bodies).
		// Return a scrubbed string, not %w: the raw error must never reach the caller.
		secrets := leaseSecrets(masterSecret, lease)
		errMsg := Scrub(err.Error(), secrets)
		rt.writeAudit(AuditEntry{
			Timestamp:   start.UTC().Format(time.RFC3339),
			Provider:    req.Provider,
			Scope:       req.Scope,
			Permissions: req.Permissions,
			Command:     scrubAll(req.Command, secrets),
			ExitCode:    1,
			DurationMs:  time.Since(start).Milliseconds(),
			Error:       errMsg,
		})
		return nil, fmt.Errorf("provider %q mint failed: %s", req.Provider, errMsg)
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

	timeout := 5 * time.Minute
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, req.Command[0], req.Command[1:]...)
	killProcessGroup(cmd) // a timeout or cancel kills the child's whole process group (audit L2)
	cmd.WaitDelay = PipeWaitDelay
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	// Build child environment (audit M1): clean-env (req.CleanEnv already folds in policy
	// clean_env/allowed_env via CheckPolicy) keeps only the base set plus policy allowed_env
	// names; otherwise the host env is inherited. Lease.Env always wins.
	cmd.Env = childEnv(req.CleanEnv, rt.Policies[req.Provider].AllowedEnv, lease.Env)

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

	// Revoke before returning so we can report accurate revocation status.
	if lease.Ephemeral {
		revokeCtx, cancelRevoke := context.WithTimeout(context.Background(), 10*time.Second)
		if err := provider.Revoke(revokeCtx, masterSecret, lease); err == nil {
			revoked = true
			lease.Ephemeral = false // prevent duplicate revoke in defer
		}
		cancelRevoke()
	}

	// A plugin may (wrongly) use a secret as lease.ID: report it scrubbed, and redact the raw ID everywhere else.
	secrets := leaseSecrets(masterSecret, lease)
	leaseID := Scrub(lease.ID, secrets)
	redactSet := append(secrets, lease.ID)

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
	rt.writeAudit(AuditEntry{
		Timestamp:   start.UTC().Format(time.RFC3339),
		Provider:    req.Provider,
		Scope:       req.Scope,
		Permissions: req.Permissions,
		Command:     scrubAll(req.Command, redactSet),
		LeaseID:     leaseID,
		Ephemeral:   res.Ephemeral,
		Revoked:     revoked,
		ExitCode:    exitCode,
		DurationMs:  res.DurationMs,
		Truncated:   res.Truncated,
		Error:       errMsg,
	})

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
