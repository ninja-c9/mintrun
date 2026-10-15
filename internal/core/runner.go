package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const RedactedPlaceholder = "[MINTRUN:REDACTED]"

// ExecRequest defines a blind command execution request.
type ExecRequest struct {
	MintRequest
	Vault      string   `json:"vault,omitempty"`   // Defaults to Runtime.DefaultVault
	Command    []string `json:"command"`           // e.g. ["wrangler", "deploy"]
	WorkingDir string   `json:"cwd,omitempty"`     // Optional working directory
	TimeoutSec int      `json:"timeout_seconds,omitempty"`
	Approve    bool     `json:"approve,omitempty"` // Require interactive human-in-the-loop approval
}

// ExecResult contains the scrubbed output of a blind command execution.
type ExecResult struct {
	ExitCode   int           `json:"exit_code"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	LeaseID    string        `json:"lease_id"`
	Ephemeral  bool          `json:"ephemeral"`
	Revoked    bool          `json:"revoked"`
	DurationMs int64         `json:"duration_ms"`
}

// AuditEntry is written to `~/.mintrun/audit.jsonl` for every mint/exec action.
// Never contains raw secret values.
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
	Error       string   `json:"error,omitempty"`
}

// PolicyRule controls which scopes and commands are permitted for a provider.
type PolicyRule struct {
	AllowedScopes   []string `json:"allowed_scopes,omitempty"`   // Empty = allow all scopes
	BlockedCommands []string `json:"blocked_commands,omitempty"` // Substrings or binary names to reject
	MaxTTLSeconds   int      `json:"max_ttl_seconds,omitempty"`  // Caps requested TTL
	RequireApproval bool     `json:"require_approval,omitempty"` // Prompt human via native OS dialog before minting
}

// Runtime coordinates Vaults, Providers, Bridges, Policy enforcement, Blind Execution, and Audit Logging.
type Runtime struct {
	HomeDir      string
	DefaultVault string
	Registry     *Registry
	Policies     map[string]PolicyRule
	ApprovalFunc func(ctx context.Context, req ExecRequest) (bool, error)
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
		ApprovalFunc: defaultOSApproval,
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
	_ = json.Unmarshal(raw, &rt.Policies)
}

func (rt *Runtime) checkPolicy(ctx context.Context, req *ExecRequest) error {
	// Built-in guardrail: block trivial secret-dumping shell commands in blind runner.
	if len(req.Command) > 0 {
		bin := filepath.Base(req.Command[0])
		joined := strings.ToLower(strings.Join(req.Command, " "))
		if bin == "env" || bin == "printenv" || bin == "export" ||
			strings.Contains(joined, "printenv") || strings.Contains(joined, "/proc/self/environ") {
			return fmt.Errorf("policy denied: command %q attempts to dump environment variables", req.Command[0])
		}
	}

	rule, hasRule := rt.Policies[req.Provider]
	if hasRule {
		if len(rule.AllowedScopes) > 0 && req.Scope != "" {
			allowed := false
			for _, s := range rule.AllowedScopes {
				if s == "*" || strings.EqualFold(s, req.Scope) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("policy denied: scope %q is not in allowed_scopes for provider %q", req.Scope, req.Provider)
			}
		}
		if len(rule.BlockedCommands) > 0 && len(req.Command) > 0 {
			cmdLine := strings.Join(req.Command, " ")
			for _, blocked := range rule.BlockedCommands {
				if blocked != "" && strings.Contains(cmdLine, blocked) {
					return fmt.Errorf("policy denied: command matches blocked pattern %q", blocked)
				}
			}
		}
		if rule.MaxTTLSeconds > 0 && (req.TTLSeconds <= 0 || req.TTLSeconds > rule.MaxTTLSeconds) {
			req.TTLSeconds = rule.MaxTTLSeconds
		}
	}

	if req.Approve || (hasRule && rule.RequireApproval) || os.Getenv("MINTRUN_APPROVE") == "1" {
		approveFn := rt.ApprovalFunc
		if approveFn == nil {
			approveFn = defaultOSApproval
		}
		ok, err := approveFn(ctx, *req)
		if err != nil || !ok {
			return fmt.Errorf("policy denied: human-in-the-loop approval rejected (%v)", err)
		}
	}
	return nil
}

func defaultOSApproval(ctx context.Context, req ExecRequest) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, errors.New("interactive approval requires macOS osascript or custom ApprovalFunc")
	}
	msg := fmt.Sprintf("mintrun HITL Security Gate\n\nAllow AI agent to execute command?\n• Provider: %s\n• Scope: %s\n• Command: %s",
		req.Provider, req.Scope, strings.Join(req.Command, " "))
	script := fmt.Sprintf(`display dialog %q with title "mintrun Security Enclave" buttons {"Deny", "Allow"} default button "Allow" cancel button "Deny" with icon caution`, msg)
	err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).Run()
	return err == nil, err
}

// ExecBlind resolves the master credential from Vault, mints a scoped JIT lease from the Provider,
// executes the target command with injected environment variables, scrubs all secrets from output,
// and immediately revokes the ephemeral lease before returning.
func (rt *Runtime) ExecBlind(ctx context.Context, req ExecRequest) (*ExecResult, error) {
	start := time.Now()
	if len(req.Command) == 0 {
		return nil, errors.New("exec requires a non-empty command")
	}
	if req.Provider == "" {
		return nil, errors.New("exec requires a provider name")
	}
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

	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 600
	}
	lease, err := provider.Mint(ctx, masterSecret, req.MintRequest)
	if err != nil {
		rt.writeAudit(AuditEntry{
			Timestamp:   start.UTC().Format(time.RFC3339),
			Provider:    req.Provider,
			Scope:       req.Scope,
			Permissions: req.Permissions,
			Command:     req.Command,
			ExitCode:    1,
			DurationMs:  time.Since(start).Milliseconds(),
			Error:       err.Error(),
		})
		return nil, fmt.Errorf("provider %q mint failed: %w", req.Provider, err)
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
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	// Build child environment: inherit OS env + inject leased credentials.
	envMap := make(map[string]string)
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			envMap[k] = v
		}
	}
	for k, v := range lease.Env {
		envMap[k] = v
	}
	cmd.Env = make([]string, 0, len(envMap))
	for k, v := range envMap {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
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

	// Build redaction set: master secret + all leased env values + explicit Redact list.
	redactSet := []string{masterSecret}
	for _, v := range lease.Env {
		redactSet = append(redactSet, v)
	}
	redactSet = append(redactSet, lease.Redact...)

	res := &ExecResult{
		ExitCode:   exitCode,
		Stdout:     Scrub(stdoutBuf.String(), redactSet),
		Stderr:     Scrub(stderrBuf.String(), redactSet),
		LeaseID:    lease.ID,
		Ephemeral:  lease.Ephemeral || revoked,
		Revoked:    revoked,
		DurationMs: time.Since(start).Milliseconds(),
	}

	errMsg := ""
	if runErr != nil && exitCode != 0 {
		errMsg = Scrub(runErr.Error(), redactSet)
	}
	rt.writeAudit(AuditEntry{
		Timestamp:   start.UTC().Format(time.RFC3339),
		Provider:    req.Provider,
		Scope:       req.Scope,
		Permissions: req.Permissions,
		Command:     req.Command,
		LeaseID:     lease.ID,
		Ephemeral:   res.Ephemeral,
		Revoked:     revoked,
		ExitCode:    exitCode,
		DurationMs:  res.DurationMs,
		Error:       errMsg,
	})

	return res, nil
}

// Scrub replaces every non-trivial secret occurrence (including Base64, RawBase64, Hex,
// and URL-encoded representations) in text with RedactedPlaceholder.
func Scrub(text string, secrets []string) string {
	if text == "" {
		return ""
	}
	out := text
	for _, s := range secrets {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) < 4 {
			continue
		}
		variants := []string{
			trimmed,
			base64.StdEncoding.EncodeToString([]byte(trimmed)),
			base64.RawStdEncoding.EncodeToString([]byte(trimmed)),
			hex.EncodeToString([]byte(trimmed)),
			url.QueryEscape(trimmed),
		}
		for _, v := range variants {
			if len(v) >= 4 {
				out = strings.ReplaceAll(out, v, RedactedPlaceholder)
			}
		}
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
