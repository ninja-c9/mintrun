package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ninja-c9/mintrun/internal/core"
)

// MCPBridge exposes mintrun's Blind Runner and Plugin Registry as an MCP (Model Context Protocol)
// JSON-RPC 2.0 server over stdio so AI agents (Antigravity, Claude Code, Cursor) can execute
// authenticated CLI commands without ever seeing or holding raw credentials.
type MCPBridge struct{}

func NewMCPBridge() *MCPBridge { return &MCPBridge{} }

func (m *MCPBridge) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "mcp",
		Version:     "0.1.0",
		Kind:        core.KindBridge,
		Description: "Model Context Protocol (MCP) JSON-RPC 2.0 stdio bridge for AI agents",
		Builtin:     true,
	}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (m *MCPBridge) Serve(ctx context.Context, rt *core.Runtime, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)
	// The AI app's name from initialize. It is self-reported, so it labels the audit log and the
	// approval text but is never identity. It lives here, not on the bridge, because one
	// MCPBridge serves every Serve call.
	var client string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		// Notifications (no ID) do not expect a response.
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}
		if req.Method == "initialize" {
			client = clientName(req.Params)
		}
		resp := m.handleRequest(ctx, rt, req, client)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// clientName returns the shortLabel of initialize's params.clientInfo.name, or "" when the params
// hold no name.
func clientName(params json.RawMessage) string {
	var p struct {
		ClientInfo struct {
			Name string `json:"name"`
		} `json:"clientInfo"`
	}
	_ = json.Unmarshal(params, &p)
	return shortLabel(p.ClientInfo.Name)
}

// shortLabel keeps only [A-Za-z0-9._ ()-] of s, then cuts it to 64 bytes.
func shortLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._ ()-", r) {
			return r
		}
		return -1
	}, s)
	return s[:min(len(s), 64)] // every kept character is one byte
}

func (m *MCPBridge) handleRequest(ctx context.Context, rt *core.Runtime, req jsonRPCRequest, client string) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"serverInfo": map[string]any{
					"name":    "mintrun",
					"version": "0.1.0",
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			},
		}

	case "tools/list":
		execSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{
					"type":        "string",
					"description": "Provider plugin name (e.g. 'cloudflare', 'github')",
				},
				"scope": map[string]any{
					"type":        "string",
					"description": "Target scope such as domain/zone name (e.g. 'example.com') or repository",
				},
				"permissions": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Scoped permissions to mint (e.g. ['dns:write', 'workers:write'])",
				},
				"command": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "Command and arguments array (e.g. ['wrangler', 'deploy'])",
				},
				"cwd": map[string]any{
					"type":        "string",
					"description": "Optional working directory path",
				},
				"ttl_seconds": map[string]any{
					"type":        "integer",
					"description": "Lease TTL in seconds (default: 600)",
				},
				"clean_env": map[string]any{
					"type":        "boolean",
					"description": "Run the command with a minimal environment (PATH, HOME, ... plus policy allowed_env and the lease credentials) instead of inheriting the host environment",
				},
				"sandbox": map[string]any{
					"type":        "boolean",
					"description": "Run the command in a macOS sandbox that cannot read mintrun's home or the Keychain (denied on other hosts). It only adds the sandbox: policy sandbox applies whatever this says",
				},
				"approve": map[string]any{
					"type":        "boolean",
					"description": "Ask a human to allow this request before anything is minted (the macOS dialog, plus Telegram or Slack when set up). It only adds a check: a denial, or no channel to ask on, fails the call",
				},
				"params": map[string]any{
					"type":                 "object",
					"additionalProperties": map[string]any{"type": "string"},
					"description":          "Provider parameters, e.g. {\"installation_id\": \"12345678\"} to pick a github App installation; a credential that pins an installation refuses any other, and policy allowed_installations, when set, must list it",
				},
				"purpose": map[string]any{
					"type":        "string",
					"description": "Why you are running this command, in plain words for the human who approves it: one line, at most 300 bytes",
				},
			},
			"required": []string{"provider", "command"},
		}
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "mintrun_exec",
						"description": "Execute a CLI command (e.g. wrangler, curl, terraform, gh) inside a zero-knowledge JIT credential lease. The credential is automatically minted, injected into the subprocess environment, scrubbed from stdout/stderr, and revoked upon exit where the provider allows it (AWS STS and GCP credentials can only expire; the result's revoked field reports which). Each output stream is capped at 4 MiB; truncated=true marks a cut. The command is killed after 5 minutes.",
						"inputSchema": execSchema,
					},
					{
						"name":        "mintrun_plugins",
						"description": "List all installed mintrun plugins (vaults, JIT credential providers, and bridges) and their supported scopes.",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{},
						},
					},
					{
						"name":        "mintrun_policy_check",
						"description": "Dry-run a mintrun_exec request (same arguments) against policy.json and the anti-exfiltration guard, using the exact gate mintrun_exec enforces. Never opens the vault, mints, runs the command, or asks a human. Returns allowed, the denial reason, approval_required, ttl_seconds (the lease TTL requested from the provider; gcp tokens always live up to 1h), clean_env, and sandbox. Policy verdict only: an allowed exec can still fail on an unknown provider, a missing vault secret, or a mint error.",
						"inputSchema": execSchema,
					},
					{
						"name":        "mintrun_audit",
						"description": "Return recent entries of the mintrun_exec audit log, oldest first. Text an agent wrote is left out or cut down, since a secret typed into argv is not one the runner can scrub and each request is logged as the agent sent it: scope, permissions, and purpose are left out, an error shows as [MINTRUN:REDACTED] (outcome and blocked_by give the verdict), each command is cut to its binary name, and provider, binary, and client names keep only letters, digits, and ._ ()- up to 64 bytes.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"provider": map[string]any{
									"type":        "string",
									"description": "Only entries for this provider (case-insensitive)",
								},
								"failed_only": map[string]any{
									"type":        "boolean",
									"description": "Only entries with a non-zero exit code or an error",
								},
								"limit": map[string]any{
									"type":        "integer",
									"description": "Return the last N matching entries (default 20, max 100)",
								},
							},
						},
					},
				},
			},
		}

	case "tools/call":
		var callParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return rpcErr(req.ID, -32602, "invalid tool call params")
		}
		return m.handleToolCall(ctx, rt, req.ID, callParams.Name, callParams.Arguments, client)

	default:
		return rpcErr(req.ID, -32601, fmt.Sprintf("method %q not found", req.Method))
	}
}

func (m *MCPBridge) handleToolCall(ctx context.Context, rt *core.Runtime, id json.RawMessage, toolName string, rawArgs json.RawMessage, client string) jsonRPCResponse {
	switch toolName {
	case "mintrun_plugins":
		manifests := rt.Registry.Manifests()
		b, _ := json.MarshalIndent(manifests, "", "  ")
		return toolTextResult(id, string(b), false)

	case "mintrun_exec":
		var execReq core.ExecRequest
		if err := json.Unmarshal(rawArgs, &execReq); err != nil {
			return toolTextResult(id, fmt.Sprintf("invalid arguments: %v", err), true)
		}
		// Client and Via are json:"-", so a "client" in the arguments never reaches the request.
		execReq.Client, execReq.Via = client, "mcp"
		execReq.FromAgent = true // after decoding: no argument can set or clear it
		res, err := rt.ExecBlind(ctx, execReq)
		if err != nil {
			return toolTextResult(id, fmt.Sprintf("mintrun execution error: %v", err), true)
		}
		outBytes, _ := json.MarshalIndent(res, "", "  ")
		return toolTextResult(id, string(outBytes), res.ExitCode != 0)

	case "mintrun_policy_check":
		var execReq core.ExecRequest
		if err := json.Unmarshal(rawArgs, &execReq); err != nil {
			return toolTextResult(id, fmt.Sprintf("invalid arguments: %v", err), true)
		}
		execReq.FromAgent = true // after decoding: no argument can set or clear it
		b, _ := json.MarshalIndent(rt.CheckPolicy(execReq), "", "  ")
		return toolTextResult(id, string(b), false)

	case "mintrun_audit":
		var args struct {
			Provider   string `json:"provider"`
			FailedOnly bool   `json:"failed_only"`
			Limit      int    `json:"limit"`
		}
		if len(rawArgs) > 0 {
			if err := json.Unmarshal(rawArgs, &args); err != nil {
				return toolTextResult(id, fmt.Sprintf("invalid arguments: %v", err), true)
			}
		}
		entries, err := readAudit(rt.HomeDir, args.Provider, args.FailedOnly, args.Limit)
		if err != nil {
			return toolTextResult(id, err.Error(), true)
		}
		b, _ := json.MarshalIndent(entries, "", "  ")
		return toolTextResult(id, string(b), false)

	default:
		return rpcErr(id, -32602, fmt.Sprintf("unknown tool %q", toolName))
	}
}

// readAudit returns the last limit (default 20, max 100) entries of audit.jsonl matching provider
// (case-insensitive) and failedOnly, filtered like `mintrun audit`. An entry keeps the request as
// the agent sent it: one written before the master loads has no secret to scrub against, a
// secret a human typed into argv is one the runner never holds, and a policy that allows `*`, or
// has no rule for the provider, lets any scope and permission through. So that one agent cannot
// pass free text to another, every entry's scope, permissions, and purpose are blanked, its error
// becomes [MINTRUN:REDACTED] (outcome and blocked_by keep the verdict), its arguments become
// [MINTRUN:REDACTED], and its provider and argv[0]'s base name are cut to a shortLabel, like the
// client. The on-disk log keeps all of it for the operator.
func readAudit(home, provider string, failedOnly bool, limit int) ([]core.AuditEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	f, err := os.Open(filepath.Join(home, "audit.jsonl"))
	if os.IsNotExist(err) {
		return []core.AuditEntry{}, nil
	}
	if err != nil {
		return nil, auditReadError(err)
	}
	defer f.Close()
	entries := []core.AuditEntry{}
	err = core.TailAudit(f, provider, failedOnly, min(limit, 100), func(_ string, e core.AuditEntry) {
		if len(e.Command) > 1 {
			e.Command = []string{e.Command[0], core.RedactedPlaceholder}
		}
		if len(e.Command) > 0 {
			e.Command[0] = shortLabel(filepath.Base(e.Command[0]))
		}
		e.Provider = shortLabel(e.Provider)
		e.Scope, e.Permissions, e.Purpose = "", nil, ""
		if e.Error != "" {
			e.Error = core.RedactedPlaceholder
		}
		entries = append(entries, e)
	})
	if err != nil {
		return nil, auditReadError(err)
	}
	return entries, nil
}

// auditReadError keeps only the cause of a *fs.PathError, whose path names the home: the text
// reaches the agent (rule 36).
func auditReadError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("read audit log: %v", err)
}

func toolTextResult(id json.RawMessage, text string, isError bool) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"isError": isError,
			"content": []map[string]any{
				{
					"type": "text",
					"text": text,
				},
			},
		},
	}
}

func rpcErr(id json.RawMessage, code int, msg string) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: msg},
	}
}
