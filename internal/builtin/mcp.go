package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		resp := m.handleRequest(ctx, rt, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (m *MCPBridge) handleRequest(ctx context.Context, rt *core.Runtime, req jsonRPCRequest) jsonRPCResponse {
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
						"description": "Execute a CLI command (e.g. wrangler, curl, terraform, gh) inside a zero-knowledge JIT credential lease. The credential is automatically minted, injected into the subprocess environment, scrubbed from stdout/stderr, and revoked upon exit where the provider allows it (AWS STS and GCP credentials can only expire; the result's revoked field reports which). Each output stream is capped at 4 MiB; truncated=true marks a cut.",
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
						"description": "Dry-run a mintrun_exec request (same arguments) against policy.json and the anti-exfiltration guard, using the exact gate mintrun_exec enforces. Never opens the vault, mints, runs the command, or asks a human. Returns allowed, the denial reason, approval_required, ttl_seconds (the lease TTL requested from the provider; gcp tokens always live up to 1h), and clean_env. Policy verdict only: an allowed exec can still fail on an unknown provider, a missing vault secret, or a mint error.",
						"inputSchema": execSchema,
					},
					{
						"name":        "mintrun_audit",
						"description": "Return recent entries of the mintrun_exec audit log, oldest first. Each command is cut to its binary name: arguments are never shown, because a secret typed into argv is not one the runner can scrub.",
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
		return m.handleToolCall(ctx, rt, req.ID, callParams.Name, callParams.Arguments)

	default:
		return rpcErr(req.ID, -32601, fmt.Sprintf("method %q not found", req.Method))
	}
}

func (m *MCPBridge) handleToolCall(ctx context.Context, rt *core.Runtime, id json.RawMessage, toolName string, rawArgs json.RawMessage) jsonRPCResponse {
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
// (case-insensitive) and failedOnly, filtered like `mintrun audit`. Every command is cut to
// argv[0]: policy-denied entries keep the raw argv (no secret is loaded yet to scrub against),
// and a secret a human typed into argv is one the runner never holds, so arguments never reach
// an agent. The on-disk log keeps the full argv for the operator.
// ponytail: reads the whole log per call; seek from the end if audit.jsonl grows large.
func readAudit(home, provider string, failedOnly bool, limit int) ([]core.AuditEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, 100)
	raw, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if os.IsNotExist(err) {
		return []core.AuditEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read audit log: %v", err)
	}
	entries := []core.AuditEntry{}
	for _, line := range strings.Split(string(raw), "\n") {
		var e core.AuditEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if provider != "" && !strings.EqualFold(e.Provider, provider) {
			continue
		}
		if failedOnly && e.ExitCode == 0 && e.Error == "" {
			continue
		}
		if len(e.Command) > 1 {
			e.Command = []string{e.Command[0], core.RedactedPlaceholder}
		}
		entries = append(entries, e)
	}
	return entries[max(0, len(entries)-limit):], nil
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
