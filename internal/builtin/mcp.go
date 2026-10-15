package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"

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
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "mintrun_exec",
						"description": "Execute a CLI command (e.g. wrangler, curl, terraform, gh) inside a zero-knowledge JIT credential lease. The credential is automatically minted, injected into the subprocess environment, scrubbed from stdout/stderr, and revoked upon exit.",
						"inputSchema": map[string]any{
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
							},
							"required": []string{"provider", "command"},
						},
					},
					{
						"name":        "mintrun_plugins",
						"description": "List all installed mintrun plugins (vaults, JIT credential providers, and bridges) and their supported scopes.",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{},
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

	default:
		return rpcErr(id, -32602, fmt.Sprintf("unknown tool %q", toolName))
	}
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
