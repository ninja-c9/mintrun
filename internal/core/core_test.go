package core_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

func TestCloudflareJITMintBlindExecAndAutoRevoke(t *testing.T) {
	const masterSecret = "cf_master_secret_super_sensitive_999"
	const mintedToken = "cf_jit_ephemeral_subtoken_123456"
	var revokedCount atomic.Int32

	// Mock Cloudflare API server verifying Zone resolution, Permission Groups, JIT Mint, and Auto-Revoke.
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+masterSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/user/tokens/permission_groups":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"82e64a83756745bbbb1c9c2701bf816b","name":"DNS Write"},{"id":"f7f0eda5697f475c90846e879bab8666","name":"Workers Scripts Write"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/user/tokens":
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"lease_tok_001","value":"` + mintedToken + `"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/user/tokens/lease_tok_001":
			revokedCount.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"lease_tok_001"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfServer.Close()

	home := t.TempDir()
	reg := core.NewRegistry()

	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	cf := &builtin.CloudflareProvider{BaseURL: cfServer.URL, Client: cfServer.Client()}
	mcp := builtin.NewMCPBridge()

	if err := reg.Register(vault); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(cf); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(mcp); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := vault.SetSecret(ctx, "cloudflare", masterSecret); err != nil {
		t.Fatal(err)
	}

	rt := core.NewRuntime(home, "keychain", reg)

	// 1. Run a child command that uses $CLOUDFLARE_API_TOKEN and tries to leak it to stdout.
	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{
			Provider:    "cloudflare",
			Scope:       "example.com",
			Permissions: []string{"dns:write", "workers:write"},
			TTLSeconds:  300,
		},
		Command: []string{"sh", "-c", `echo "Deploying with token=$CLOUDFLARE_API_TOKEN"`},
	})
	if err != nil {
		t.Fatalf("ExecBlind failed: %v", err)
	}

	// Verify secret was injected into child process AND scrubbed from output!
	if strings.Contains(res.Stdout, mintedToken) || strings.Contains(res.Stdout, masterSecret) {
		t.Fatalf("SECURITY LEAK: output still contained secret: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, core.RedactedPlaceholder) {
		t.Fatalf("expected scrubbed placeholder in output, got: %q", res.Stdout)
	}
	// Verify ephemeral token was automatically revoked immediately after execution.
	if !res.Revoked || revokedCount.Load() != 1 {
		t.Fatalf("expected ephemeral token to be revoked once, got revoked=%v count=%d", res.Revoked, revokedCount.Load())
	}

	// 2. Verify policy blocks direct `printenv` exfiltration attempts.
	_, err = rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare"},
		Command:     []string{"printenv"},
	})
	if err == nil || !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("expected policy denial on printenv, got: %v", err)
	}
}

func TestExternalPluginInstallAndExecution(t *testing.T) {
	home := t.TempDir()
	pluginSrcDir := t.TempDir()

	// Create an external provider plugin (e.g. GitHub App token minter) using JSON-over-stdio protocol.
	manifest := `{
  "name": "github",
  "version": "0.1.0",
  "kind": "provider",
  "description": "External GitHub JIT Token Provider Plugin",
  "entrypoint": "run",
  "scopes": ["repo:read", "contents:write"]
}`
	script := `#!/bin/sh
read input
case "$input" in
  *'"op":"mint"'*)
    echo '{"lease":{"id":"gh-lease-1","provider":"github","env":{"GITHUB_TOKEN":"ghs_ephemeral_secret_777"},"redact":["ghs_ephemeral_secret_777"],"ephemeral":true}}'
    ;;
  *'"op":"revoke"'*)
    echo '{}'
    ;;
  *)
    echo '{"error":"unsupported op"}'
    ;;
esac
`
	if err := os.WriteFile(filepath.Join(pluginSrcDir, "plugin.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginSrcDir, "run"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	reg := core.NewRegistry()
	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	_ = reg.Register(vault)
	_ = reg.Register(builtin.NewMCPBridge())
	rt := core.NewRuntime(home, "keychain", reg)

	ctx := context.Background()
	installed, err := core.InstallPlugin(ctx, rt.PluginsDir(), pluginSrcDir)
	if err != nil {
		t.Fatalf("InstallPlugin failed: %v", err)
	}
	if installed.Name != "github" {
		t.Fatalf("unexpected plugin name: %s", installed.Name)
	}

	if err := core.LoadExternalPlugins(rt.PluginsDir(), reg); err != nil {
		t.Fatalf("LoadExternalPlugins failed: %v", err)
	}
	if err := vault.SetSecret(ctx, "github", "gh_master_app_key_888"); err != nil {
		t.Fatal(err)
	}

	// Test calling external plugin via MCP Bridge JSON-RPC 2.0 stdio!
	mcpBridge, err := reg.Bridge("mcp")
	if err != nil {
		t.Fatal(err)
	}
	mcpInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mintrun_exec","arguments":{"provider":"github","scope":"ninja-c9/mintrun","command":["sh","-c","echo token=$GITHUB_TOKEN"]}}}` + "\n"
	var mcpOutput bytes.Buffer
	if err := mcpBridge.Serve(ctx, rt, strings.NewReader(mcpInput), &mcpOutput); err != nil {
		t.Fatalf("MCP Serve failed: %v", err)
	}

	outStr := mcpOutput.String()
	if strings.Contains(outStr, "ghs_ephemeral_secret_777") || strings.Contains(outStr, "gh_master_app_key_888") {
		t.Fatalf("MCP output leaked secret: %s", outStr)
	}
	if !strings.Contains(outStr, core.RedactedPlaceholder) {
		t.Fatalf("expected redacted placeholder in MCP output, got: %s", outStr)
	}

	var rpcResp struct {
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(mcpOutput.Bytes(), &rpcResp); err != nil {
		t.Fatalf("invalid MCP JSON response: %v", err)
	}
	if rpcResp.Result.IsError {
		t.Fatalf("expected MCP tool call success, got error: %s", outStr)
	}
}
