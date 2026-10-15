package core_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	rt := core.NewRuntime(home, "", reg) // test empty defaultVault fallback to "keychain"

	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{
			Provider:    "cloudflare",
			Scope:       "example.com",
			Permissions: []string{"dns:write", "workers:write"},
			TTLSeconds:  300,
		},
		WorkingDir: home,
		TimeoutSec: 10,
		Command:    []string{"sh", "-c", `echo "Deploying with token=$CLOUDFLARE_API_TOKEN"`},
	})
	if err != nil {
		t.Fatalf("ExecBlind failed: %v", err)
	}

	if strings.Contains(res.Stdout, mintedToken) || strings.Contains(res.Stdout, masterSecret) {
		t.Fatalf("SECURITY LEAK: output still contained secret: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, core.RedactedPlaceholder) {
		t.Fatalf("expected scrubbed placeholder in output, got: %q", res.Stdout)
	}
	if !res.Revoked || revokedCount.Load() != 1 {
		t.Fatalf("expected ephemeral token to be revoked once, got revoked=%v count=%d", res.Revoked, revokedCount.Load())
	}

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
	// Subdir in plugin source should be skipped gracefully.
	_ = os.MkdirAll(filepath.Join(pluginSrcDir, "subdir"), 0o700)

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

func TestBuiltinGitHubJITEncodingScrubAndHITLApproval(t *testing.T) {
	const ghAppSecret = "998877:gh_app_jwt_secret_token"
	const ghMintedToken = "ghs_ephemeral_jit_token_abcdef123"
	var ghRevoked atomic.Int32

	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/998877/access_tokens":
			if r.Header.Get("Authorization") != "Bearer gh_app_jwt_secret_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"token":"` + ghMintedToken + `","expires_at":"2026-10-15T12:00:00Z"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
			if r.Header.Get("Authorization") == "Bearer "+ghMintedToken {
				ghRevoked.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghServer.Close()

	home := t.TempDir()
	reg := core.NewRegistry()
	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	gh := &builtin.GitHubProvider{BaseURL: ghServer.URL, Client: ghServer.Client()}
	_ = reg.Register(vault)
	_ = reg.Register(gh)

	ctx := context.Background()
	if err := vault.SetSecret(ctx, "github", ghAppSecret); err != nil {
		t.Fatal(err)
	}

	rt := core.NewRuntime(home, "keychain", reg)

	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{
			Provider:    "github",
			Scope:       "ninja-c9/mintrun",
			Permissions: []string{"contents:write"},
		},
		Command: []string{"sh", "-c", `printf "b64=%s hex=%s" "$(printf '%s' "$GITHUB_TOKEN" | base64)" "$(printf '%s' "$GITHUB_TOKEN" | xxd -p | tr -d '\n')"`},
	})
	if err != nil {
		t.Fatalf("GitHub ExecBlind failed: %v", err)
	}
	if strings.Count(res.Stdout, core.RedactedPlaceholder) < 2 {
		t.Fatalf("expected both base64 and hex secret encodings to be redacted, got: %q", res.Stdout)
	}
	if !res.Revoked || ghRevoked.Load() != 1 {
		t.Fatalf("expected GitHub installation token to be revoked once, got revoked=%v count=%d", res.Revoked, ghRevoked.Load())
	}

	rt.ApprovalFunc = func(_ context.Context, _ core.ExecRequest) (bool, error) {
		return false, nil
	}
	_, err = rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "github", Scope: "ninja-c9/mintrun"},
		Command:     []string{"echo", "should-not-run"},
		Approve:     true,
	})
	if err == nil || !strings.Contains(err.Error(), "human-in-the-loop approval rejected") {
		t.Fatalf("expected HITL rejection error, got: %v", err)
	}
}

func TestGitHubLeaseIDIsOpaqueAndTokenNeverReachesAuditOrMCP(t *testing.T) {
	const ghAppSecret = "424242:gh_app_jwt_master_secret"
	const ghMintedToken = "ghs_installation_token_must_not_leak"
	var ghRevoked atomic.Int32

	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/424242/access_tokens":
			_, _ = w.Write([]byte(`{"token":"` + ghMintedToken + `"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token" && r.Header.Get("Authorization") == "Bearer "+ghMintedToken:
			ghRevoked.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ghServer.Close()

	home := t.TempDir()
	reg := core.NewRegistry()
	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	_ = reg.Register(vault)
	_ = reg.Register(&builtin.GitHubProvider{BaseURL: ghServer.URL, Client: ghServer.Client()})
	_ = reg.Register(builtin.NewMCPBridge())
	ctx := context.Background()
	if err := vault.SetSecret(ctx, "github", ghAppSecret); err != nil {
		t.Fatal(err)
	}
	rt := core.NewRuntime(home, "keychain", reg)
	bridge, err := reg.Bridge("mcp")
	if err != nil {
		t.Fatal(err)
	}

	mcpInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mintrun_exec","arguments":{"provider":"github","scope":"ninja-c9/mintrun","permissions":["contents:read"],"command":["echo","hi"]}}}` + "\n"
	var mcpOutput bytes.Buffer
	if err := bridge.Serve(ctx, rt, strings.NewReader(mcpInput), &mcpOutput); err != nil {
		t.Fatalf("MCP Serve failed: %v", err)
	}
	audit, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"MCP output": mcpOutput.String(), "audit.jsonl": string(audit)} {
		if strings.Contains(out, ghMintedToken) || strings.Contains(out, "gh_app_jwt_master_secret") {
			t.Fatalf("SECURITY LEAK: %s contains a secret: %s", name, out)
		}
		if !strings.Contains(out, "gh-inst-424242-") {
			t.Fatalf("expected opaque gh-inst lease handle in %s, got: %s", name, out)
		}
	}
	if ghRevoked.Load() != 1 {
		t.Fatalf("expected revoke using the real installation token, got count=%d", ghRevoked.Load())
	}
	if b, _ := json.Marshal(core.Lease{RevokeSecret: ghMintedToken}); strings.Contains(string(b), ghMintedToken) {
		t.Fatalf("Lease.RevokeSecret must never be serialized: %s", b)
	}
}

func TestMintFailureAndLeakyPluginLeaseAreScrubbed(t *testing.T) {
	const master = "leaky_master_secret_31337"
	const token = "leaky_jit_token_31337"
	// Scope "crash": dumps the RPC request (incl. master_secret) to stderr and exits 1.
	// Otherwise: wrongly uses the minted token as lease ID.
	script := `#!/bin/sh
read input
case "$input" in
  *'"scope":"crash"'*) printf '%s' "$input" >&2; exit 1 ;;
  *'"op":"mint"'*) echo '{"lease":{"id":"` + token + `","provider":"leaky","env":{"LEAKY_TOKEN":"` + token + `"}}}' ;;
  *) echo '{}' ;;
esac
`
	pluginSrc := t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginSrc, "plugin.json"), []byte(`{"name":"leaky","version":"0.1.0","kind":"provider","entrypoint":"run"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginSrc, "run"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	reg := core.NewRegistry()
	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	_ = reg.Register(vault)
	_ = reg.Register(builtin.NewMCPBridge())
	rt := core.NewRuntime(home, "keychain", reg)
	ctx := context.Background()
	if _, err := core.InstallPlugin(ctx, rt.PluginsDir(), pluginSrc); err != nil {
		t.Fatal(err)
	}
	if err := core.LoadExternalPlugins(rt.PluginsDir(), reg); err != nil {
		t.Fatal(err)
	}
	if err := vault.SetSecret(ctx, "leaky", master); err != nil {
		t.Fatal(err)
	}

	// Failed mint: returned error must be scrubbed, directly and via MCP.
	_, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "leaky", Scope: "crash"},
		Command:     []string{"echo", master},
	})
	if err == nil || strings.Contains(err.Error(), master) || !strings.Contains(err.Error(), core.RedactedPlaceholder) {
		t.Fatalf("expected scrubbed mint error, got: %v", err)
	}
	bridge, err := reg.Bridge("mcp")
	if err != nil {
		t.Fatal(err)
	}
	mcpInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mintrun_exec","arguments":{"provider":"leaky","scope":"crash","command":["echo","x"]}}}` + "\n"
	var mcpOutput bytes.Buffer
	if err := bridge.Serve(ctx, rt, strings.NewReader(mcpInput), &mcpOutput); err != nil {
		t.Fatal(err)
	}
	if out := mcpOutput.String(); strings.Contains(out, master) || !strings.Contains(out, "mint failed") {
		t.Fatalf("expected scrubbed mint failure in MCP output, got: %s", out)
	}

	// Successful mint whose lease ID is the token, with the master secret in argv.
	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "leaky"},
		Command:     []string{"echo", master},
	})
	if err != nil || res.LeaseID != core.RedactedPlaceholder || strings.Contains(res.Stdout, master) {
		t.Fatalf("expected scrubbed lease ID and stdout, got: %+v err=%v", res, err)
	}

	audit, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), master) || strings.Contains(string(audit), token) {
		t.Fatalf("SECURITY LEAK: audit.jsonl contains a secret:\n%s", audit)
	}
}

func TestPolicyFailClosedPhase45PRB(t *testing.T) {
	ctx := context.Background()
	newRT := func(t *testing.T, policyJSON string) (*core.Runtime, string) {
		home := t.TempDir()
		if policyJSON != "" {
			if err := os.WriteFile(filepath.Join(home, "policy.json"), []byte(policyJSON), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		reg := core.NewRegistry()
		_ = reg.Register(&builtin.KeychainVault{HomeDir: home, ForceFile: true})
		_ = reg.Register(builtin.NewCloudflareProvider())
		return core.NewRuntime(home, "keychain", reg), home
	}
	deny := func(t *testing.T, rt *core.Runtime, req core.ExecRequest, want string) {
		t.Helper()
		if _, err := rt.ExecBlind(ctx, req); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("expected denial containing %q, got %v", want, err)
		}
	}

	// H1: rule restricts scopes, so an empty scope must be denied (previously fail-open).
	rt, _ := newRT(t, `{"cloudflare":{"allowed_scopes":["allowed.com"]}}`)
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare"}, Command: []string{"echo"}}, "not in allowed_scopes")

	// H1/H2: rule restricts permissions, so declaring none is denied unless '*' is allowed.
	rt, _ = newRT(t, `{"cloudflare":{"allowed_permissions":["dns:read"]}}`)
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "x"}, Command: []string{"echo"}}, "requires declared permissions")

	// H2: explicit static mode is denied without allow_static, via params.mode and via "static" perm.
	rt, _ = newRT(t, "")
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare", Params: map[string]string{"mode": "static"}}, Command: []string{"echo"}}, "allow_static")
	rt, _ = newRT(t, `{"cloudflare":{}}`)
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare", Permissions: []string{"STATIC"}}, Command: []string{"echo"}}, "allow_static")

	// H3: a malformed policy.json makes every exec fail closed.
	rt, _ = newRT(t, `{ not valid json `)
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "x", Permissions: []string{"dns:read"}}, Command: []string{"echo"}}, "failed to load")

	// M8: blocked_commands match case-insensitively.
	rt, _ = newRT(t, `{"cloudflare":{"allowed_scopes":["*"],"blocked_commands":["RM -RF"]}}`)
	deny(t, rt, core.ExecRequest{MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "x", Permissions: []string{"dns:read"}}, Command: []string{"sh", "-c", "rm -rf /tmp/x"}}, "blocked pattern")

	// Positive: static mode runs once policy opts in; exit code flows through.
	rt, home := newRT(t, `{"cloudflare":{"allow_static":true}}`)
	if err := (&builtin.KeychainVault{HomeDir: home, ForceFile: true}).SetSecret(ctx, "cloudflare", "cf_static_tok_abcdef"); err != nil {
		t.Fatal(err)
	}
	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Permissions: []string{"static"}},
		Command:     []string{"sh", "-c", "exit 7"},
	})
	if err != nil || res.ExitCode != 7 {
		t.Fatalf("expected static mode allowed with exit 7, got res=%+v err=%v", res, err)
	}
}

type dummyPlugin struct{ m core.Manifest }

func (d dummyPlugin) Manifest() core.Manifest { return d.m }

func TestRegistryAndExternalVaultAndRemoteInstall(t *testing.T) {
	reg := core.NewRegistry()
	if err := reg.Register(dummyPlugin{core.Manifest{}}); err == nil {
		t.Fatal("expected missing name error")
	}
	if err := reg.Register(dummyPlugin{core.Manifest{Name: "bad", Kind: core.KindVault}}); err == nil {
		t.Fatal("expected unimplemented kind error")
	}
	if _, err := reg.Vault("missing"); err == nil {
		t.Fatal("expected missing vault error")
	}
	if _, err := reg.Provider("missing"); err == nil {
		t.Fatal("expected missing provider error")
	}
	if _, err := reg.Bridge("missing"); err == nil {
		t.Fatal("expected missing bridge error")
	}

	_ = reg.Register(builtin.NewKeychainVault(t.TempDir()))
	_ = reg.Register(builtin.NewOnePasswordVault())
	_ = reg.Register(builtin.NewCloudflareProvider())
	_ = reg.Register(builtin.NewGitHubProvider())
	_ = reg.Register(builtin.NewMCPBridge())
	if len(reg.Manifests()) != 5 {
		t.Fatalf("expected 5 manifests, got %d", len(reg.Manifests()))
	}

	// H5: an external (non-builtin) plugin must never shadow a built-in of the same name.
	if err := reg.Register(dummyPlugin{core.Manifest{Name: "keychain", Kind: core.KindVault}}); err == nil || !strings.Contains(err.Error(), "built-in vault") {
		t.Fatalf("expected built-in vault shadow rejection, got %v", err)
	}
	if err := reg.Register(dummyPlugin{core.Manifest{Name: "cloudflare", Kind: core.KindProvider}}); err == nil || !strings.Contains(err.Error(), "built-in provider") {
		t.Fatalf("expected built-in provider shadow rejection, got %v", err)
	}
	if err := reg.Register(dummyPlugin{core.Manifest{Name: "mcp", Kind: core.KindBridge}}); err == nil || !strings.Contains(err.Error(), "built-in bridge") {
		t.Fatalf("expected built-in bridge shadow rejection, got %v", err)
	}

	// Test remote plugin install + external vault RPC (get/set/delete) + error cases + RemovePlugin
	script := `#!/bin/sh
read input
case "$input" in
  *'"op":"set_secret"'*) echo '{}' ;;
  *'"op":"get_secret"'*) echo '{"value":"ext_vault_secret_123"}' ;;
  *'"op":"delete_secret"'*) echo '{}' ;;
  *'"op":"mint"'*)
    case "$input" in
      *'"scope":"nil"'*) echo '{}' ;;
      *'"scope":"badjson"'*) echo 'not-json' ;;
      *'"scope":"exit1"'*) echo 'boom' >&2; exit 1 ;;
      *) echo '{"error":"mint failed"}' ;;
    esac
    ;;
esac
`
	sum := sha256.Sum256([]byte(script))
	hashHex := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":   "extplugin",
				"kind":   "", // registers as both Vault and Provider
				"script": script,
				"sha256": hashHex,
			})
		case "/empty.json":
			_, _ = w.Write([]byte(`{"name":""}`))
		case "/badjson.json":
			_, _ = w.Write([]byte(`{invalid`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pluginsDir := filepath.Join(t.TempDir(), "plugins")
	ctx := context.Background()

	// LoadExternalPlugins on non-existent dir
	if err := core.LoadExternalPlugins(pluginsDir, reg); err != nil {
		t.Fatal(err)
	}

	// Remote install errors
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/404"); err == nil {
		t.Fatal("expected 404 error")
	}
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/empty.json"); err == nil {
		t.Fatal("expected missing script error")
	}
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/badjson.json"); err == nil {
		t.Fatal("expected bad json error")
	}
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/ok.json#sha256=deadbeef"); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
	if _, err := core.InstallPlugin(ctx, pluginsDir, filepath.Join(pluginsDir, "not-a-dir")); err == nil {
		t.Fatal("expected local dir error")
	}

	// Escape entrypoint check in local dir
	escapeDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(escapeDir, "plugin.json"), []byte(`{"name":"esc","entrypoint":"../escape"}`), 0o600)
	if _, err := core.InstallPlugin(ctx, pluginsDir, escapeDir); err == nil {
		t.Fatal("expected entrypoint escape error")
	}

	// Valid remote install over loopback http with a mandatory out-of-band digest (audit M6).
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/ok.json#sha256="+hashHex); err != nil {
		t.Fatalf("remote install failed: %v", err)
	}
	// Missing out-of-band digest must be rejected even when the bundle self-declares one (audit M6).
	if _, err := core.InstallPlugin(ctx, pluginsDir, srv.URL+"/ok.json"); err == nil {
		t.Fatal("expected missing-digest error")
	}
	// M6: a non-loopback plaintext URL is rejected even with a digest fragment.
	if _, err := core.InstallPlugin(ctx, pluginsDir, "http://example.com/p.json#sha256="+hashHex); err == nil {
		t.Fatal("expected https-required rejection for remote http")
	}
	// M6: a malformed http URL is rejected (isLoopbackURL parse-failure path).
	if _, err := core.InstallPlugin(ctx, pluginsDir, "http://[::1/p.json#sha256="+hashHex); err == nil {
		t.Fatal("expected rejection for malformed http URL")
	}
	// C1: a plugin whose manifest name escapes its directory is rejected on local install.
	travDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(travDir, "plugin.json"), []byte(`{"name":"../evil","kind":"provider"}`), 0o600)
	_ = os.WriteFile(filepath.Join(travDir, "run"), []byte("#!/bin/sh\necho '{}'\n"), 0o700)
	if _, err := core.InstallPlugin(ctx, pluginsDir, travDir); err == nil {
		t.Fatal("expected path-traversal name rejection on install")
	}
	// C1: RemovePlugin rejects traversal names too.
	if err := core.RemovePlugin(pluginsDir, "../../etc"); err == nil {
		t.Fatal("expected path-traversal name rejection on remove")
	}
	// Also test local plugin with empty entrypoint (defaults to "run")
	defaultEpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(defaultEpDir, "plugin.json"), []byte(`{"name":"defep","kind":"provider"}`), 0o600)
	_ = os.WriteFile(filepath.Join(defaultEpDir, "run"), []byte("#!/bin/sh\necho '{\"error\":\"fail\"}'\n"), 0o700)
	if _, err := core.InstallPlugin(ctx, pluginsDir, defaultEpDir); err != nil {
		t.Fatalf("default entrypoint install failed: %v", err)
	}

	// Add a stray file and invalid plugin dir to test LoadExternalPlugins resilience
	_ = os.WriteFile(filepath.Join(pluginsDir, "stray.txt"), []byte("hi"), 0o600)
	_ = os.MkdirAll(filepath.Join(pluginsDir, "broken"), 0o700)
	_ = os.WriteFile(filepath.Join(pluginsDir, "broken", "plugin.json"), []byte(`{bad`), 0o600)

	if err := core.LoadExternalPlugins(pluginsDir, reg); err != nil {
		t.Fatal(err)
	}

	extV, err := reg.Vault("extplugin")
	if err != nil {
		t.Fatal(err)
	}
	if err := extV.SetSecret(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if got, err := extV.GetSecret(ctx, "k"); err != nil || got != "ext_vault_secret_123" {
		t.Fatalf("unexpected GetSecret: %q %v", got, err)
	}
	if err := extV.DeleteSecret(ctx, "k"); err != nil {
		t.Fatal(err)
	}

	// Test ExternalPlugin.GetSecret error path via defep
	defP, err := reg.Provider("defep")
	if err != nil {
		t.Fatal(err)
	}
	if extDef, ok := defP.(*core.ExternalPlugin); ok {
		if _, err := extDef.GetSecret(ctx, "k"); err == nil {
			t.Fatal("expected GetSecret error from defep")
		}
	}

	extP, err := reg.Provider("extplugin")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range []string{"nil", "badjson", "exit1", "err"} {
		if _, err := extP.Mint(ctx, "sec", core.MintRequest{Scope: sc}); err == nil {
			t.Fatalf("expected error for scope %s", sc)
		}
	}

	// Test ExecBlind when provider.Mint fails (writes error audit entry)
	rt := core.NewRuntime(t.TempDir(), "extplugin", reg)
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "extplugin", Scope: "err"},
		Command:     []string{"echo", "hi"},
	}); err == nil || !strings.Contains(err.Error(), "mint failed") {
		t.Fatalf("expected ExecBlind provider mint failure, got %v", err)
	}

	if err := core.RemovePlugin(pluginsDir, "extplugin"); err != nil {
		t.Fatal(err)
	}
	if err := core.RemovePlugin(pluginsDir, "extplugin"); err == nil {
		t.Fatal("expected error removing non-existent plugin")
	}
}

func TestPolicyAndRunnerEdgeCases(t *testing.T) {
	home := t.TempDir()
	policyJSON := `{
  "cloudflare": {
    "allowed_scopes": ["allowed.com", "*.allowed.com", "prefix/*"],
    "allowed_permissions": ["dns:*", "static"],
    "blocked_commands": ["rm -rf"],
    "max_ttl_seconds": 120,
    "require_approval": false,
    "allow_static": true
  }
}`
	_ = os.WriteFile(filepath.Join(home, "policy.json"), []byte(policyJSON), 0o600)

	reg := core.NewRegistry()
	vault := &builtin.KeychainVault{HomeDir: home, ForceFile: true}
	cf := builtin.NewCloudflareProvider()
	_ = reg.Register(vault)
	_ = reg.Register(cf)

	rt := core.NewRuntime(home, "keychain", reg)
	ctx := context.Background()

	// Validation errors
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{}); err == nil {
		t.Fatal("expected empty command error")
	}
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{Command: []string{"echo"}}); err == nil {
		t.Fatal("expected empty provider error")
	}
	// Policy: disallowed scope
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "forbidden.com"},
		Command:     []string{"echo", "hi"},
	}); err == nil || !strings.Contains(err.Error(), "not in allowed_scopes") {
		t.Fatalf("expected scope policy denial, got %v", err)
	}
	// Policy: disallowed permission
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "sub.allowed.com", Permissions: []string{"workers:write"}},
		Command:     []string{"echo", "hi"},
	}); err == nil || !strings.Contains(err.Error(), "not in allowed_permissions") {
		t.Fatalf("expected permission policy denial, got %v", err)
	}
	// Policy: blocked command
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "prefix/zone1", Permissions: []string{"dns:read"}},
		Command:     []string{"sh", "-c", "rm -rf /tmp/x"},
	}); err == nil || !strings.Contains(err.Error(), "blocked pattern") {
		t.Fatalf("expected blocked command denial, got %v", err)
	}

	// Missing vault / missing provider / missing secret
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "allowed.com"},
		Vault:       "no_such_vault",
		Command:     []string{"echo"},
	}); err == nil {
		t.Fatal("expected missing vault error")
	}
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "no_such_provider"},
		Command:     []string{"echo"},
	}); err == nil {
		t.Fatal("expected missing provider error")
	}
	if _, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "allowed.com"},
		Command:     []string{"echo"},
	}); err == nil {
		t.Fatal("expected missing secret error")
	}

	_ = vault.SetSecret(ctx, "cloudflare", "cf_static_secret_12345")

	// Non-zero exit code & non-existent command binary
	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "allowed.com", Permissions: []string{"static"}},
		Command:     []string{"sh", "-c", "exit 42"},
	})
	if err != nil || res.ExitCode != 42 {
		t.Fatalf("expected exit code 42, got res=%+v err=%v", res, err)
	}
	res2, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "allowed.com", Permissions: []string{"static"}},
		Command:     []string{"/nonexistent_binary_xyz_999"},
	})
	if err != nil || res2.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code for bad binary, got res=%+v err=%v", res2, err)
	}

	// Test defaultOSApproval with already-canceled context so osascript never blocks or pops UI
	rt.ApprovalFunc = nil
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rt.ExecBlind(canceledCtx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare", Scope: "allowed.com", Permissions: []string{"static"}},
		Command:     []string{"echo"},
		Approve:     true,
	}); err == nil {
		t.Fatal("expected canceled approval error")
	}

	// Scrub edge cases & empty HomeDir audit
	if got := core.Scrub("", []string{"secret"}); got != "" {
		t.Fatalf("expected empty scrub, got %q", got)
	}
	if got := core.Scrub("abc", []string{"ab"}); got != "abc" {
		t.Fatalf("expected short secret ignored, got %q", got)
	}
	rtNoHome := core.NewRuntime("", "keychain", reg)
	rtNoHome.ApprovalFunc = func(context.Context, core.ExecRequest) (bool, error) { return false, errors.New("denied") }
	_, _ = rtNoHome.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cloudflare"},
		Command:     []string{"echo"},
		Approve:     true,
	})
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
