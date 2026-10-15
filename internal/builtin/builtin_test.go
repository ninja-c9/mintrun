package builtin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ninja-c9/mintrun/internal/core"
)

func TestCloudflareProviderComprehensive(t *testing.T) {
	cf := NewCloudflareProvider()
	if cf.Manifest().Name != "cloudflare" {
		t.Fatalf("unexpected manifest: %+v", cf.Manifest())
	}

	ctx := context.Background()
	if _, err := cf.Mint(ctx, "", core.MintRequest{}); err == nil {
		t.Fatal("expected error on empty master secret")
	}

	// Static mode
	lease, err := cf.Mint(ctx, "cf_static_tok_123", core.MintRequest{
		Scope:       "example.com",
		Permissions: []string{"static"},
	})
	if err != nil || lease.Ephemeral || lease.Env["CF_API_TOKEN"] != "cf_static_tok_123" {
		t.Fatalf("unexpected static lease: %+v err=%v", lease, err)
	}
	if err := cf.Revoke(ctx, "cf_static_tok_123", lease); err != nil {
		t.Fatalf("static revoke should be no-op, got %v", err)
	}

	// Mock server for dynamic flows
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones" && r.URL.Query().Get("name") == "notfound.com":
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		case r.URL.Path == "/zones" && r.URL.Query().Get("name") == "http500.com":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`server error`))
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com"}]}`))
		case r.URL.Path == "/user/tokens/permission_groups":
			if r.Header.Get("Authorization") == "Bearer perm_500" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"82e64a83756745bbbb1c9c2701bf816b","name":"DNS Write"},{"id":"aaaabbbbccccddddeeeeffff00001111","name":"Zone Read"},{"id":"11112222333344445555666677778888","name":"Custom Thing Read"}]}`))
		case r.URL.Path == "/user/tokens" && r.Method == http.MethodPost:
			switch r.Header.Get("Authorization") {
			case "Bearer reject_tok":
				_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"rejected"}]}`))
			case "Bearer post_500":
				w.WriteHeader(http.StatusInternalServerError)
			case "Bearer bad_json":
				_, _ = w.Write([]byte(`{invalid-json`))
			default:
				_, _ = w.Write([]byte(`{"success":true,"result":{"id":"tok_id_1","value":"sub_tok_val_1"}}`))
			}
		case strings.HasPrefix(r.URL.Path, "/user/tokens/") && r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{"success":true}`))
		}
	}))
	defer srv.Close()
	cf.BaseURL = srv.URL
	cf.Client = srv.Client()

	// Direct 32-hex zone ID and direct 32-hex permission group ID (zero extra lookups)
	hexZone := "023e105f4ecef8ad9ca31a8372d0c353"
	hexPerm := "82e64a83756745bbbb1c9c2701bf816b"
	l2, err := cf.Mint(ctx, "master_ok", core.MintRequest{
		Scope:       "zone:" + hexZone,
		Permissions: []string{hexPerm},
	})
	if err != nil || !l2.Ephemeral || l2.ID != "tok_id_1" {
		t.Fatalf("hex mint failed: %+v %v", l2, err)
	}
	if err := cf.Revoke(ctx, "master_ok", l2); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Default permissions + custom colon fallback + mixed hex
	if _, err := cf.Mint(ctx, "master_ok", core.MintRequest{
		Scope:       "example.com",
		Permissions: nil, // defaults to dns:write, zone:read
	}); err != nil {
		t.Fatalf("default perms mint failed: %v", err)
	}
	if _, err := cf.Mint(ctx, "master_ok", core.MintRequest{
		Scope:       "*",
		Permissions: []string{hexPerm, "custom:thing:read"},
	}); err != nil {
		t.Fatalf("mixed perms mint failed: %v", err)
	}

	// Error paths: zone not found, zone HTTP 500, perm_groups 500, unmatched permissions, token rejected, post 500, bad JSON
	if _, err := cf.Mint(ctx, "master_ok", core.MintRequest{Scope: "notfound.com"}); err == nil {
		t.Fatal("expected zone not found error")
	}
	if _, err := cf.Mint(ctx, "master_ok", core.MintRequest{Scope: "http500.com"}); err == nil {
		t.Fatal("expected HTTP 500 error")
	}
	if _, err := cf.Mint(ctx, "perm_500", core.MintRequest{Scope: "*"}); err == nil {
		t.Fatal("expected perm_groups 500 error")
	}
	if _, err := cf.Mint(ctx, "master_ok", core.MintRequest{Permissions: []string{"nonexistent:perm"}}); err == nil {
		t.Fatal("expected unmatched perm error")
	}
	if _, err := cf.Mint(ctx, "reject_tok", core.MintRequest{Permissions: []string{hexPerm}}); err == nil {
		t.Fatal("expected token mint rejected error")
	}
	if _, err := cf.Mint(ctx, "post_500", core.MintRequest{Permissions: []string{hexPerm}}); err == nil {
		t.Fatal("expected post 500 error")
	}
	if _, err := cf.Mint(ctx, "bad_json", core.MintRequest{Permissions: []string{hexPerm}}); err == nil {
		t.Fatal("expected bad JSON error")
	}
}

func TestGitHubProviderAndJWTSigningComprehensive(t *testing.T) {
	gh := NewGitHubProvider()
	if gh.Manifest().Name != "github" {
		t.Fatalf("unexpected manifest: %+v", gh.Manifest())
	}

	ctx := context.Background()
	if _, err := gh.Mint(ctx, "", core.MintRequest{}); err == nil {
		t.Fatal("expected empty secret error")
	}

	// Static PAT mode
	staticLease, err := gh.Mint(ctx, "ghp_static_pat_token_123", core.MintRequest{Scope: "owner/repo"})
	if err != nil || staticLease.Ephemeral || staticLease.ID != "gh-static" {
		t.Fatalf("expected static lease, got %+v err=%v", staticLease, err)
	}
	if err := gh.Revoke(ctx, "", staticLease); err != nil {
		t.Fatal(err)
	}

	// Generate RSA key for PKCS#1 and PKCS#8 JWT signing tests
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}))
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}))

	if _, err := signGitHubAppJWT("123", pkcs1PEM); err != nil {
		t.Fatalf("PKCS1 JWT sign failed: %v", err)
	}
	if _, err := signGitHubAppJWT("123", pkcs8PEM); err != nil {
		t.Fatalf("PKCS8 JWT sign failed: %v", err)
	}
	if _, err := signGitHubAppJWT("123", "not-a-pem"); err == nil {
		t.Fatal("expected invalid PEM error")
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecBytes, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecBytes}))
	if _, err := signGitHubAppJWT("123", ecPEM); err == nil {
		t.Fatal("expected unsupported non-RSA key error")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/555/access_tokens":
			_, _ = w.Write([]byte(`{"token":"ghs_minted_555"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/empty/access_tokens":
			_, _ = w.Write([]byte(`{"token":""}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token" && r.Header.Get("Authorization") == "Bearer ghs_minted_555":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`bad request`))
		}
	}))
	defer srv.Close()
	gh.BaseURL = srv.URL
	gh.Client = srv.Client()

	// Mint using full "<app_id>:<inst_id>:<pem>" composite secret
	compositeSecret := "12345:555:" + strings.ReplaceAll(pkcs1PEM, "\n", `\n`)
	dynLease, err := gh.Mint(ctx, compositeSecret, core.MintRequest{
		Scope:       "org/repo",
		Permissions: []string{"contents:write", "pull_requests:read"},
	})
	if err != nil || !dynLease.Ephemeral || !strings.HasPrefix(dynLease.ID, "gh-inst-555-") || dynLease.RevokeSecret != "ghs_minted_555" {
		t.Fatalf("composite RSA mint failed: %+v %v", dynLease, err)
	}
	if err := gh.Revoke(ctx, "", dynLease); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if err := gh.Revoke(ctx, "", &core.Lease{ID: dynLease.ID, Ephemeral: true}); err == nil {
		t.Fatal("expected revoke error without RevokeSecret")
	}

	// Error cases in Mint
	if _, err := gh.Mint(ctx, "123:555:-----BEGIN INVALID", core.MintRequest{}); err == nil {
		t.Fatal("expected invalid PEM error in Mint")
	}
	if _, err := gh.Mint(ctx, "empty:jwt_tok", core.MintRequest{}); err == nil {
		t.Fatal("expected empty installation token error")
	}
	if _, err := gh.Mint(ctx, "400:jwt_tok", core.MintRequest{}); err == nil {
		t.Fatal("expected HTTP 400 error")
	}
}

func TestKeychainAndOnePasswordVaults(t *testing.T) {
	home := t.TempDir()
	kv := NewKeychainVault(home)
	if kv.Manifest().Name != "keychain" {
		t.Fatalf("unexpected manifest: %+v", kv.Manifest())
	}

	ctx := context.Background()
	// Test file vault mode + edge cases
	kv.ForceFile = true
	if err := kv.SetSecret(ctx, "cf", "   "); err == nil {
		t.Fatal("expected empty secret error")
	}
	if _, err := kv.GetSecret(ctx, "missing"); err == nil {
		t.Fatal("expected missing secret error")
	}
	if err := kv.SetSecret(ctx, "cf", "sec_123"); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.GetSecret(ctx, "cf"); err != nil || got != "sec_123" {
		t.Fatalf("unexpected secret: %q %v", got, err)
	}
	if err := kv.DeleteSecret(ctx, "cf"); err != nil {
		t.Fatal(err)
	}

	// Corrupted vault.json handling & AES-256-GCM tamper detection
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{corrupt`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected corrupt JSON error")
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"!!!not-base64!!!"}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected invalid base64 error")
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"YWJj"}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected short nonce error")
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected GCM authentication failure error")
	}
	// Legacy plaintext JSON map backward compatibility
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"mintrun:cf":"legacy_plain_val"}`), 0o600)
	if got, err := kv.GetSecret(ctx, "cf"); err != nil || got != "legacy_plain_val" {
		t.Fatalf("expected legacy_plain_val, got %q %v", got, err)
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`null`), 0o600)
	if err := kv.SetSecret(ctx, "cf", "recovered"); err != nil {
		t.Fatal(err)
	}

	// Test native macOS Keychain path (ForceFile = false) with ephemeral test key
	kv.ForceFile = false
	testKey := "unit_test_ephemeral_key_999"
	defer func() { _ = kv.DeleteSecret(ctx, testKey) }()
	if err := kv.SetSecret(ctx, testKey, "keychain_val_999"); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.GetSecret(ctx, testKey); err != nil || got != "keychain_val_999" {
		t.Fatalf("expected keychain_val_999, got %q %v", got, err)
	}
	if err := kv.DeleteSecret(ctx, testKey); err != nil {
		t.Fatal(err)
	}
	// Fallback to file secret when key is not in macOS Keychain
	if got, err := kv.GetSecret(ctx, "cf"); err != nil || got != "recovered" {
		t.Fatalf("expected fallback to file secret 'recovered', got %q %v", got, err)
	}

	// Test OnePasswordVault using a mock `op` CLI binary in PATH
	binDir := t.TempDir()
	opScript := `#!/bin/sh
case "$*" in
  *"fail"*)
    echo "op error" >&2
    exit 1
    ;;
  "read op://Private/cf/token")
    echo "op_uri_secret_val"
    ;;
  "item get mintrun:cloudflare --fields label=credential --reveal --vault TeamVault")
    echo "op_item_secret_val"
    ;;
  "item create"*)
    echo "created"
    ;;
  "item delete"*)
    echo "deleted"
    ;;
esac
`
	opPath := filepath.Join(binDir, "op")
	if err := os.WriteFile(opPath, []byte(opScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("MINTRUN_OP_VAULT", "TeamVault")

	opv := NewOnePasswordVault()
	if opv.Manifest().Name != "1password" || opv.VaultName != "TeamVault" {
		t.Fatalf("unexpected 1password vault: %+v", opv)
	}
	if err := opv.SetSecret(ctx, "cloudflare", ""); err == nil {
		t.Fatal("expected empty secret error")
	}
	if err := opv.SetSecret(ctx, "cloudflare", "val123"); err != nil {
		t.Fatalf("op SetSecret failed: %v", err)
	}
	if got, err := opv.GetSecret(ctx, "op://Private/cf/token"); err != nil || got != "op_uri_secret_val" {
		t.Fatalf("op:// GetSecret failed: %q %v", got, err)
	}
	if got, err := opv.GetSecret(ctx, "cloudflare"); err != nil || got != "op_item_secret_val" {
		t.Fatalf("item GetSecret failed: %q %v", got, err)
	}
	if err := opv.DeleteSecret(ctx, "cloudflare"); err != nil {
		t.Fatalf("op DeleteSecret failed: %v", err)
	}
	// Error paths when `op` exits non-zero
	if _, err := opv.GetSecret(ctx, "op://fail"); err == nil {
		t.Fatal("expected op read error")
	}
	if _, err := opv.GetSecret(ctx, "fail"); err == nil {
		t.Fatal("expected op item get error")
	}
	if err := opv.SetSecret(ctx, "fail", "v"); err == nil {
		t.Fatal("expected op item create error")
	}
	if err := opv.DeleteSecret(ctx, "fail"); err == nil {
		t.Fatal("expected op item delete error")
	}
}

func TestMCPBridgeComprehensive(t *testing.T) {
	home := t.TempDir()
	reg := core.NewRegistry()
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	_ = kv.SetSecret(context.Background(), "cloudflare", "cf_sec_12345")
	_ = reg.Register(kv)
	_ = reg.Register(NewCloudflareProvider())
	bridge := NewMCPBridge()
	_ = reg.Register(bridge)

	if bridge.Manifest().Name != "mcp" {
		t.Fatalf("unexpected manifest: %+v", bridge.Manifest())
	}

	rt := core.NewRuntime(home, "keychain", reg)
	requests := []string{
		"",                                    // empty line ignored
		"{invalid-json",                       // malformed JSON ignored
		`{"jsonrpc":"2.0","method":"notify"}`, // notification without ID ignored
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":"not-an-object"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mintrun_plugins"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mintrun_exec","arguments":"bad"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"mintrun_exec","arguments":{"provider":"missing","command":["echo"]}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"mintrun_exec","arguments":{"provider":"cloudflare","permissions":["static"],"command":["echo","ok"]}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"unknown_tool"}}`,
		`{"jsonrpc":"2.0","id":9,"method":"unknown_method"}`,
	}

	var out bytes.Buffer
	if err := bridge.Serve(context.Background(), rt, strings.NewReader(strings.Join(requests, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("expected 9 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}

	// Verify canceled context exits cleanly
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bridge.Serve(canceledCtx, rt, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`+"\n"), &out); err == nil {
		t.Fatal("expected context canceled error")
	}

	// Verify rpcErr formatting
	var errResp jsonRPCResponse
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &errResp); err != nil || errResp.Error == nil || errResp.Error.Code != -32601 {
		t.Fatalf("expected -32601 method not found, got %+v err=%v", errResp, err)
	}
}

func TestAWSProviderComprehensive(t *testing.T) {
	aws := NewAWSProvider()
	if aws.Manifest().Name != "aws" {
		t.Fatalf("unexpected manifest: %+v", aws.Manifest())
	}

	ctx := context.Background()
	if _, err := aws.Mint(ctx, "", core.MintRequest{}); err == nil {
		t.Fatal("expected empty master secret error")
	}
	if _, err := aws.Mint(ctx, "invalid-format-without-colon", core.MintRequest{}); err == nil {
		t.Fatal("expected invalid master secret format error")
	}

	// Static mode (2-part and 3-part with session token)
	staticLease, err := aws.Mint(ctx, "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:sess_tok_1", core.MintRequest{
		Scope: "my-bucket",
	})
	if err != nil || staticLease.Ephemeral || staticLease.Env["AWS_SESSION_TOKEN"] != "sess_tok_1" {
		t.Fatalf("unexpected static lease: %+v err=%v", staticLease, err)
	}
	if err := aws.Revoke(ctx, "", staticLease); err != nil {
		t.Fatal(err)
	}

	// Mock AWS STS server verifying SigV4 header & inline session policy
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		roleArn := r.FormValue("RoleArn")
		switch {
		case strings.Contains(roleArn, "fail500"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`sts internal error`))
		case strings.Contains(roleArn, "badxml"):
			_, _ = w.Write([]byte(`<not-valid-sts-xml`))
		default:
			_, _ = w.Write([]byte(`<AssumeRoleResponse><AssumeRoleResult><AssumedRoleUser><AssumedRoleId>AROA123:mintrun</AssumedRoleId></AssumedRoleUser><Credentials><AccessKeyId>ASIAJIT123456</AccessKeyId><SecretAccessKey>jit_secret_key_999</SecretAccessKey><SessionToken>jit_sess_tok_888</SessionToken><Expiration>2026-10-15T12:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>`))
		}
	}))
	defer srv.Close()
	aws.Endpoint = srv.URL
	aws.Client = srv.Client()

	jitLease, err := aws.Mint(ctx, "AKIA123456:secret123456:parent_sess", core.MintRequest{
		Scope:       "arn:aws:iam::123456789012:role/DeployRole",
		Permissions: []string{"s3:GetObject", "s3:PutObject"},
		TTLSeconds:  100, // clamped to 900
	})
	if err != nil || !jitLease.Ephemeral || jitLease.Env["AWS_ACCESS_KEY_ID"] != "ASIAJIT123456" {
		t.Fatalf("unexpected JIT STS lease: %+v err=%v", jitLease, err)
	}
	// Test upper TTL clamp (>43200) and error responses
	if _, err := aws.Mint(ctx, "AKIA123456:secret123456", core.MintRequest{
		Scope:      "arn:aws:iam::123456789012:role/DeployRole",
		TTLSeconds: 99999,
	}); err != nil {
		t.Fatalf("expected success with clamped upper TTL, got %v", err)
	}
	if _, err := aws.Mint(ctx, "AKIA123456:secret123456", core.MintRequest{
		Scope: "arn:aws:iam::123456789012:role/fail500",
	}); err == nil {
		t.Fatal("expected STS HTTP 500 error")
	}
	if _, err := aws.Mint(ctx, "AKIA123456:secret123456", core.MintRequest{
		Scope: "arn:aws:iam::123456789012:role/badxml",
	}); err == nil {
		t.Fatal("expected STS XML parse error")
	}
}
