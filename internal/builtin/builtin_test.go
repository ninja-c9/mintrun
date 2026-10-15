package builtin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	kv.SecretTool = "" // hermetic on Linux hosts with libsecret installed
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
	// An encrypted blob with no salt is rejected as unrecognized (audit C3).
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"YWJj"}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected missing-salt error")
	}
	// With a valid salt present, base64 / nonce / GCM-auth failures are still detected.
	const salt = `,"__salt__":"AAAAAAAAAAAAAAAAAAAAAA=="`
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"!!!not-base64!!!"`+salt+`}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected invalid base64 error")
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"YWJj"`+salt+`}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected short nonce error")
	}
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"__aes256gcm__":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`+salt+`}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected GCM authentication failure error")
	}
	// Legacy plaintext maps are now rejected, not silently trusted (audit C3).
	_ = os.WriteFile(kv.vaultFilePath(), []byte(`{"mintrun:cf":"legacy_plain_val"}`), 0o600)
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected legacy-plaintext rejection")
	}
	// An unrecognized vault file is fail-closed: SetSecret refuses to clobber it until
	// it is removed, then writes a fresh encrypted vault cleanly.
	if err := kv.SetSecret(ctx, "cf", "recovered"); err == nil {
		t.Fatal("expected fail-closed SetSecret over unrecognized vault")
	}
	_ = os.Remove(kv.vaultFilePath())
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
func TestFileVaultPassphraseRequiredPhase45PRC(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	vaultFile := filepath.Join(home, "vault.json")

	// C3: with no passphrase, the file vault refuses to write.
	t.Setenv("MINTRUN_VAULT_KEY", "")
	if err := kv.SetSecret(ctx, "cf", "s3cr3t"); err == nil {
		t.Fatal("expected missing-passphrase error on SetSecret")
	}

	// With a passphrase, set+get round-trips, the secret is not stored in plaintext,
	// and a per-vault random salt is persisted.
	t.Setenv("MINTRUN_VAULT_KEY", "correct horse battery staple")
	if err := kv.SetSecret(ctx, "cf", "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("plaintext secret leaked into vault.json")
	}
	var onDisk map[string]string
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk["__salt__"] == "" {
		t.Fatal("expected a per-vault salt persisted")
	}
	if got, err := kv.GetSecret(ctx, "cf"); err != nil || got != "s3cr3t" {
		t.Fatalf("round-trip failed: %q %v", got, err)
	}

	// C3: a wrong passphrase cannot decrypt the vault.
	t.Setenv("MINTRUN_VAULT_KEY", "wrong passphrase")
	if _, err := kv.GetSecret(ctx, "cf"); err == nil {
		t.Fatal("expected decrypt failure under wrong passphrase")
	}

	// Each write re-salts: the salt on disk changes between writes.
	t.Setenv("MINTRUN_VAULT_KEY", "correct horse battery staple")
	if err := kv.SetSecret(ctx, "cf", "s3cr3t"); err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk2 map[string]string
	if err := json.Unmarshal(raw2, &onDisk2); err != nil {
		t.Fatal(err)
	}
	if onDisk2["__salt__"] == onDisk["__salt__"] {
		t.Fatal("expected a fresh salt on re-write")
	}
}

// TestGCPProviderPhase5 drives the GCP provider against an offline mock OAuth2 server: the
// JWT bearer assertion must be RS256-signed by the service-account key with the expected
// claims, and every error path must stay scrubbed of the assertion and private key.
func TestGCPProviderPhase5(t *testing.T) {
	ctx := context.Background()
	const token = "ya29.mock_gcp_access_token"
	const jwtHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" // base64url {"alg":"RS256","typ":"JWT"}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}))
	saJSON, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "ci@example.iam.gserviceaccount.com", "private_key": pemKey})

	checkAssertion := func(r *http.Request) string {
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			return "bad grant_type"
		}
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		if len(parts) != 3 {
			return "malformed assertion"
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, digest[:], sig) != nil {
			return "bad RS256 signature"
		}
		var c struct {
			Iss, Scope, Aud string
			Iat, Exp        int64
		}
		body, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(body, &c)
		switch {
		case c.Iss != "ci@example.iam.gserviceaccount.com":
			return "bad iss " + c.Iss
		case c.Scope != "https://www.googleapis.com/auth/cloud-platform.read-only https://www.googleapis.com/auth/devstorage.read_only":
			return "bad scope " + c.Scope
		case c.Aud != "http://"+r.Host+r.URL.Path:
			return "bad aud " + c.Aud
		case c.Exp-c.Iat != 3600:
			return "bad exp"
		}
		return ""
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/token":
			if msg := checkAssertion(r); msg != "" {
				http.Error(w, msg, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + token + `","expires_in":3599,"token_type":"Bearer"}`))
		case "/echo": // a buggy endpoint echoing the grant and key back in its error body
			http.Error(w, "invalid_grant: "+r.PostForm.Encode()+" key="+pemKey, http.StatusBadRequest)
		case "/empty":
			_, _ = w.Write([]byte(`{"access_token":""}`))
		case "/garbage":
			_, _ = w.Write([]byte(`not json`))
		case "/revoke":
			if r.URL.RawQuery != "" || r.PostForm.Get("token") != token {
				http.Error(w, "token must be in the POST body", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	g := NewGCPProvider()
	if g.Manifest().Name != "gcp" || g.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Fatalf("unexpected gcp provider: %+v", g.Manifest())
	}
	g.TokenURL, g.RevokeURL = srv.URL+"/token", srv.URL+"/revoke"
	jit := core.MintRequest{Scope: "example-project", Permissions: []string{"cloud-platform.read-only", " ", "https://www.googleapis.com/auth/devstorage.read_only"}}

	lease, err := g.Mint(ctx, string(saJSON), jit)
	if err != nil {
		t.Fatalf("JIT mint failed: %v", err)
	}
	if !lease.Ephemeral || !strings.HasPrefix(lease.ID, "gcp-sa-") || lease.RevokeSecret != token ||
		lease.Env["CLOUDSDK_AUTH_ACCESS_TOKEN"] != token || lease.Env["GOOGLE_OAUTH_ACCESS_TOKEN"] != token ||
		len(lease.Redact) != 4 || time.Until(lease.ExpiresAt) < 59*time.Minute {
		t.Fatalf("unexpected JIT lease: %+v", lease)
	}
	if err := g.Revoke(ctx, "", lease); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Static mode wraps an access token, but never a service-account key.
	static, err := g.Mint(ctx, "ya29.static_access_token", core.MintRequest{Permissions: []string{"static"}})
	if err != nil || static.Ephemeral || static.ID != "gcp-static" || static.Env["CLOUDSDK_AUTH_ACCESS_TOKEN"] != "ya29.static_access_token" {
		t.Fatalf("unexpected static lease: %+v %v", static, err)
	}
	if err := g.Revoke(ctx, "", static); err != nil {
		t.Fatal(err)
	}
	if err := g.Revoke(ctx, "", nil); err != nil {
		t.Fatal(err)
	}
	for _, master := range []string{string(saJSON), pemKey} {
		if _, err := g.Mint(ctx, master, core.MintRequest{Params: map[string]string{"mode": "static"}}); err == nil {
			t.Fatal("expected static mode to refuse service-account key material")
		}
	}

	// Mint errors.
	for name, master := range map[string]string{
		"empty":       "",
		"not json":    "ya29.not_a_key",
		"no key":      `{"client_email":"ci@example.iam.gserviceaccount.com"}`,
		"bad pem":     `{"client_email":"ci@example.iam.gserviceaccount.com","private_key":"not-a-pem"}`,
		"scopeless":   string(saJSON),
		"token_400":   string(saJSON),
		"empty_token": string(saJSON),
		"bad_json":    string(saJSON),
		"bad_url":     string(saJSON),
		"unreachable": string(saJSON),
	} {
		g2 := *g
		req := jit
		switch name {
		case "scopeless":
			req.Permissions = []string{" "}
		case "token_400":
			g2.TokenURL = srv.URL + "/echo"
		case "empty_token":
			g2.TokenURL = srv.URL + "/empty"
		case "bad_json":
			g2.TokenURL = srv.URL + "/garbage"
		case "bad_url":
			g2.TokenURL = "://bad"
		case "unreachable":
			g2.TokenURL = deadURL + "/token"
		}
		_, err := g2.Mint(ctx, master, req)
		if err == nil {
			t.Fatalf("%s: expected mint error", name)
		}
		if msg := err.Error(); strings.Contains(msg, jwtHeader) || strings.Contains(msg, "PRIVATE KEY") {
			t.Fatalf("%s: mint error leaked the assertion or private key: %s", name, msg)
		}
		if name == "token_400" && !strings.Contains(err.Error(), core.RedactedPlaceholder) {
			t.Fatalf("expected the echoed grant to be scrubbed, got: %v", err)
		}
	}

	// Revoke errors.
	if err := g.Revoke(ctx, "", &core.Lease{Ephemeral: true}); err == nil {
		t.Fatal("expected missing revocation token error")
	}
	g.RevokeURL = srv.URL + "/nope"
	if err := g.Revoke(ctx, "", lease); err == nil {
		t.Fatal("expected revoke HTTP 404 error")
	}
}

// TestKeychainVaultLinuxSecretTool drives the libsecret path through a mock `secret-tool`:
// the secret must travel on stdin only (never argv), a failing secret-tool must fall back to
// the encrypted file vault, and deleting a libsecret-only key must not demand MINTRUN_VAULT_KEY.
func TestKeychainVaultLinuxSecretTool(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, argLog := filepath.Join(dir, "store"), filepath.Join(dir, "argv.log")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	// Mock CLI: secret-tool <store|lookup|clear> [--label=L] service <svc> account mintrun
	script := `#!/bin/sh
echo "$*" >> "$MOCK_SECRET_LOG"
action=$1; shift
case "$1" in --label=*) shift ;; esac
case "$2" in *fail*) exit 1 ;; esac
f="$MOCK_SECRET_STORE/$2"
case "$action" in
  store) cat > "$f" ;;
  lookup) cat "$f" 2>/dev/null || exit 1 ;;
  clear) rm -f "$f" ;;
esac
`
	tool := filepath.Join(dir, "secret-tool")
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOCK_SECRET_STORE", store)
	t.Setenv("MOCK_SECRET_LOG", argLog)

	kv := &KeychainVault{HomeDir: filepath.Join(dir, "home"), ForceFile: true, SecretTool: tool}
	if err := kv.SetSecret(ctx, "GCP", "  sa_json_secret_value  "); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.GetSecret(ctx, "gcp"); err != nil || got != "sa_json_secret_value" {
		t.Fatalf("libsecret round trip failed: %q %v", got, err)
	}
	logged, _ := os.ReadFile(argLog)
	if strings.Contains(string(logged), "sa_json_secret_value") || !strings.Contains(string(logged), "store --label=mintrun:gcp service mintrun:gcp account mintrun") {
		t.Fatalf("unexpected secret-tool argv (secret must go via stdin):\n%s", logged)
	}

	// Deleting a libsecret-only key needs no passphrase and never creates vault.json.
	t.Setenv("MINTRUN_VAULT_KEY", "")
	if err := kv.DeleteSecret(ctx, "gcp"); err != nil {
		t.Fatalf("delete without MINTRUN_VAULT_KEY: %v", err)
	}
	if _, err := kv.GetSecret(ctx, "gcp"); err == nil {
		t.Fatal("expected secret to be gone after delete")
	}
	if _, err := os.Stat(kv.vaultFilePath()); !os.IsNotExist(err) {
		t.Fatalf("libsecret-only usage must not create vault.json: %v", err)
	}

	// A failing secret-tool (no D-Bus session, locked keyring) falls back to the file vault.
	t.Setenv("MINTRUN_VAULT_KEY", "mintrun-unit-test-passphrase")
	if err := kv.SetSecret(ctx, "fail-key", "file_fallback_val"); err != nil {
		t.Fatal(err)
	}
	if got, err := kv.GetSecret(ctx, "fail-key"); err != nil || got != "file_fallback_val" {
		t.Fatalf("expected file-vault fallback, got %q %v", got, err)
	}
	if err := kv.DeleteSecret(ctx, "fail-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.GetSecret(ctx, "fail-key"); err == nil {
		t.Fatal("expected fallback secret to be gone after delete")
	}
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
