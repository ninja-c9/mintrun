package builtin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

type relayTestProvider struct {
	mu          sync.Mutex
	ephemeral   bool
	leakMaster  bool
	ttlOverride time.Duration
	mintErr     error
	mintHook    func() // runs at the start of Mint, outside mu
	revokedIDs  []string
	mints       []string // "<req.Provider>|<master>" per Mint call
}

func (p *relayTestProvider) Manifest() core.Manifest {
	return core.Manifest{Name: "cf-relay", Kind: core.KindProvider, Version: "1.0.0", Builtin: true}
}

func (p *relayTestProvider) Mint(_ context.Context, master string, req core.MintRequest) (*core.Lease, error) {
	p.mu.Lock()
	hook := p.mintHook
	p.mints = append(p.mints, req.Provider+"|"+master)
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	if p.mintErr != nil {
		return nil, p.mintErr
	}
	tok := "cf_jit_secret_token_987654"
	if p.leakMaster {
		tok = master
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if p.ttlOverride > 0 {
		ttl = p.ttlOverride
	}
	return &core.Lease{
		ID:           "lease-cf-12345",
		Provider:     "cf-relay",
		Scope:        req.Scope,
		Env:          map[string]string{"CF_API_TOKEN": tok},
		Redact:       []string{tok},
		RevokeSecret: "revoke-only-server-secret-9999",
		ExpiresAt:    time.Now().Add(ttl),
		Ephemeral:    p.ephemeral,
	}, nil
}

func (p *relayTestProvider) Revoke(_ context.Context, _ string, lease *core.Lease) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Revoke gets the lease as Mint returned it, never one renamed for an account.
	if lease.RevokeSecret != "revoke-only-server-secret-9999" || lease.Provider != "cf-relay" {
		return errors.New("missing server-side RevokeSecret, or a lease Mint did not return")
	}
	p.revokedIDs = append(p.revokedIDs, lease.ID)
	return nil
}

func readAuditLines(t *testing.T, home string) []core.AuditEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit.jsonl: %v", err)
	}
	var out []core.AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e core.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal audit line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func TestRelayDevices(t *testing.T) {
	home := t.TempDir()

	devs, err := ListRelayDevices(home)
	if err != nil || len(devs) != 0 {
		t.Fatalf("expected empty device list, got %v, err=%v", devs, err)
	}

	tok, dev, err := AddRelayDevice(home, "laptop-alice_01.local")
	if err != nil {
		t.Fatalf("AddRelayDevice: %v", err)
	}
	if !strings.HasPrefix(tok, "mr_dev_") {
		t.Fatalf("unexpected token prefix: %q", tok)
	}
	sum := sha256.Sum256([]byte(tok))
	if dev.TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("TokenSHA256 = %q, want %x", dev.TokenSHA256, sum)
	}

	raw, err := os.ReadFile(devicesFilePath(home))
	if err != nil {
		t.Fatalf("ReadFile devices.json: %v", err)
	}
	if strings.Contains(string(raw), tok) {
		t.Fatal("devices.json must never store the raw device token")
	}
	if info, err := os.Stat(devicesFilePath(home)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("devices.json mode = %v, err = %v", info, err)
	}

	if _, _, err := AddRelayDevice(home, "laptop-alice_01.local"); err == nil {
		t.Fatal("expected duplicate device name to be rejected")
	}
	for _, bad := range []string{"", ".", "..", "bad/name", "bad name", strings.Repeat("a", 65)} {
		if _, _, err := AddRelayDevice(home, bad); err == nil {
			t.Fatalf("expected invalid device name %q to be rejected", bad)
		}
		if err := RemoveRelayDevice(home, bad); err == nil {
			t.Fatalf("expected RemoveRelayDevice(%q) to fail", bad)
		}
	}

	devs, err = ListRelayDevices(home)
	if err != nil || len(devs) != 1 || devs[0].Name != "laptop-alice_01.local" {
		t.Fatalf("ListRelayDevices = %v, err = %v", devs, err)
	}

	if err := RemoveRelayDevice(home, "unknown-device"); err == nil {
		t.Fatal("expected removing unknown device to fail")
	}
	if err := RemoveRelayDevice(home, "laptop-alice_01.local"); err != nil {
		t.Fatalf("RemoveRelayDevice: %v", err)
	}
	devs, err = ListRelayDevices(home)
	if err != nil || len(devs) != 0 {
		t.Fatalf("expected empty list after remove, got %v, err=%v", devs, err)
	}

	// Symlinked devices.json resolves to target on write; dangling symlink and malformed JSON fail closed without leaking home path.
	realFile := filepath.Join(t.TempDir(), "real-devices.json")
	if err := os.WriteFile(realFile, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(devicesFilePath(home))
	if err := os.Symlink(realFile, devicesFilePath(home)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddRelayDevice(home, "symlinked-dev"); err != nil {
		t.Fatalf("AddRelayDevice through symlink: %v", err)
	}

	for _, badJSON := range []string{
		`[{"name":"a","token_sha256":"short","created_at":"2026-01-01T00:00:00Z"}]`,
		`[{"name":"a","token_sha256":"` + strings.Repeat("G", 64) + `","created_at":"2026-01-01T00:00:00Z"}]`,
		`[{"name":"a","token_sha256":"` + strings.Repeat("a", 64) + `","unknown":1}]`,
		`[] trailing`,
		`[{"name":"a","token_sha256":"` + strings.Repeat("a", 64) + `"},{"name":"a","token_sha256":"` + strings.Repeat("b", 64) + `"}]`,
	} {
		if err := os.WriteFile(realFile, []byte(badJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ListRelayDevices(home); err == nil {
			t.Fatalf("expected malformed devices.json %s to fail", badJSON)
		}
	}

	// Dangling symlink fails closed and never leaks path.
	_ = os.Remove(realFile)
	if _, err := ListRelayDevices(home); err == nil || strings.Contains(err.Error(), home) {
		t.Fatalf("expected dangling symlink to fail without leaking path, got: %v", err)
	}
	if _, _, err := AddRelayDevice(home, "dev2"); err == nil {
		t.Fatal("expected AddRelayDevice on dangling symlink to fail")
	}
}

func TestRelayURLAndCertPin(t *testing.T) {
	goodPin := strings.Repeat("ab", 32)
	base, pin, err := ParseRelayURL("https://relay.example.com:8443/sub/#sha256=" + goodPin)
	if err != nil {
		t.Fatalf("ParseRelayURL: %v", err)
	}
	if base != "https://relay.example.com:8443/sub" || hex.EncodeToString(pin[:]) != goodPin {
		t.Fatalf("base=%q pin=%x", base, pin)
	}

	for _, bad := range []string{
		"",
		"http://relay.example.com#sha256=" + goodPin,
		"https://#sha256=" + goodPin,
		"https://user:pass@relay.example.com#sha256=" + goodPin,
		"https://relay.example.com?foo=1#sha256=" + goodPin,
		"https://relay.example.com",
		"https://relay.example.com#sha256=1234",
		"https://relay.example.com#sha256=" + strings.Repeat("zz", 32),
	} {
		if _, _, err := ParseRelayURL(bad); err == nil {
			t.Fatalf("expected ParseRelayURL(%q) to fail", bad)
		}
		if _, err := NewRelayClient(bad, func(context.Context) (string, error) { return "tok", nil }); err == nil {
			t.Fatalf("expected NewRelayClient(%q) to fail", bad)
		}
	}
	if _, err := NewRelayClient("https://relay.example.com#sha256="+goodPin, nil); err == nil {
		t.Fatal("expected NewRelayClient with nil tokenFn to fail")
	}
	if _, err := RelaySPKIPin([]byte("not-der")); err == nil {
		t.Fatal("expected RelaySPKIPin on bad DER to fail")
	}
	if _, err := RelayCertPin([]byte("not-pem")); err == nil {
		t.Fatal("expected RelayCertPin on bad PEM to fail")
	}

	// Verify RelayTLSConfig VerifyConnection checks.
	spki := []byte("matching-spki")
	spkiSum := sha256.Sum256(spki)
	cfg := RelayTLSConfig(spkiSum)
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("unexpected TLS version bounds: min=%x max=%x", cfg.MinVersion, cfg.MaxVersion)
	}
	validLeaf := &x509.Certificate{
		NotBefore:               time.Now().Add(-time.Hour),
		NotAfter:                time.Now().Add(time.Hour),
		RawSubjectPublicKeyInfo: spki,
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{validLeaf}}); err == nil {
		t.Fatal("expected TLS 1.2 to be rejected")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13}); err == nil {
		t.Fatal("expected empty PeerCertificates to be rejected")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(2 * time.Hour), RawSubjectPublicKeyInfo: spki}},
	}); err == nil {
		t.Fatal("expected not-yet-valid cert to be rejected")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), RawSubjectPublicKeyInfo: []byte("wrong")}},
	}); err == nil {
		t.Fatal("expected wrong SPKI pin to be rejected")
	}
}

func TestRelayEndToEnd(t *testing.T) {
	t.Setenv("MINTRUN_VAULT_KEY", "relay-test-vault-passphrase")
	serverHome := t.TempDir()
	clientHome := t.TempDir()

	// Configure server runtime with master secret in file vault.
	serverReg := core.NewRegistry()
	kv := NewKeychainVault(serverHome)
	kv.ForceFile, kv.SecretTool = true, ""
	_ = serverReg.Register(kv)
	prov := &relayTestProvider{ephemeral: true}
	_ = serverReg.Register(prov)

	masterSecret := "cf_master_secret_super_sensitive_0001"
	if err := kv.SetSecret(context.Background(), "cf-relay", masterSecret); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	policyJSON := `{
		"cf-relay": {
			"allowed_scopes": ["example.com"],
			"allowed_permissions": ["dns:write"],
			"max_ttl_seconds": 120,
			"clean_env": true
		},
		"cf-relay@work": {
			"allowed_scopes": ["work.example"],
			"max_ttl_seconds": 60
		}
	}`
	if err := os.WriteFile(filepath.Join(serverHome, "policy.json"), []byte(policyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	serverRT := core.NewRuntime(serverHome, "keychain", serverReg)
	// The server screens what it decides, with its own key; the client never screens, even with a
	// Screen set, and shows the server's verdict.
	var serverScreens, clientScreens atomic.Int32
	serverRT.Screen = func(core.ExecRequest, core.PolicyRule) *core.JevVerdict {
		serverScreens.Add(1)
		return &core.JevVerdict{Risk: "low", Model: "jev-1.13.0"}
	}
	relaySrv := NewRelayServer(serverRT)
	defer relaySrv.Close()

	ts := httptest.NewUnstartedServer(relaySrv)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()

	certDER := ts.Certificate().Raw
	pinHex, err := RelaySPKIPin(certDER)
	if err != nil {
		t.Fatalf("RelaySPKIPin: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if gotPin, err := RelayCertPin(certPEM); err != nil || gotPin != pinHex {
		t.Fatalf("RelayCertPin = %q, err = %v, want %q", gotPin, err, pinHex)
	}

	aliceToken, _, err := AddRelayDevice(serverHome, "laptop-alice")
	if err != nil {
		t.Fatalf("AddRelayDevice alice: %v", err)
	}
	bobToken, _, err := AddRelayDevice(serverHome, "laptop-bob")
	if err != nil {
		t.Fatalf("AddRelayDevice bob: %v", err)
	}

	relayURL := ts.URL + "#sha256=" + pinHex
	aliceClient, err := NewRelayClient(relayURL, func(context.Context) (string, error) { return aliceToken, nil })
	if err != nil {
		t.Fatalf("NewRelayClient: %v", err)
	}
	bobClient, err := NewRelayClient(relayURL, func(context.Context) (string, error) { return bobToken, nil })
	if err != nil {
		t.Fatalf("NewRelayClient bob: %v", err)
	}

	// Client runtime has NO vault secret and NO local policy: everything comes from the relay.
	clientRT := core.NewRuntime(clientHome, "keychain", core.NewRegistry())
	clientRT.Relay = aliceClient
	clientRT.Screen = func(core.ExecRequest, core.PolicyRule) *core.JevVerdict {
		clientScreens.Add(1)
		return &core.JevVerdict{Risk: "high", Route: "deny", Reason: "policy denied: the client screened"}
	}

	// 1. SPKI pin mismatch must fail closed.
	wrongPinClient, err := NewRelayClient(ts.URL+"#sha256="+strings.Repeat("00", 32), func(context.Context) (string, error) { return aliceToken, nil })
	if err != nil {
		t.Fatal(err)
	}
	if d := wrongPinClient.CheckPolicy(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); d.Allowed || d.BlockedBy != "relay" || strings.Contains(d.Reason, aliceToken) ||
		!strings.HasPrefix(d.Reason, "policy denied: relay cannot be reached (") || !strings.Contains(d.Reason, "does not match pinned") {
		t.Fatalf("expected SPKI mismatch to fail closed without token leak, got: %+v", d)
	}

	// 2. Wrong device token must fail closed (401) and scrub the token from any error.
	badTok := "mr_dev_invalid_secret_token_value"
	badTokClient, _ := NewRelayClient(relayURL, func(context.Context) (string, error) { return badTok, nil })
	if d := badTokClient.CheckPolicy(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); d.Allowed || d.BlockedBy != "relay" || d.Reason != "policy denied: relay rejected device token (401 unauthorized)" {
		t.Fatalf("expected bad token to fail closed, got: %+v", d)
	}

	// 3. HTTP method and endpoint validation on server.
	reqGet, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/check", nil)
	if resp, err := aliceClient.client.Do(reqGet); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %v, err = %v", resp, err)
	}
	if code, _ := aliceClient.postJSON(context.Background(), "/v1/unknown", map[string]any{}, nil); code != http.StatusNotFound {
		t.Fatalf("unknown endpoint status = %d", code)
	}
	reqBadBody, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/check", bytes.NewReader([]byte(`{"unknown_field":1}`)))
	reqBadBody.Header.Set("Authorization", "Bearer "+aliceToken)
	if resp, err := aliceClient.client.Do(reqBadBody); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status = %v, err = %v", resp, err)
	}

	// 4. Policy check through relay: allowed vs denied (scope, static, vault, timeout).
	dOK := clientRT.CheckPolicy(core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}, TTLSeconds: 600},
		Command:     []string{"true"},
	})
	if !dOK.Allowed || dOK.TTLSeconds != 120 || !dOK.CleanEnv {
		t.Fatalf("unexpected CheckPolicy decision: %+v", dOK)
	}
	for _, tc := range []struct {
		name string
		req  core.ExecRequest
		want string
	}{
		{
			name: "wrong scope",
			req: core.ExecRequest{
				MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "other.com", Permissions: []string{"dns:write"}},
				Command:     []string{"true"},
			},
			want: "scope",
		},
		{
			name: "static mode refused",
			req: core.ExecRequest{
				MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"static"}},
				Command:     []string{"true"},
			},
			want: "static",
		},
		{
			name: "vault override refused",
			req: core.ExecRequest{
				MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
				Vault:       "1password",
				Command:     []string{"true"},
			},
			want: "invalid_request",
		},
		{
			name: "timeout override refused",
			req: core.ExecRequest{
				MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
				TimeoutSec:  30,
				Command:     []string{"true"},
			},
			want: "invalid_request",
		},
	} {
		d := clientRT.CheckPolicy(tc.req)
		if d.Allowed || d.BlockedBy != tc.want {
			t.Fatalf("%s: CheckPolicy = %+v, want blocked_by=%q", tc.name, d, tc.want)
		}
		if _, err := clientRT.ExecBlind(context.Background(), tc.req); err == nil || err.Error() != d.Reason {
			t.Fatalf("%s: ExecBlind err = %v, want %q", tc.name, err, d.Reason)
		}
	}

	// 5. Full ExecBlind through relay: mints on server, injects CF_API_TOKEN on client, strips MINTRUN_RELAY_TOKEN, scrubs output, and revokes on server.
	t.Setenv("MINTRUN_RELAY_TOKEN", aliceToken)
	screensBefore := serverScreens.Load()
	res, err := clientRT.ExecBlind(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"sh", "-c", `printf "tok=%s relay=%s id=%s" "$CF_API_TOKEN" "$MINTRUN_RELAY_TOKEN" "lease-cf-12345"`},
		Client:      "Cursor",
		Purpose:     "deploy preview worker",
	})
	if err != nil {
		t.Fatalf("ExecBlind via relay: %v", err)
	}
	if res.ExitCode != 0 || !res.Ephemeral || !res.Revoked {
		t.Fatalf("unexpected ExecResult: %+v", res)
	}
	if strings.Contains(res.Stdout, "cf_jit_secret_token_987654") || strings.Contains(res.Stdout, aliceToken) || strings.Contains(res.Stdout, "lease-cf-12345") {
		t.Fatalf("unscrubbed stdout: %q", res.Stdout)
	}
	if want := "tok=[MINTRUN:REDACTED] relay= id=[MINTRUN:REDACTED]"; res.Stdout != want {
		t.Fatalf("stdout = %q, want %q", res.Stdout, want)
	}

	serverEntries := readAuditLines(t, serverHome)
	if len(serverEntries) < 2 {
		t.Fatalf("expected minted + done entries on server, got %d: %+v", len(serverEntries), serverEntries)
	}
	mintedEntry := serverEntries[len(serverEntries)-2]
	doneEntry := serverEntries[len(serverEntries)-1]
	if mintedEntry.Outcome != "minted" || mintedEntry.Device != "laptop-alice" || mintedEntry.Via != "relay" || mintedEntry.LeaseID != "lease-cf-12345" {
		t.Fatalf("unexpected server minted entry: %+v", mintedEntry)
	}
	if doneEntry.Outcome != "done" || doneEntry.Device != "laptop-alice" || !doneEntry.Revoked || doneEntry.Task != mintedEntry.Task {
		t.Fatalf("unexpected server done entry: %+v", doneEntry)
	}
	// One screen for /v1/check and one for /v1/mint; both server entries and the client's carry it.
	clientEntry := readAuditLines(t, clientHome)[len(readAuditLines(t, clientHome))-1]
	for _, e := range []core.AuditEntry{mintedEntry, doneEntry, clientEntry} {
		if e.JevRisk != "low" || e.JevModel != "jev-1.13.0" || e.JevError != "" {
			t.Fatalf("entry %q: jev_risk %q, jev_model %q, jev_error %q", e.Outcome, e.JevRisk, e.JevModel, e.JevError)
		}
	}
	if n := serverScreens.Load() - screensBefore; n != 2 {
		t.Fatalf("server screened %d times for one relay exec, want 2", n)
	}

	// 5b. An account alias reads its own master secret and its own rule on the server, with nothing
	// inherited from the bare type's, the provider sees only its type, and every entry names the alias.
	workMaster := "cf_master_secret_work_account_0002"
	if err := kv.SetSecret(context.Background(), "cf-relay@work", workMaster); err != nil {
		t.Fatalf("SetSecret alias: %v", err)
	}
	aliasReq := func(provider, scope string) core.ExecRequest {
		return core.ExecRequest{
			MintRequest: core.MintRequest{Provider: provider, Scope: scope, Permissions: []string{"dns:write"}},
			Command:     []string{"sh", "-c", `printf "tok=%s" "$CF_API_TOKEN"`},
		}
	}
	if d := clientRT.CheckPolicy(aliasReq("cf-relay@work", "example.com")); d.Allowed || d.BlockedBy != "scope" {
		t.Fatalf("the alias took the bare type's scope: %+v", d)
	}
	if d := clientRT.CheckPolicy(aliasReq("cf-relay@work", "work.example")); !d.Allowed || d.TTLSeconds != 60 || d.CleanEnv {
		t.Fatalf("alias CheckPolicy = %+v, want its own rule", d)
	}
	res, err = clientRT.ExecBlind(context.Background(), aliasReq("cf-relay@work", "work.example"))
	if err != nil || res.ExitCode != 0 || !res.Revoked || res.Stdout != "tok=[MINTRUN:REDACTED]" {
		t.Fatalf("alias ExecBlind via relay: res=%+v err=%v", res, err)
	}
	prov.mu.Lock()
	lastMint := prov.mints[len(prov.mints)-1]
	prov.mu.Unlock()
	if lastMint != "cf-relay|"+workMaster {
		t.Fatalf("the provider minted %q, want its type with the alias's master secret", lastMint)
	}
	srv, cli := readAuditLines(t, serverHome), readAuditLines(t, clientHome)
	for i, e := range []core.AuditEntry{srv[len(srv)-2], srv[len(srv)-1], cli[len(cli)-1]} {
		if want := []string{"minted", "done", "done"}[i]; e.Provider != "cf-relay@work" || e.Outcome != want {
			t.Fatalf("alias audit entry %d: %+v", i, e)
		}
	}
	// An alias with no rule is governed like any provider without one; with no secret it fails to
	// mint, and the vault names the fix.
	if d := clientRT.CheckPolicy(aliasReq("cf-relay@ci", "other.example")); !d.Allowed || d.CleanEnv {
		t.Fatalf("an alias with no rule: %+v", d)
	}
	if _, err := clientRT.ExecBlind(context.Background(), aliasReq("cf-relay@ci", "other.example")); err == nil ||
		err.Error() != `relay mint failed: vault "keychain" could not load master secret for "cf-relay@ci": secret "cf-relay@ci" not found in vault (run mintrun secret set cf-relay@ci)` {
		t.Fatalf("an alias with no secret: %v", err)
	}

	// 6. Cross-device revoke isolation: bob cannot revoke alice's lease, and invalid outcome is rejected.
	lease, _, _, err := aliceClient.Mint(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	})
	if err != nil {
		t.Fatalf("alice Mint: %v", err)
	}
	if _, err := bobClient.Revoke(context.Background(), lease.ID, "done", 0, false); err == nil || err.Error() != "unknown lease" {
		t.Fatalf("expected bob to be refused with unknown lease when revoking alice's lease, got: %v", err)
	}
	if _, err := aliceClient.Revoke(context.Background(), lease.ID, "invalid_outcome", 0, false); err == nil {
		t.Fatal("expected invalid revoke outcome to be refused")
	}
	if ok, err := aliceClient.Revoke(context.Background(), lease.ID, "done", 0, true); err != nil || !ok {
		t.Fatalf("expected alice Revoke to succeed, got ok=%v err=%v", ok, err)
	}

	// 7. Lease expiry without client revoke writes "unreported" and revokes the lease on the server.
	prov.ttlOverride = 40 * time.Millisecond
	if _, _, _, err := aliceClient.Mint(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); err != nil {
		t.Fatalf("alice short-TTL Mint: %v", err)
	}
	prov.ttlOverride = 0
	time.Sleep(120 * time.Millisecond)
	serverEntries = readAuditLines(t, serverHome)
	last := serverEntries[len(serverEntries)-1]
	if last.Outcome != "unreported" || last.ExitCode != -1 || !last.Revoked || last.Device != "laptop-alice" {
		t.Fatalf("expected unreported expiry entry, got: %+v", last)
	}

	// 8. Non-ephemeral or master-leaking provider lease on server is refused and never sent to client.
	prov.ephemeral = false
	if _, err := clientRT.ExecBlind(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); err == nil || !strings.Contains(err.Error(), "non-ephemeral or master-secret lease") {
		t.Fatalf("expected non-ephemeral lease to be refused, got: %v", err)
	}
	prov.ephemeral = true
	prov.leakMaster = true
	if _, err := clientRT.ExecBlind(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); err == nil || strings.Contains(err.Error(), masterSecret) || !strings.Contains(err.Error(), "non-ephemeral or master-secret lease") {
		t.Fatalf("expected master-leaking lease to be refused and scrubbed, got: %v", err)
	}
	// An alias's refused lease is still revoked, and Revoke gets it as the provider minted it.
	prov.mu.Lock()
	revokesBefore := len(prov.revokedIDs)
	prov.mu.Unlock()
	if _, err := clientRT.ExecBlind(context.Background(), aliasReq("cf-relay@work", "work.example")); err == nil || strings.Contains(err.Error(), workMaster) || !strings.Contains(err.Error(), `provider "cf-relay@work" returned a non-ephemeral or master-secret lease`) {
		t.Fatalf("expected the alias's master-leaking lease to be refused and scrubbed, got: %v", err)
	}
	prov.mu.Lock()
	revokesAfter := len(prov.revokedIDs)
	prov.mu.Unlock()
	if revokesAfter != revokesBefore+1 {
		t.Fatalf("the alias's refused lease got %d revokes, want 1 with the lease as minted", revokesAfter-revokesBefore)
	}
	prov.leakMaster = false

	// 9. Server-side human approval includes quoted Device: line right under Network: in ApprovalText (even when truncated) and propagates allow/deny.
	var seenPrompt string
	allowApproval := true
	serverRT.ApprovalFunc = func(_ context.Context, req core.ExecRequest) (bool, error) {
		seenPrompt = core.ApprovalText("mintrun relay approval", req, 3500)
		return allowApproval, nil
	}
	screensBefore = serverScreens.Load()
	res, err = clientRT.ExecBlind(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true", strings.Repeat("x", 4000)},
		Approve:     true,
		Purpose:     "rotate preview dns",
		Client:      "Claude Code",
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("approved ExecBlind failed: res=%+v err=%v", res, err)
	}
	if !strings.Contains(seenPrompt, "\nSandbox: off\nNetwork: open\nDevice: \"laptop-alice\"\nHints: none\nRisk: low (jev-1.13.0)\nProvider: \"cf-relay\"\n") || !strings.Contains(seenPrompt, "TRUNCATED") {
		t.Fatalf("ApprovalText missing quoted Device line right under Network on truncated request:\n%s", seenPrompt)
	}
	// The approval reuses the verdict: the second decide after it screens nothing.
	if n := serverScreens.Load() - screensBefore; n != 2 {
		t.Fatalf("server screened %d times for one approved relay exec, want 2", n)
	}

	allowApproval = false
	if _, err := clientRT.ExecBlind(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
		Approve:     true,
	}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected denied approval to fail, got: %v", err)
	}
	clientEntries := readAuditLines(t, clientHome)
	if lastClient := clientEntries[len(clientEntries)-1]; lastClient.Outcome != "denied" || lastClient.ExitCode != 126 || lastClient.DecidedAt == "" {
		t.Fatalf("expected client audit entry to record denied/126/DecidedAt, got: %+v", lastClient)
	}

	// 10. Server Close() revokes and audits any still-open lease as "unreported".
	allowApproval = true
	if _, _, _, err := aliceClient.Mint(context.Background(), core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}); err != nil {
		t.Fatalf("Mint before Close: %v", err)
	}
	relaySrv.Close()
	serverEntries = readAuditLines(t, serverHome)
	if lastClose := serverEntries[len(serverEntries)-1]; lastClose.Outcome != "unreported" || lastClose.ExitCode != -1 || !lastClose.Revoked {
		t.Fatalf("expected Close() to record unreported/revoked entry, got: %+v", lastClose)
	}
	if n := clientScreens.Load(); n != 0 {
		t.Fatalf("the relay client screened %d requests itself, want 0", n)
	}
}

func TestRelayRateLimitAndLeaseCap(t *testing.T) {
	t.Setenv("MINTRUN_VAULT_KEY", "relay-rate-vault-passphrase")
	serverHome := t.TempDir()
	reg := core.NewRegistry()
	fv := NewKeychainVault(serverHome)
	fv.ForceFile, fv.SecretTool = true, ""
	if err := reg.Register(fv); err != nil {
		t.Fatal(err)
	}
	prov := &relayTestProvider{ephemeral: true}
	if err := reg.Register(prov); err != nil {
		t.Fatal(err)
	}
	if err := fv.SetSecret(context.Background(), "cf-relay", "MASTER-SECRET-CANARY-999"); err != nil {
		t.Fatal(err)
	}
	policyJSON := `{"cf-relay":{"allowed_scopes":["example.com"],"allowed_permissions":["dns:write"],"max_ttl_seconds":300}}`
	if err := os.WriteFile(filepath.Join(serverHome, "policy.json"), []byte(policyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	aliceToken, _, err := AddRelayDevice(serverHome, "laptop-alice")
	if err != nil {
		t.Fatal(err)
	}
	bobToken, _, err := AddRelayDevice(serverHome, "laptop-bob")
	if err != nil {
		t.Fatal(err)
	}

	serverRT := core.NewRuntime(serverHome, "keychain", reg)
	relaySrv := NewRelayServer(serverRT)
	defer relaySrv.Close()

	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	relaySrv.Now = func() time.Time { return now }
	relaySrv.RatePerMin = 60
	relaySrv.Burst = 2

	ts := httptest.NewUnstartedServer(relaySrv)
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()

	pin, err := RelaySPKIPin(ts.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	pinnedURL := ts.URL + "#sha256=" + pin
	aliceClient, err := NewRelayClient(pinnedURL, func(context.Context) (string, error) { return aliceToken, nil })
	if err != nil {
		t.Fatal(err)
	}
	bobClient, err := NewRelayClient(pinnedURL, func(context.Context) (string, error) { return bobToken, nil })
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "example.com", Permissions: []string{"dns:write"}},
		Command:     []string{"true"},
	}

	// 1. Burst of 2 succeeds for laptop-alice; 3rd request at the same instant gets 429, while laptop-bob succeeds.
	for i := range 2 {
		if d := aliceClient.CheckPolicy(ctx, req); !d.Allowed {
			t.Fatalf("alice request %d denied: %+v", i, d)
		}
	}
	const limited = "policy denied: relay rate limited (429: rate limit exceeded)"
	if d := aliceClient.CheckPolicy(ctx, req); d.Allowed || d.BlockedBy != "relay" || d.Reason != limited {
		t.Fatalf("expected 429 rate limit exceeded on 3rd request, got: %+v", d)
	}
	// The raw reply alice gets: its status, Retry-After, and the error in its body.
	rawPost := func(path string) (int, string, string) {
		t.Helper()
		hreq, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		hreq.Header.Set("Authorization", "Bearer "+aliceToken)
		resp, err := ts.Client().Do(hreq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, resp.Header.Get("Retry-After"), body.Error
	}
	if code, ra, msg := rawPost("/v1/check"); code != http.StatusTooManyRequests || ra != "1" || msg != "rate limit exceeded" {
		t.Fatalf("rate-limited /v1/check = %d, Retry-After %q, error %q; want 429, \"1\", \"rate limit exceeded\"", code, ra, msg)
	}
	if d := bobClient.CheckPolicy(ctx, req); !d.Allowed {
		t.Fatalf("bob should not be rate-limited by alice: %+v", d)
	}

	// 2. Advancing clock by 1s refills 1 token (60/min = 1/sec), allowing 1 more request for alice.
	now = now.Add(time.Second)
	if d := aliceClient.CheckPolicy(ctx, req); !d.Allowed {
		t.Fatalf("alice should succeed after 1s refill: %+v", d)
	}
	if d := aliceClient.CheckPolicy(ctx, req); d.Allowed || d.BlockedBy != "relay" || d.Reason != limited {
		t.Fatalf("alice should be limited again when bucket empties: %+v", d)
	}

	// 3. A revoke spends no token: alice, out of tokens, still ends her lease, and the server
	// audits it as done, not unreported.
	now = now.Add(time.Second)
	la, _, _, err := aliceClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("alice mint after refill: %v", err)
	}
	if d := aliceClient.CheckPolicy(ctx, req); d.Allowed || d.Reason != limited {
		t.Fatalf("alice should be out of tokens after her mint: %+v", d)
	}
	if ok, err := aliceClient.Revoke(ctx, la.ID, "done", 0, false); err != nil || !ok {
		t.Fatalf("rate-limited alice Revoke = %v, %v; want true, nil", ok, err)
	}
	entries := readAuditLines(t, serverHome)
	if minted, final := entries[len(entries)-2], entries[len(entries)-1]; minted.Outcome != "minted" ||
		final.Outcome != "done" || !final.Revoked || final.Task != minted.Task || final.Device != "laptop-alice" {
		t.Fatalf("server audit after a rate-limited revoke = %+v, %+v; want minted, then done and revoked", minted, final)
	}
	now = now.Add(time.Second) // one token back; a revoke must leave it for the check below
	if _, err := aliceClient.Revoke(ctx, "no-such-lease", "done", 0, false); err == nil || err.Error() != "unknown lease" {
		t.Fatalf("Revoke of an unknown lease = %v, want unknown lease", err)
	}
	if d := aliceClient.CheckPolicy(ctx, req); !d.Allowed {
		t.Fatalf("a revoke spent alice's token: %+v", d)
	}

	// 4. Per-device active concurrent lease cap on /v1/mint.
	relaySrv.RatePerMin = 0 // disable request rate limit to isolate lease cap
	relaySrv.MaxLeases = 2

	// Parallel mints that all reach the server before any lease is stored still mint only
	// MaxLeases: the provider holds every mint it gets until each request has either reached
	// it or been refused.
	const parallel = 8
	const capped = "relay lease cap reached (429: too many active leases for device)"
	arrived, release := make(chan struct{}, parallel), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	prov.mu.Lock()
	prov.mintHook = func() { arrived <- struct{}{}; <-release }
	prov.mu.Unlock()
	var wg sync.WaitGroup
	leases, errs := make(chan *core.Lease, parallel), make(chan error, parallel)
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, _, _, err := aliceClient.Mint(ctx, req)
			if err != nil {
				errs <- err
				arrived <- struct{}{}
				return
			}
			leases <- l
		}()
	}
	for range parallel {
		select {
		case <-arrived:
		case <-time.After(time.Minute):
			t.Fatal("parallel mints neither reached the provider nor failed within a minute")
		}
	}
	// Alice's mints in flight count against her cap only: Bob's mint still reaches the provider.
	var bobLease *core.Lease
	bobDone := make(chan error, 1)
	go func() {
		l, _, _, err := bobClient.Mint(ctx, req)
		if err != nil {
			arrived <- struct{}{}
		}
		bobLease = l
		bobDone <- err
	}()
	select {
	case <-arrived:
	case <-time.After(time.Minute):
		t.Fatal("bob's mint neither reached the provider nor failed within a minute")
	}
	releaseOnce()
	wg.Wait()
	if err := <-bobDone; err != nil {
		t.Fatalf("bob's mint while alice's were in flight: %v", err)
	}
	if ok, err := bobClient.Revoke(ctx, bobLease.ID, "done", 0, false); err != nil || !ok {
		t.Fatalf("Revoke(bob) = %v, %v", ok, err)
	}
	close(leases)
	close(errs)
	prov.mu.Lock()
	prov.mintHook = nil
	prov.mu.Unlock()
	for err := range errs {
		if err.Error() != capped {
			t.Fatalf("parallel mint error = %q, want %q", err, capped)
		}
	}
	var minted []*core.Lease
	for l := range leases {
		minted = append(minted, l)
	}
	if len(minted) != relaySrv.MaxLeases {
		t.Fatalf("%d parallel mints gave %d leases, want MaxLeases = %d", parallel, len(minted), relaySrv.MaxLeases)
	}
	for _, l := range minted {
		if ok, err := aliceClient.Revoke(ctx, l.ID, "done", 0, false); err != nil || !ok {
			t.Fatalf("Revoke(%s) = %v, %v", l.ID, ok, err)
		}
	}

	l1, _, _, err := aliceClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("alice mint 1: %v", err)
	}
	l2, _, _, err := aliceClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("alice mint 2: %v", err)
	}
	if _, _, _, err := aliceClient.Mint(ctx, req); err == nil || err.Error() != capped {
		t.Fatalf("expected active lease cap error on 3rd mint, got: %v", err)
	}
	// What a capped exec shows: the relay was reached, and refused the mint.
	clientRT := core.NewRuntime(t.TempDir(), "keychain", core.NewRegistry())
	clientRT.Relay = aliceClient
	if _, err := clientRT.ExecBlind(ctx, req); err == nil || err.Error() != "relay mint failed: "+capped {
		t.Fatalf("capped ExecBlind error = %v, want %q", err, "relay mint failed: "+capped)
	}
	if code, ra, msg := rawPost("/v1/mint"); code != http.StatusTooManyRequests || ra != "1" || msg != "too many active leases for device" {
		t.Fatalf("capped /v1/mint = %d, Retry-After %q, error %q; want 429, \"1\", \"too many active leases for device\"", code, ra, msg)
	}
	// Bob can still mint while Alice is at her cap.
	lb, _, _, err := bobClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("bob mint while alice capped: %v", err)
	}
	_, _ = bobClient.Revoke(ctx, lb.ID, "done", 0, false)

	// Alice can still revoke l1 while at her cap, freeing a slot to mint again.
	if ok, err := aliceClient.Revoke(ctx, l1.ID, "done", 0, false); err != nil || !ok {
		t.Fatalf("expected alice Revoke(l1) to succeed while at lease cap: ok=%v err=%v", ok, err)
	}
	l3, _, _, err := aliceClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("alice mint 3 after revoking l1: %v", err)
	}
	_, _ = aliceClient.Revoke(ctx, l2.ID, "done", 0, false)
	_, _ = aliceClient.Revoke(ctx, l3.ID, "done", 0, false)

	// 5. A mint that fails gives its slot back: a denied one and one the provider fails.
	relaySrv.MaxLeases = 1
	denied := req
	denied.Scope = "other.com"
	if _, _, _, err := aliceClient.Mint(ctx, denied); !errors.As(err, new(*core.RelayDenyError)) {
		t.Fatalf("Mint for an unlisted scope = %v, want a relay deny", err)
	}
	prov.mintErr = errors.New("provider down")
	if _, _, _, err := aliceClient.Mint(ctx, req); err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Fatalf("Mint with a failing provider = %v, want provider down", err)
	}
	prov.mintErr = nil
	l4, _, _, err := aliceClient.Mint(ctx, req)
	if err != nil {
		t.Fatalf("Mint after two failed mints: %v", err)
	}
	if _, _, _, err := aliceClient.Mint(ctx, req); err == nil || err.Error() != capped {
		t.Fatalf("Mint over a cap of 1 = %v, want %q", err, capped)
	}
	if ok, err := aliceClient.Revoke(ctx, l4.ID, "done", 0, false); err != nil || !ok {
		t.Fatalf("Revoke(l4) = %v, %v", ok, err)
	}
}

// A reply cut off mid-body is a transport failure, so it reads as "cannot be reached", which a
// 429 or a 401 never does (TestRelayRateLimitAndLeaseCap, TestRelayEndToEnd).
func TestRelayClientCutOffReply(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"allowed":`))
	}))
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()
	pin, err := RelaySPKIPin(ts.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRelayClient(ts.URL+"#sha256="+pin, func(context.Context) (string, error) { return "mr_dev_cut_off_token", nil })
	if err != nil {
		t.Fatal(err)
	}
	d := c.CheckPolicy(context.Background(), core.ExecRequest{MintRequest: core.MintRequest{Provider: "cf-relay"}, Command: []string{"true"}})
	if want := "policy denied: relay cannot be reached (unexpected EOF)"; d.Allowed || d.BlockedBy != "relay" || d.Reason != want {
		t.Fatalf("cut-off reply = %+v, want reason %q", d, want)
	}
}
