package builtin

import (
	"context"
	"testing"
)

// BenchmarkFileVaultOpen reads one secret from the AES-256-GCM file vault: every read derives the
// key with PBKDF2-HMAC-SHA256 (vaultKDFIters rounds) and decrypts vault.json. ForceFile and no
// SecretTool keep it off the macOS Keychain and libsecret.
func BenchmarkFileVaultOpen(b *testing.B) {
	b.Setenv("MINTRUN_VAULT_KEY", "mintrun-bench-passphrase")
	ctx := context.Background()
	v := &KeychainVault{HomeDir: b.TempDir(), ForceFile: true}
	const want = "bench-secret-value"
	if err := v.SetSecret(ctx, "github", want); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if got, err := v.GetSecret(ctx, "github"); err != nil || got != want {
			b.Fatalf("GetSecret did not return the stored secret (%v)", err)
		}
	}
}
