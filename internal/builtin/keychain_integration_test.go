//go:build integration

package builtin

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// TestKeychainVaultRealKeychain round-trips throwaway items through the real macOS Keychain. It
// is opt-in (`go test -tags integration`) so `go test ./...` stays hermetic (audit L8).
func TestKeychainVaultRealKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Keychain only")
	}
	ctx := context.Background()
	var warn bytes.Buffer
	oldWarn := warnOut
	warnOut = &warn
	defer func() { warnOut = oldWarn }()

	kv := &KeychainVault{HomeDir: t.TempDir()}
	const key, bigKey = "integration_test_ephemeral_key", "integration_test_ephemeral_big"
	defer func() { _, _ = kv.DeleteSecret(ctx, key), kv.DeleteSecret(ctx, bigKey) }()

	// Everything `security -i` and `-g` must carry byte-exactly: newlines, quotes, a backslash,
	// shell and comment characters, and UTF-8 (-g prints such values in its 0x hex form).
	multi := "{\n  \"key\": \"multi \\\\ line\",\n  \"utf8\": \"\u00fcn\u00efcode $HOME; # 'x'\"\n}"
	for _, val := range []string{multi, "plain_printable_value_123"} {
		if err := kv.SetSecret(ctx, key, val); err != nil {
			t.Fatal(err)
		}
		if got, err := kv.keychainGet(ctx, key); err != nil || got != val {
			t.Fatalf("Keychain round trip: %q %v", got, err)
		}
	}

	// An oversize secret is refused before `security -i` sees it and lands in the file vault.
	big := strings.Repeat("b", 2100)
	if err := kv.SetSecret(ctx, bigKey, big); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.keychainGet(ctx, bigKey); !errors.Is(err, errNotFound) {
		t.Fatalf("oversize secret must not reach the Keychain: %v", err)
	}
	if got, err := kv.GetSecret(ctx, bigKey); err != nil || got != big || !strings.Contains(warn.String(), "too long") {
		t.Fatalf("oversize secret must land in the file vault with a warning: %v, warnings %q", err, warn.String())
	}

	if err := kv.DeleteSecret(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.keychainGet(ctx, key); !errors.Is(err, errNotFound) {
		t.Fatalf("expected the Keychain item to be gone: %v", err)
	}
}
