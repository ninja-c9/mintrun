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

	// A secret one `security -i` line cannot carry is split into parts behind a header. Part 1 is
	// printable with quotes (-g's raw form), part 2 holds backslashes and ends mid-rune, and part 3
	// starts with the rest of that rune. Replacing the secret, then deleting it, leaves no parts.
	big := strings.Repeat(`q"q `, 375) + strings.Repeat(`a\b `, 374) + "ccc\u00fc\nend"
	svc := kv.serviceName(bigKey)
	gens := map[string]int{}
	for _, val := range []string{big, big[:2501]} {
		if err := kv.SetSecret(ctx, bigKey, val); err != nil {
			t.Fatal(err)
		}
		if got, err := kv.keychainGet(ctx, bigKey); err != nil || got != val {
			t.Fatalf("chunked round trip: %v", err)
		}
		head, err := kv.keychainRead(ctx, svc)
		gen, n, _, ok := parseChunkHeader(head)
		if err != nil || !ok || n != (len(val)+chunkSize-1)/chunkSize {
			t.Fatalf("expected a header, got %q %v", head, err)
		}
		gens[gen] = n
	}
	if err := kv.DeleteSecret(ctx, bigKey); err != nil {
		t.Fatal(err)
	}
	for gen, n := range gens {
		for i := range n {
			if _, err := kv.keychainRead(ctx, partService(svc, gen, i)); !errors.Is(err, errNotFound) {
				t.Fatalf("part %s.%d left in the Keychain: %v", gen, i, err)
			}
		}
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warnings:\n%s", warn.String())
	}

	if err := kv.DeleteSecret(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.keychainGet(ctx, key); !errors.Is(err, errNotFound) {
		t.Fatalf("expected the Keychain item to be gone: %v", err)
	}
}
