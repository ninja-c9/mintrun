package builtin

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ninja-c9/mintrun/internal/core"
)

const keychainAccount = "mintrun"

// File-vault KDF parameters: the AES-256-GCM key is derived from the
// MINTRUN_VAULT_KEY passphrase and a per-vault random salt via PBKDF2-HMAC-SHA256.
const (
	vaultKDFIters = 210000
	vaultKDFName  = "pbkdf2-hmac-sha256"
	vaultSaltLen  = 16
)

// KeychainVault stores master secrets in macOS Keychain (`/usr/bin/security`)
// with a fallback to an AES-256-GCM encrypted 0600 file vault (`~/.mintrun/vault.json`).
type KeychainVault struct {
	mu        sync.Mutex
	HomeDir   string
	ForceFile bool // Used on Linux or in deterministic unit tests
}

func NewKeychainVault(homeDir string) *KeychainVault {
	return &KeychainVault{
		HomeDir:   homeDir,
		ForceFile: runtime.GOOS != "darwin" || os.Getenv("MINTRUN_FILE_VAULT") == "1",
	}
}

func (k *KeychainVault) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "keychain",
		Version:     "0.4.0",
		Kind:        core.KindVault,
		Description: "OS native secret vault (macOS Keychain via /usr/bin/security with AES-256-GCM 0600 fallback)",
		Builtin:     true,
	}
}

func (k *KeychainVault) serviceName(key string) string {
	return "mintrun:" + strings.TrimSpace(strings.ToLower(key))
}

func (k *KeychainVault) GetSecret(ctx context.Context, key string) (string, error) {
	if !k.ForceFile {
		cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password",
			"-a", keychainAccount,
			"-s", k.serviceName(key),
			"-w",
		)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			val := strings.TrimSpace(out.String())
			if val != "" {
				return val, nil
			}
		}
	}
	return k.getFileSecret(key)
}

func (k *KeychainVault) SetSecret(ctx context.Context, key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("secret value cannot be empty")
	}
	if !k.ForceFile {
		cmd := exec.CommandContext(ctx, "/usr/bin/security", "add-generic-password",
			"-U",
			"-a", keychainAccount,
			"-s", k.serviceName(key),
			"-w", value,
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return k.setFileSecret(key, value)
}

func (k *KeychainVault) DeleteSecret(ctx context.Context, key string) error {
	if !k.ForceFile {
		_ = exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password",
			"-a", keychainAccount,
			"-s", k.serviceName(key),
		).Run()
	}
	return k.deleteFileSecret(key)
}

func (k *KeychainVault) vaultFilePath() string {
	return filepath.Join(k.HomeDir, "vault.json")
}

// vaultKey derives the AES-256-GCM key from the MINTRUN_VAULT_KEY passphrase and a
// per-vault random salt via PBKDF2-HMAC-SHA256. A passphrase is mandatory: the file
// vault is the at-rest store on non-macOS hosts, so a path-derived key would leave
// secrets decryptable by anyone who can read vault.json (audit C3).
func (k *KeychainVault) vaultKey(salt []byte) ([32]byte, error) {
	var out [32]byte
	pass := os.Getenv("MINTRUN_VAULT_KEY")
	if pass == "" {
		return out, errors.New("file vault requires a passphrase: set MINTRUN_VAULT_KEY, then run `mintrun secret set` to (re-)encrypt")
	}
	dk, err := pbkdf2.Key(sha256.New, pass, salt, vaultKDFIters, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], dk)
	return out, nil
}

func (k *KeychainVault) readMap() (map[string]string, error) {
	raw, err := os.ReadFile(k.vaultFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	encB64, encOK := m["__aes256gcm__"]
	saltB64, saltOK := m["__salt__"]
	if !encOK || !saltOK {
		return nil, errors.New("unrecognized or legacy vault format; delete vault.json and re-run `mintrun secret set` to re-encrypt under MINTRUN_VAULT_KEY")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode vault salt: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted vault: %w", err)
	}
	key, err := k.vaultKey(salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("corrupted encrypted vault nonce")
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault (wrong MINTRUN_VAULT_KEY?): %w", err)
	}
	var dec map[string]string
	if err := json.Unmarshal(plain, &dec); err != nil {
		return nil, err
	}
	if dec == nil {
		dec = make(map[string]string)
	}
	return dec, nil
}

func (k *KeychainVault) writeMap(m map[string]string) error {
	if err := os.MkdirAll(k.HomeDir, 0o700); err != nil {
		return err
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}
	salt := make([]byte, vaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate vault salt: %w", err)
	}
	key, err := k.vaultKey(salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate vault nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	raw, err := json.MarshalIndent(map[string]string{
		"__aes256gcm__": base64.StdEncoding.EncodeToString(sealed),
		"__salt__":      base64.StdEncoding.EncodeToString(salt),
		"__kdf__":       fmt.Sprintf("%s:%d", vaultKDFName, vaultKDFIters),
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(k.vaultFilePath(), raw, 0o600)
}

// writeFileAtomic writes to a temp file in the same directory, fsyncs it, then
// renames over path, so a crash mid-write never leaves a truncated vault (audit L3).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (k *KeychainVault) getFileSecret(key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.readMap()
	if err != nil {
		return "", err
	}
	v, ok := m[k.serviceName(key)]
	if !ok || v == "" {
		return "", fmt.Errorf("secret %q not found in vault", key)
	}
	return v, nil
}

func (k *KeychainVault) setFileSecret(key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.readMap()
	if err != nil {
		return err
	}
	m[k.serviceName(key)] = value
	return k.writeMap(m)
}

func (k *KeychainVault) deleteFileSecret(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.readMap()
	if err != nil {
		return err
	}
	delete(m, k.serviceName(key))
	return k.writeMap(m)
}

// OnePasswordVault stores and reads master secrets via the official 1Password CLI (`op`),
// supporting TouchID / biometric unlock out of the box.
type OnePasswordVault struct {
	VaultName string // Optional 1Password vault name (defaults to $MINTRUN_OP_VAULT or "Private")
}

func NewOnePasswordVault() *OnePasswordVault {
	return &OnePasswordVault{VaultName: os.Getenv("MINTRUN_OP_VAULT")}
}

func (o *OnePasswordVault) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "1password",
		Version:     "0.2.0",
		Kind:        core.KindVault,
		Description: "1Password CLI (op) biometric vault (supports op:// URIs and mintrun:<provider> items)",
		Builtin:     true,
	}
}

func (o *OnePasswordVault) GetSecret(ctx context.Context, key string) (string, error) {
	if strings.HasPrefix(key, "op://") {
		out, err := exec.CommandContext(ctx, "op", "read", key).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("op read %q: %w (%s)", key, err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	args := []string{"item", "get", "mintrun:" + strings.ToLower(strings.TrimSpace(key)), "--fields", "label=credential", "--reveal"}
	if o.VaultName != "" {
		args = append(args, "--vault", o.VaultName)
	}
	out, err := exec.CommandContext(ctx, "op", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("op item get %q: %w (%s)", key, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (o *OnePasswordVault) SetSecret(ctx context.Context, key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("secret value cannot be empty")
	}
	title := "mintrun:" + strings.ToLower(strings.TrimSpace(key))
	args := []string{"item", "create", "--category", "Password", "--title", title, "credential=" + value}
	if o.VaultName != "" {
		args = append(args, "--vault", o.VaultName)
	}
	out, err := exec.CommandContext(ctx, "op", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("op item create %q: %w (%s)", title, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (o *OnePasswordVault) DeleteSecret(ctx context.Context, key string) error {
	title := "mintrun:" + strings.ToLower(strings.TrimSpace(key))
	args := []string{"item", "delete", title}
	if o.VaultName != "" {
		args = append(args, "--vault", o.VaultName)
	}
	out, err := exec.CommandContext(ctx, "op", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("op item delete %q: %w (%s)", title, err, strings.TrimSpace(string(out)))
	}
	return nil
}
