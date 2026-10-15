package builtin

import (
	"bytes"
	"context"
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

// KeychainVault stores master secrets in macOS Keychain (`/usr/bin/security`)
// with a fallback to a 0600 file vault (`~/.mintrun/vault.json`) on non-darwin or test environments.
type KeychainVault struct {
	mu       sync.Mutex
	HomeDir  string
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
		Version:     "0.1.0",
		Kind:        core.KindVault,
		Description: "OS native secret vault (macOS Keychain via /usr/bin/security with 0600 local fallback)",
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
	if m == nil {
		m = make(map[string]string)
	}
	return m, nil
}

func (k *KeychainVault) writeMap(m map[string]string) error {
	if err := os.MkdirAll(k.HomeDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(k.vaultFilePath(), raw, 0o600)
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

