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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ninja-c9/mintrun/internal/core"
)

const keychainAccount = "mintrun"

// Swapped by tests: the macOS security(1) binary, and where keystore fallback warnings go.
var (
	securityPath           = "/usr/bin/security"
	warnOut      io.Writer = os.Stderr
)

// errNotFound marks a plain keystore miss, which falls back to the file vault quietly.
var errNotFound = errors.New("not found")

// maxSecurityLine is the longest command line `security -i` reads intact (a 4 KiB fgets buffer,
// newline included). Measured on macOS: a 4095-byte line stores the secret, while a 4097-byte
// line is split, stores a corrupted item, and exits 1.
const maxSecurityLine = 4095

// File-vault KDF parameters: the AES-256-GCM key is derived from the
// MINTRUN_VAULT_KEY passphrase and a per-vault random salt via PBKDF2-HMAC-SHA256.
const (
	vaultKDFIters = 210000
	vaultKDFName  = "pbkdf2-hmac-sha256"
	vaultSaltLen  = 16
)

// KeychainVault stores master secrets in macOS Keychain (`/usr/bin/security`) or Linux
// libsecret (`secret-tool`), with a fallback to an AES-256-GCM encrypted 0600 file vault
// (`~/.mintrun/vault.json`).
type KeychainVault struct {
	mu         sync.Mutex
	HomeDir    string
	ForceFile  bool   // Skip macOS Keychain (non-macOS hosts or deterministic unit tests)
	SecretTool string // Path to Linux libsecret `secret-tool`; empty disables it
}

func NewKeychainVault(homeDir string) *KeychainVault {
	k := &KeychainVault{
		HomeDir:   homeDir,
		ForceFile: runtime.GOOS != "darwin" || os.Getenv("MINTRUN_FILE_VAULT") == "1",
	}
	if runtime.GOOS == "linux" && os.Getenv("MINTRUN_FILE_VAULT") != "1" {
		// err != nil includes exec.ErrDot: never run a secret-tool found via a relative PATH entry.
		if p, err := exec.LookPath("secret-tool"); err == nil {
			k.SecretTool = p
		}
	}
	return k
}

func (k *KeychainVault) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "keychain",
		Version:     "0.5.0",
		Kind:        core.KindVault,
		Description: "OS native secret vault (macOS Keychain via /usr/bin/security, Linux libsecret via secret-tool, AES-256-GCM 0600 fallback)",
		Builtin:     true,
	}
}

func (k *KeychainVault) serviceName(key string) string {
	return "mintrun:" + strings.TrimSpace(strings.ToLower(key))
}

// secretTool runs Linux libsecret `secret-tool` against this key's attributes. The secret only
// travels on stdin (store) or stdout (lookup), never argv, so it cannot leak via `ps` (audit M5).
func (k *KeychainVault) secretTool(ctx context.Context, stdin, action, key string, extra ...string) (string, error) {
	args := append(append([]string{action}, extra...), "service", k.serviceName(key), "account", keychainAccount)
	cmd := exec.CommandContext(ctx, k.SecretTool, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if action != "store" && errors.As(err, &exitErr) && errOut.Len() == 0 {
		err = errNotFound // secret-tool reports a miss as a bare exit 1; real failures print a reason
	}
	return strings.TrimSpace(out.String()), err
}

// security runs macOS security(1); exit 44 (errSecItemNotFound) is a plain miss. Its stderr is
// returned for `-g` parsing only, never put in an error: it can hold the secret.
func (k *KeychainVault) security(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, securityPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
		err = errNotFound
	}
	return errOut.String(), err
}

// keychainGet reads with -g, not -w: -w hex-dumps any value holding a newline or a non-ASCII
// byte. -g prints `password: "<raw>"`, or `password: 0x<HEX>  "<escaped>"` for such values.
func (k *KeychainVault) keychainGet(ctx context.Context, key string) (string, error) {
	errOut, err := k.security(ctx, "", "find-generic-password", "-a", keychainAccount, "-s", k.serviceName(key), "-g")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(errOut, "\n") {
		rest, ok := strings.CutPrefix(line, "password: ")
		if !ok {
			continue
		}
		var val string
		if h, ok := strings.CutPrefix(rest, "0x"); ok {
			h, _, _ = strings.Cut(h, " ")
			b, err := hex.DecodeString(h)
			if err != nil {
				return "", errors.New("unparseable Keychain password line") // never wrap: the hex error quotes secret bytes
			}
			val = string(b)
		} else if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
			val = rest[1 : len(rest)-1]
		}
		if val = strings.TrimSpace(val); val == "" {
			return "", errNotFound
		}
		return val, nil
	}
	return "", errors.New("security printed no password line")
}

// keychainSet stores via `security -i` so argv is only `-i` (audit M5): the command, with the
// secret hex-encoded for -X, travels on stdin. A line `security -i` would split is refused
// before anything is sent, since a split line stores a corrupted item.
func (k *KeychainVault) keychainSet(ctx context.Context, key, value string) error {
	svc := k.serviceName(key)
	if strings.ContainsFunc(svc, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '"' || r == '\\' }) {
		return fmt.Errorf("service name %q cannot be quoted for `security -i`", svc)
	}
	line := fmt.Sprintf("add-generic-password -U -a %s -s \"%s\" -X %s\n", keychainAccount, svc, hex.EncodeToString([]byte(value)))
	if len(line) > maxSecurityLine {
		// ponytail: hex doubles the size, so the ceiling is ~2 KB and a GCP service-account JSON
		// lands in the file vault. Split the secret over several items if it must stay in Keychain.
		return fmt.Errorf("secret is %d bytes, too long for `security -i` (max ~2 KB)", len(value))
	}
	_, err := k.security(ctx, line, "-i")
	return err
}

// warnFallback reports a keystore failure before the file vault takes over (audit M7). A plain
// miss stays quiet, and only the error is printed, never the secret or the helper's stderr.
func warnFallback(store, op, key string, err error) {
	if err != nil && !errors.Is(err, errNotFound) {
		fmt.Fprintf(warnOut, "mintrun: warning: %s %s for %q failed (%v); using the encrypted file vault\n", store, op, key, err)
	}
}

func (k *KeychainVault) GetSecret(ctx context.Context, key string) (string, error) {
	if k.SecretTool != "" {
		val, err := k.secretTool(ctx, "", "lookup", key)
		if err == nil && val != "" {
			return val, nil
		}
		warnFallback("libsecret", "lookup", key, err)
	}
	if !k.ForceFile {
		val, err := k.keychainGet(ctx, key)
		if err == nil {
			return val, nil
		}
		warnFallback("macOS Keychain", "lookup", key, err)
	}
	return k.getFileSecret(key)
}

func (k *KeychainVault) SetSecret(ctx context.Context, key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("secret value cannot be empty")
	}
	if k.SecretTool != "" {
		_, err := k.secretTool(ctx, value, "store", key, "--label="+k.serviceName(key))
		if err == nil {
			return nil
		}
		warnFallback("libsecret", "store", key, err)
	}
	if !k.ForceFile {
		err := k.keychainSet(ctx, key, value)
		if err == nil {
			return nil
		}
		warnFallback("macOS Keychain", "store", key, err)
	}
	return k.setFileSecret(key, value)
}

// DeleteSecret removes the key from every store. A store that does not hold it is fine; any
// other failure is reported, so a secret is never silently left behind.
func (k *KeychainVault) DeleteSecret(ctx context.Context, key string) error {
	var errs []error
	if k.SecretTool != "" {
		if _, err := k.secretTool(ctx, "", "clear", key); err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, fmt.Errorf("libsecret clear: %w", err))
		}
	}
	if !k.ForceFile {
		if _, err := k.security(ctx, "", "delete-generic-password", "-a", keychainAccount, "-s", k.serviceName(key)); err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, fmt.Errorf("macOS Keychain delete: %w", err))
		}
	}
	return errors.Join(append(errs, k.deleteFileSecret(key))...)
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
	if _, ok := m[k.serviceName(key)]; !ok {
		return nil // nothing to delete: don't (re-)write a vault, which would demand MINTRUN_VAULT_KEY
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
