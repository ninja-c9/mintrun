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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// ErrSecretNotFound is what KeychainVault.GetSecret wraps when no store holds the key, as
// opposed to a store that could not be read.
var ErrSecretNotFound = errors.New("not found in vault")

// maxSecurityLine is the longest command line `security -i` reads intact (a 4 KiB fgets buffer,
// newline included). Measured on macOS: a 4095-byte line stores the secret, while a 4097-byte
// line is split, stores a corrupted item, and exits 1.
const maxSecurityLine = 4095

// A secret one `security -i` line cannot carry (hex doubles it, so about 2 KB) is split into part
// items of chunkSize bytes under a fresh random generation. The key's own item then holds a header,
// chunkPrefix + "<generation>:<parts>:<sha256 hex>", written last, so a read assembles the old
// secret or the new one, never a mix: parts are only created and removed, never rewritten.
const (
	chunkPrefix = "mintrun-chunks:v1:"
	chunkSize   = 1500
	maxChunks   = 16
)

var errLineTooLong = errors.New("too long for `security -i`")

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

// keychainRead returns one item's exact value. It reads with -g, not -w: -w hex-dumps any value
// holding a newline or a non-ASCII byte. -g prints `password: "<raw>"`, or
// `password: 0x<HEX>  "<escaped>"` for such values.
func (k *KeychainVault) keychainRead(ctx context.Context, svc string) (string, error) {
	errOut, err := k.security(ctx, "", "find-generic-password", "-a", keychainAccount, "-s", svc, "-g")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(errOut, "\n") {
		rest, ok := strings.CutPrefix(line, "password: ")
		if !ok {
			continue
		}
		if h, ok := strings.CutPrefix(rest, "0x"); ok {
			h, _, _ = strings.Cut(h, " ")
			b, err := hex.DecodeString(h)
			if err != nil {
				return "", errors.New("unparseable Keychain password line") // never wrap: the hex error quotes secret bytes
			}
			return string(b), nil
		}
		if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
			return rest[1 : len(rest)-1], nil
		}
		return "", nil
	}
	return "", errors.New("security printed no password line")
}

func (k *KeychainVault) keychainGet(ctx context.Context, key string) (string, error) {
	svc := k.serviceName(key)
	val, err := k.keychainRead(ctx, svc)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(val, chunkPrefix) {
		gen, n, sum, ok := parseChunkHeader(val)
		if !ok {
			return "", errors.New("unparseable Keychain chunk header")
		}
		var b strings.Builder
		for i := range n {
			part, err := k.keychainRead(ctx, partService(svc, gen, i))
			if err != nil {
				return "", fmt.Errorf("Keychain part %d of %d: %v", i+1, n, err) // %v: a missing part is no quiet miss
			}
			b.WriteString(part)
		}
		if fmt.Sprintf("%x", sha256.Sum256([]byte(b.String()))) != sum {
			return "", errors.New("Keychain parts do not match their checksum")
		}
		return b.String(), nil
	}
	if val = strings.TrimSpace(val); val == "" {
		return "", errNotFound
	}
	return val, nil
}

// keychainWrite stores one item via `security -i` so argv is only `-i` (audit M5): the command,
// with the value hex-encoded for -X, travels on stdin. A line `security -i` would split is refused
// before anything is sent, since a split line stores a corrupted item.
func (k *KeychainVault) keychainWrite(ctx context.Context, svc, value string) error {
	line := fmt.Sprintf("add-generic-password -U -a %s -s \"%s\" -X %s\n", keychainAccount, svc, hex.EncodeToString([]byte(value)))
	if len(line) > maxSecurityLine {
		return errLineTooLong
	}
	_, err := k.security(ctx, line, "-i")
	return err
}

// keychainSet stores a secret as one item, or as parts behind a header when one line cannot carry
// it (or it would read back as a header), then removes the parts of the value it replaced.
func (k *KeychainVault) keychainSet(ctx context.Context, key, value string) error {
	svc := k.serviceName(key)
	if strings.ContainsFunc(svc, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '"' || r == '\\' }) {
		return fmt.Errorf("service name %q cannot be quoted for `security -i`", svc)
	}
	old, _ := k.keychainRead(ctx, svc) // best effort: names the parts to remove once the new value is in
	err := errLineTooLong
	if !strings.HasPrefix(value, chunkPrefix) {
		err = k.keychainWrite(ctx, svc, value)
	}
	if errors.Is(err, errLineTooLong) {
		err = k.keychainSetParts(ctx, svc, value)
	}
	if err != nil {
		return err
	}
	if gen, n, _, ok := parseChunkHeader(old); ok {
		if err := k.deleteParts(ctx, svc, gen, n); err != nil {
			fmt.Fprintf(warnOut, "mintrun: warning: removing the replaced Keychain parts for %q failed (%v)\n", key, err)
		}
	}
	return nil
}

// keychainSetParts writes value's parts under a fresh generation, then the header naming them. Until
// the header lands a read still sees the old value, and a failure removes the parts written so far.
func (k *KeychainVault) keychainSetParts(ctx context.Context, svc, value string) error {
	n := (len(value) + chunkSize - 1) / chunkSize
	if n > maxChunks {
		return fmt.Errorf("secret is %d bytes, too long for the Keychain (max %d)", len(value), maxChunks*chunkSize)
	}
	gen := rand.Text()
	var err error
	for i := 0; i < n && err == nil; i++ {
		err = k.keychainWrite(ctx, partService(svc, gen, i), value[i*chunkSize:min((i+1)*chunkSize, len(value))])
	}
	if err == nil {
		err = k.keychainWrite(ctx, svc, fmt.Sprintf("%s%s:%d:%x", chunkPrefix, gen, n, sha256.Sum256([]byte(value))))
	}
	if err != nil {
		_ = k.deleteParts(ctx, svc, gen, n)
	}
	return err
}

// partService names part i of generation gen; the random generation keeps it apart from every other item.
func partService(svc, gen string, i int) string {
	return fmt.Sprintf("%s:%s.%d", svc, gen, i)
}

// parseChunkHeader splits a header into its generation, part count and SHA-256 hex.
func parseChunkHeader(v string) (gen string, n int, sum string, ok bool) {
	f := strings.Split(strings.TrimPrefix(v, chunkPrefix), ":")
	if !strings.HasPrefix(v, chunkPrefix) || len(f) != 3 || f[0] == "" {
		return "", 0, "", false
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 1 || n > maxChunks {
		return "", 0, "", false
	}
	return f[0], n, f[2], true
}

// deleteParts removes the n parts of generation gen; a part already gone is fine.
func (k *KeychainVault) deleteParts(ctx context.Context, svc, gen string, n int) error {
	var errs []error
	for i := range n {
		if _, err := k.security(ctx, "", "delete-generic-password", "-a", keychainAccount, "-s", partService(svc, gen, i)); err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
			k.dropFileCopy(key)
			return nil
		}
		warnFallback("libsecret", "store", key, err)
	}
	if !k.ForceFile {
		err := k.keychainSet(ctx, key, value)
		if err == nil {
			k.dropFileCopy(key)
			return nil
		}
		warnFallback("macOS Keychain", "store", key, err)
	}
	if err := k.setFileSecret(key, value); err != nil {
		return err
	}
	// GetSecret reads the keystores first, so an older item left in one that failed to store the
	// new value would shadow it: remove that item, or report that it still wins.
	if err := k.deleteKeystores(ctx, key); err != nil {
		return fmt.Errorf("stored %q in the encrypted file vault, but removing an older keystore item for it failed (%v); while that item exists, it takes precedence on read", key, err)
	}
	return nil
}

// dropFileCopy removes an older file-vault copy of a key a keystore now holds: GetSecret falls
// back to it when a keystore lookup fails. The store already succeeded, so a copy that cannot be
// removed (no MINTRUN_VAULT_KEY to decrypt vault.json) only warns.
func (k *KeychainVault) dropFileCopy(key string) {
	if err := k.deleteFileSecret(key); err != nil {
		fmt.Fprintf(warnOut, "mintrun: warning: stored %q in the OS keystore, but an older copy may remain in the encrypted file vault (%v); a failed keystore lookup falls back to it\n", key, err)
	}
}

// DeleteSecret removes the key from every store. A store that does not hold it is fine; any
// other failure is reported, so a secret is never silently left behind.
func (k *KeychainVault) DeleteSecret(ctx context.Context, key string) error {
	return errors.Join(k.deleteKeystores(ctx, key), k.deleteFileSecret(key))
}

// deleteKeystores removes the key from libsecret and the macOS Keychain: the item, and the parts
// its header names. A keystore that does not hold the key is fine.
func (k *KeychainVault) deleteKeystores(ctx context.Context, key string) error {
	var errs []error
	if k.SecretTool != "" {
		if _, err := k.secretTool(ctx, "", "clear", key); err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, fmt.Errorf("libsecret clear: %w", err))
		}
	}
	if !k.ForceFile {
		svc := k.serviceName(key)
		head, _ := k.keychainRead(ctx, svc)
		if _, err := k.security(ctx, "", "delete-generic-password", "-a", keychainAccount, "-s", svc); err != nil && !errors.Is(err, errNotFound) {
			errs = append(errs, fmt.Errorf("macOS Keychain delete: %w", err))
		}
		if gen, n, _, ok := parseChunkHeader(head); ok {
			if err := k.deleteParts(ctx, svc, gen, n); err != nil {
				errs = append(errs, fmt.Errorf("macOS Keychain delete: %w", err))
			}
		}
	}
	return errors.Join(errs...)
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
		// Keep only the cause: the path names the home, and the text reaches agents (rule 36).
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("read vault.json: %v", err)
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
	return WriteFileAtomic(k.vaultFilePath(), raw, 0o600)
}

// WriteFileAtomic writes to a temp file in the same directory, fsyncs it, then
// renames over path, so a crash mid-write never leaves a truncated file (audit L3).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
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
		return "", fmt.Errorf("secret %q %w (run %s)", key, ErrSecretNotFound, setupHint(key))
	}
	return v, nil
}

// setupHint names the command that stores key: the mintrun init step for a key init sets up
// (initSteps in cmd/mintrun/setup.go), otherwise mintrun secret set. It folds case and space as
// serviceName does.
func setupHint(key string) string {
	switch k := strings.TrimSpace(strings.ToLower(key)); k {
	case "github", "aws", "gcp", "cloudflare":
		return "mintrun init " + k
	case TelegramApprovalKey:
		return "mintrun init telegram"
	case SlackApprovalKey:
		return "mintrun init slack"
	default:
		return "mintrun secret set " + k
	}
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

// run runs the 1Password CLI and returns its trimmed stdout. A failure quotes only op's stderr,
// with secrets scrubbed from it: stdout can hold a secret.
func (o *OnePasswordVault) run(ctx context.Context, stdin []byte, secrets []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "op", args...) // refuses an op found via a relative PATH entry (exec.ErrDot)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New(core.Scrub(fmt.Sprintf("op %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(errOut.String())), secrets))
	}
	return bytes.TrimSpace(out), nil
}

func (o *OnePasswordVault) GetSecret(ctx context.Context, key string) (string, error) {
	args := []string{"read", key}
	if !strings.HasPrefix(key, "op://") {
		args = []string{"item", "get", "mintrun:" + strings.ToLower(strings.TrimSpace(key)), "--fields", "label=credential", "--reveal"}
		if o.VaultName != "" {
			args = append(args, "--vault", o.VaultName)
		}
	}
	out, err := o.run(ctx, nil, nil, args...)
	return string(out), err
}

// SetSecret pipes an item template to `op item create -`, so the secret travels on stdin, never
// argv (rule 14). op adds a new item on every call, so older items with the same title are then
// archived: `op item get` refuses an ambiguous title.
func (o *OnePasswordVault) SetSecret(ctx context.Context, key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("secret value cannot be empty")
	}
	title := "mintrun:" + strings.ToLower(strings.TrimSpace(key))
	tmpl, err := json.Marshal(map[string]any{
		"title":    title,
		"category": "PASSWORD",
		"fields":   []map[string]string{{"id": "credential", "label": "credential", "type": "CONCEALED", "value": value}},
	})
	if err != nil {
		return err
	}
	esc, _ := json.Marshal(value) // the template's escaped form, in case op quotes it back
	args := []string{"item", "create", "--format", "json"}
	if o.VaultName != "" {
		args = append(args, "--vault", o.VaultName)
	}
	out, err := o.run(ctx, tmpl, []string{value, string(esc[1 : len(esc)-1])}, append(args, "-")...)
	if err != nil {
		return err
	}
	if err := o.archiveOlder(ctx, title, out); err != nil {
		fmt.Fprintf(warnOut, "mintrun: warning: stored %q, but archiving older 1Password items with that title failed (%v); reads fail while more than one exists\n", title, err)
	}
	return nil
}

// archiveOlder archives every other item titled title in the vault op just created the new item in.
// created is op's JSON for the new item; it can hold the secret, so it is never quoted.
func (o *OnePasswordVault) archiveOlder(ctx context.Context, title string, created []byte) error {
	var item struct {
		ID    string
		Vault struct{ ID string }
	}
	if json.Unmarshal(created, &item) != nil || item.ID == "" || item.Vault.ID == "" {
		return errors.New("op printed no item and vault ID")
	}
	out, err := o.run(ctx, nil, nil, "item", "list", "--vault", item.Vault.ID, "--format", "json")
	if err != nil {
		return err
	}
	var items []struct{ ID, Title string }
	if json.Unmarshal(out, &items) != nil {
		return errors.New("op item list printed invalid JSON")
	}
	for _, it := range items {
		if it.Title == title && it.ID != item.ID {
			if _, err := o.run(ctx, nil, nil, "item", "delete", it.ID, "--archive", "--vault", item.Vault.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *OnePasswordVault) DeleteSecret(ctx context.Context, key string) error {
	args := []string{"item", "delete", "mintrun:" + strings.ToLower(strings.TrimSpace(key))}
	if o.VaultName != "" {
		args = append(args, "--vault", o.VaultName)
	}
	_, err := o.run(ctx, nil, nil, args...)
	return err
}
