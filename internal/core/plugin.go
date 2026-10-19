package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind identifies what role a plugin plays in the mintrun runtime.
type Kind string

const (
	KindVault    Kind = "vault"    // Stores/retrieves master secrets (e.g. macOS Keychain, 1Password)
	KindProvider Kind = "provider" // Mints/revokes JIT ephemeral leases from a master secret (e.g. Cloudflare, GitHub)
	KindBridge   Kind = "bridge"   // Exposes mintrun to agent harnesses (e.g. MCP stdio server)
)

// Manifest describes a plugin's metadata, capabilities, and marketplace provenance.
type Manifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Kind        Kind     `json:"kind"`
	Description string   `json:"description"`
	Author      string   `json:"author,omitempty"`
	Entrypoint  string   `json:"entrypoint,omitempty"` // Relative binary/script path for external plugins
	Scopes      []string `json:"scopes,omitempty"`     // Supported scopes/permissions (e.g. "zone", "dns:write", "workers:write")
	Builtin     bool     `json:"builtin"`
}

// MintRequest is passed to a Provider plugin to issue a short-lived scoped credential.
type MintRequest struct {
	Provider    string            `json:"provider"`
	Scope       string            `json:"scope,omitempty"`       // e.g. domain/zone "example.com" or repo "owner/repo"
	Permissions []string          `json:"permissions,omitempty"` // e.g. ["dns:write", "workers:write"]
	TTLSeconds  int               `json:"ttl_seconds,omitempty"` // Default: 600 (10 minutes)
	Params      map[string]string `json:"params,omitempty"`
}

// Lease represents an ephemeral credential issued by a Provider plugin.
// Raw secret values in Env and Redact never leave the host runtime into agent context.
type Lease struct {
	ID        string            `json:"id"`
	Provider  string            `json:"provider"`
	Scope     string            `json:"scope,omitempty"`
	Env       map[string]string `json:"env"`    // Injected into blind child process (e.g. CLOUDFLARE_API_TOKEN=...)
	Redact    []string          `json:"redact"` // Sensitive strings to scrub from stdout/stderr
	ExpiresAt time.Time         `json:"expires_at"`
	Ephemeral bool              `json:"ephemeral"` // True if dynamically minted and revocable
	// RevokeSecret is a provider-private credential needed only by Revoke (e.g. a GitHub installation token).
	// Never serialized (audit, MCP, plugin RPC) and always scrubbed; ID must stay a non-secret handle.
	RevokeSecret string `json:"-"`
}

// Plugin is the universal contract for all mintrun plugins.
type Plugin interface {
	Manifest() Manifest
}

// VaultPlugin stores and retrieves master credentials outside agent reach.
type VaultPlugin interface {
	Plugin
	GetSecret(ctx context.Context, key string) (string, error)
	SetSecret(ctx context.Context, key, value string) error
	DeleteSecret(ctx context.Context, key string) error
}

// ProviderPlugin mints and revokes short-lived scoped credentials using a master secret.
type ProviderPlugin interface {
	Plugin
	Mint(ctx context.Context, masterSecret string, req MintRequest) (*Lease, error)
	Revoke(ctx context.Context, masterSecret string, lease *Lease) error
}

// BridgePlugin exposes the runtime to external AI agents (e.g. MCP over stdio).
type BridgePlugin interface {
	Plugin
	Serve(ctx context.Context, rt *Runtime, in io.Reader, out io.Writer) error
}

// Registry holds all loaded built-in and external plugins.
type Registry struct {
	mu        sync.RWMutex
	vaults    map[string]VaultPlugin
	providers map[string]ProviderPlugin
	bridges   map[string]BridgePlugin
}

func NewRegistry() *Registry {
	return &Registry{
		vaults:    make(map[string]VaultPlugin),
		providers: make(map[string]ProviderPlugin),
		bridges:   make(map[string]BridgePlugin),
	}
}

func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := p.Manifest()
	if m.Name == "" {
		return errors.New("plugin manifest missing name")
	}
	// An external plugin must never shadow a built-in of the same name (audit H5).
	if !m.Builtin {
		if ex, ok := r.vaults[m.Name]; ok && ex.Manifest().Builtin {
			return fmt.Errorf("plugin %q cannot override the built-in vault of the same name", m.Name)
		}
		if ex, ok := r.providers[m.Name]; ok && ex.Manifest().Builtin {
			return fmt.Errorf("plugin %q cannot override the built-in provider of the same name", m.Name)
		}
		if ex, ok := r.bridges[m.Name]; ok && ex.Manifest().Builtin {
			return fmt.Errorf("plugin %q cannot override the built-in bridge of the same name", m.Name)
		}
	}
	registered := false
	if v, ok := p.(VaultPlugin); ok && (m.Kind == "" || m.Kind == KindVault) {
		r.vaults[m.Name] = v
		registered = true
	}
	if pr, ok := p.(ProviderPlugin); ok && (m.Kind == "" || m.Kind == KindProvider) {
		r.providers[m.Name] = pr
		registered = true
	}
	if b, ok := p.(BridgePlugin); ok && (m.Kind == "" || m.Kind == KindBridge) {
		r.bridges[m.Name] = b
		registered = true
	}
	if !registered {
		return fmt.Errorf("plugin %q (kind=%s) does not implement its kind interface", m.Name, m.Kind)
	}
	return nil
}

func (r *Registry) Vault(name string) (VaultPlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.vaults[name]
	if !ok {
		return nil, fmt.Errorf("vault plugin %q not found", name)
	}
	return v, nil
}

func (r *Registry) Provider(name string) (ProviderPlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider plugin %q not found", name)
	}
	return p, nil
}

func (r *Registry) Bridge(name string) (BridgePlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.bridges[name]
	if !ok {
		return nil, fmt.Errorf("bridge plugin %q not found", name)
	}
	return b, nil
}

func (r *Registry) Manifests() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []Manifest
	for _, v := range r.vaults {
		list = append(list, v.Manifest())
	}
	for _, p := range r.providers {
		list = append(list, p.Manifest())
	}
	for _, b := range r.bridges {
		list = append(list, b.Manifest())
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		return list[i].Name < list[j].Name
	})
	return list
}

// ExternalPlugin adapts any out-of-process executable into a VaultPlugin and ProviderPlugin
// over a simple JSON-over-stdio protocol. This allows plugins written in Go, Python, Rust,
// Node, or Bash to be installed dynamically without recompiling mintrun.
type ExternalPlugin struct {
	manifest Manifest
	execPath string
	home     string // the mintrun home, which quoted plugin text shows as $MINTRUN_HOME
}

type rpcRequest struct {
	Op           string       `json:"op"` // "get_secret", "set_secret", "delete_secret", "mint", "revoke"
	Key          string       `json:"key,omitempty"`
	Value        string       `json:"value,omitempty"`
	MasterSecret string       `json:"master_secret,omitempty"`
	MintReq      *MintRequest `json:"mint_request,omitempty"`
	Lease        *Lease       `json:"lease,omitempty"`
}

type rpcResponse struct {
	Value string `json:"value,omitempty"`
	Lease *Lease `json:"lease,omitempty"`
	Error string `json:"error,omitempty"`
}

func (e *ExternalPlugin) Manifest() Manifest { return e.manifest }

func (e *ExternalPlugin) call(ctx context.Context, req rpcRequest) (*rpcResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, e.execPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Keep only the cause of a failed start: the entrypoint's path names the home, and the
		// text reaches agents (rule 36).
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("plugin %q failed: %v (%s)", e.manifest.Name, err, e.quote(strings.TrimSpace(stderr.String()), req))
	}
	var resp rpcResponse
	if json.Unmarshal(stdout.Bytes(), &resp) != nil {
		// Never wrap the error: Go's JSON errors quote stdout, which can hold a secret Scrub does not know yet.
		return nil, fmt.Errorf("plugin %q returned an invalid JSON response", e.manifest.Name)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("plugin %q error: %s", e.manifest.Name, e.quote(resp.Error, req))
	}
	return &resp, nil
}

// quote returns text the plugin wrote (a traceback names its own path) fit for an error that
// reaches agents and audit.jsonl: scrubbed of the master first, because the runner scrubs only
// the whole master and a replaced home inside it would leak the rest, then through ShortHomes.
func (e *ExternalPlugin) quote(text string, req rpcRequest) string {
	return ShortHomes(Scrub(text, []string{req.MasterSecret}), e.home)
}

// ShortHomes shows the user's home in text as ~ and the mintrun home as $MINTRUN_HOME (rule 36).
// A relative or root home is left alone.
// ponytail: only the paths as given are replaced, so a resolved symlink or an escaped form
// (JSON's \u, Windows' \\) still gets through; match those if a plugin is seen printing them.
func ShortHomes(text, home string) string {
	userHome, _ := os.UserHomeDir()
	var oldnew []string
	for _, p := range [][2]string{{userHome, "~"}, {home, "$MINTRUN_HOME"}} { // ~ wins inside the user home
		if dir := filepath.Clean(p[0]); filepath.IsAbs(dir) && filepath.Dir(dir) != dir {
			oldnew = append(oldnew, dir, p[1])
		}
	}
	return strings.NewReplacer(oldnew...).Replace(text)
}

func (e *ExternalPlugin) GetSecret(ctx context.Context, key string) (string, error) {
	resp, err := e.call(ctx, rpcRequest{Op: "get_secret", Key: key})
	if err != nil {
		return "", err
	}
	return resp.Value, nil
}

func (e *ExternalPlugin) SetSecret(ctx context.Context, key, value string) error {
	_, err := e.call(ctx, rpcRequest{Op: "set_secret", Key: key, Value: value})
	return err
}

func (e *ExternalPlugin) DeleteSecret(ctx context.Context, key string) error {
	_, err := e.call(ctx, rpcRequest{Op: "delete_secret", Key: key})
	return err
}

func (e *ExternalPlugin) Mint(ctx context.Context, masterSecret string, req MintRequest) (*Lease, error) {
	resp, err := e.call(ctx, rpcRequest{Op: "mint", MasterSecret: masterSecret, MintReq: &req})
	if err != nil {
		return nil, err
	}
	if resp.Lease == nil {
		return nil, fmt.Errorf("plugin %q returned nil lease", e.manifest.Name)
	}
	return resp.Lease, nil
}

func (e *ExternalPlugin) Revoke(ctx context.Context, masterSecret string, lease *Lease) error {
	_, err := e.call(ctx, rpcRequest{Op: "revoke", MasterSecret: masterSecret, Lease: lease})
	return err
}

// LoadExternalPlugins discovers all installed plugins in `<homeDir>/plugins/*/plugin.json`.
func LoadExternalPlugins(pluginsDir string, reg *Registry) error {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(pluginsDir, entry.Name())
		p, err := loadPluginDir(dir)
		if err != nil {
			continue
		}
		p.home = filepath.Dir(filepath.Clean(pluginsDir))
		_ = reg.Register(p)
	}
	return nil
}

func loadPluginDir(dir string) (*ExternalPlugin, error) {
	manifestPath := filepath.Join(dir, "plugin.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m.Builtin = false
	if m.Entrypoint == "" {
		m.Entrypoint = "run"
	}
	execPath := filepath.Join(dir, filepath.Clean(m.Entrypoint))
	if !strings.HasPrefix(execPath, filepath.Clean(dir)+string(os.PathSeparator)) {
		return nil, errors.New("entrypoint escapes plugin directory")
	}
	return &ExternalPlugin{manifest: m, execPath: execPath}, nil
}

// safePluginName rejects a name that is not a single safe path segment, so a crafted
// manifest cannot escape the plugins directory on install/remove (audit C1).
func safePluginName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", errors.New("plugin name is empty")
	}
	if n == "." || n == ".." || n != filepath.Base(n) || strings.ContainsAny(n, `/\`) {
		return "", fmt.Errorf("plugin name %q must be a single path segment", name)
	}
	return n, nil
}

// InstallPlugin installs an external plugin from either a local directory or an HTTP(S) manifest URL.
func InstallPlugin(ctx context.Context, pluginsDir, source string) (Manifest, error) {
	if err := os.MkdirAll(pluginsDir, 0o700); err != nil {
		return Manifest{}, err
	}

	// Case 1: Remote URL pointing to a plugin manifest JSON with an embedded script or binary URL.
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return installRemotePlugin(ctx, pluginsDir, source)
	}

	// Case 2: Local directory containing plugin.json + entrypoint executable/script.
	srcInfo, err := os.Stat(source)
	if err != nil || !srcInfo.IsDir() {
		return Manifest{}, fmt.Errorf("plugin source %q must be a directory or https:// URL", source)
	}
	ext, err := loadPluginDir(source)
	if err != nil {
		return Manifest{}, fmt.Errorf("invalid plugin in %q: %w", source, err)
	}
	name, err := safePluginName(ext.manifest.Name)
	if err != nil {
		return Manifest{}, err
	}
	destDir := filepath.Join(pluginsDir, name)
	if err := os.RemoveAll(destDir); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return Manifest{}, err
	}
	items, err := os.ReadDir(source)
	if err != nil {
		return Manifest{}, err
	}
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(source, item.Name()))
		if err != nil {
			return Manifest{}, err
		}
		mode := os.FileMode(0o600)
		if item.Name() == ext.manifest.Entrypoint {
			mode = 0o700
		}
		if err := os.WriteFile(filepath.Join(destDir, item.Name()), data, mode); err != nil {
			return Manifest{}, err
		}
	}
	return ext.manifest, nil
}

type remoteBundle struct {
	Manifest
	Script string `json:"script,omitempty"` // Self-contained executable script body for lightweight plugins
	SHA256 string `json:"sha256,omitempty"` // Optional SHA-256 hex digest of Script for integrity verification
}

// isLoopbackURL reports whether raw points at the local host (localhost or a
// loopback IP), the one case where a plaintext http:// fetch cannot be MITM'd.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func installRemotePlugin(ctx context.Context, pluginsDir, rawURL string) (Manifest, error) {
	expectedHash := ""
	if base, frag, ok := strings.Cut(rawURL, "#sha256="); ok {
		rawURL, expectedHash = base, strings.ToLower(strings.TrimSpace(frag))
	}
	// Require https for any networked fetch (audit M6). Plaintext is tolerated only to
	// loopback, which cannot be MITM'd across a network; the mandatory digest below
	// still guarantees integrity in both cases.
	if !strings.HasPrefix(rawURL, "https://") && !isLoopbackURL(rawURL) {
		return Manifest{}, errors.New("remote plugin install requires an https:// URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Manifest{}, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("fetch plugin %s: HTTP %d", rawURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return Manifest{}, err
	}
	var bundle remoteBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return Manifest{}, err
	}
	if bundle.Name == "" || bundle.Script == "" {
		return Manifest{}, errors.New("remote plugin bundle requires name and script")
	}
	// The integrity digest must be supplied out-of-band via the URL (#sha256=<hex>); a digest
	// the bundle declares about itself is attacker-controlled and proves nothing (audit M6).
	if expectedHash == "" {
		return Manifest{}, errors.New("remote plugin install requires an out-of-band digest: append #sha256=<hex> to the URL")
	}
	sum := sha256.Sum256([]byte(bundle.Script))
	if actual := hex.EncodeToString(sum[:]); actual != expectedHash {
		return Manifest{}, fmt.Errorf("plugin %q SHA-256 mismatch: expected %s, got %s", bundle.Name, expectedHash, actual)
	}
	if bundle.Entrypoint == "" {
		bundle.Entrypoint = "run"
	}
	name, err := safePluginName(bundle.Name)
	if err != nil {
		return Manifest{}, err
	}
	bundle.Builtin = false // a remote bundle cannot declare itself built-in
	destDir := filepath.Join(pluginsDir, name)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return Manifest{}, err
	}
	manifestBytes, _ := json.MarshalIndent(bundle.Manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(destDir, "plugin.json"), manifestBytes, 0o600); err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(destDir, filepath.Base(bundle.Entrypoint)), []byte(bundle.Script), 0o700); err != nil {
		return Manifest{}, err
	}
	return bundle.Manifest, nil
}

func RemovePlugin(pluginsDir, name string) error {
	safe, err := safePluginName(name)
	if err != nil {
		return err
	}
	target := filepath.Join(pluginsDir, safe)
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("external plugin %q is not installed", name)
	}
	return os.RemoveAll(target)
}
