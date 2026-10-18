package builtin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// RelayDevice is one enrolled client device in <home>/relay/devices.json. The raw token is shown
// once on `mintrun relay device add` and never stored; only its lowercase SHA-256 hex is kept.
type RelayDevice struct {
	Name        string `json:"name"`
	TokenSHA256 string `json:"token_sha256"`
	CreatedAt   string `json:"created_at"`
}

func validDeviceName(name string) bool {
	if name == "" || len(name) > 64 || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func devicesFilePath(homeDir string) string {
	return filepath.Join(homeDir, "relay", "devices.json")
}

// ListRelayDevices reads <home>/relay/devices.json. Only a missing file means no devices; any
// other read error, a dangling symlink, unknown JSON fields, or an invalid entry fails closed
// without naming the filesystem path (rule 36).
func ListRelayDevices(homeDir string) ([]RelayDevice, error) {
	p := devicesFilePath(homeDir)
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("devices.json cannot be read (%v)", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var devs []RelayDevice
	if err := dec.Decode(&devs); err != nil {
		return nil, fmt.Errorf("devices.json is malformed (%v)", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("devices.json is malformed (trailing data)")
	}
	seen := make(map[string]bool, len(devs))
	for _, d := range devs {
		if !validDeviceName(d.Name) || !validHexSHA256(d.TokenSHA256) || seen[d.Name] {
			return nil, errors.New("devices.json is malformed (invalid device entry)")
		}
		seen[d.Name] = true
	}
	return devs, nil
}

func writeRelayDevices(homeDir string, devs []RelayDevice) error {
	dir := filepath.Join(homeDir, "relay")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	target := devicesFilePath(homeDir)
	if real, err := filepath.EvalSymlinks(target); err == nil {
		target = real
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	out, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(target, append(out, '\n'), 0o600)
}

// AddRelayDevice enrolls a new device in <home>/relay/devices.json and returns its one-time
// bearer token alongside the stored record.
func AddRelayDevice(homeDir, name string) (string, RelayDevice, error) {
	if !validDeviceName(name) {
		return "", RelayDevice{}, fmt.Errorf("invalid device name %q (use 1..64 ASCII letters, digits, '.', '_', or '-')", name)
	}
	devs, err := ListRelayDevices(homeDir)
	if err != nil {
		return "", RelayDevice{}, err
	}
	for _, d := range devs {
		if d.Name == name {
			return "", RelayDevice{}, fmt.Errorf("relay device %q already exists", name)
		}
	}
	token := "mr_dev_" + rand.Text()
	sum := sha256.Sum256([]byte(token))
	dev := RelayDevice{
		Name:        name,
		TokenSHA256: hex.EncodeToString(sum[:]),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	devs = append(devs, dev)
	if err := writeRelayDevices(homeDir, devs); err != nil {
		return "", RelayDevice{}, err
	}
	return token, dev, nil
}

// RemoveRelayDevice removes name from <home>/relay/devices.json.
func RemoveRelayDevice(homeDir, name string) error {
	if !validDeviceName(name) {
		return fmt.Errorf("invalid device name %q", name)
	}
	devs, err := ListRelayDevices(homeDir)
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(devs, func(d RelayDevice) bool { return d.Name == name })
	if idx < 0 {
		return fmt.Errorf("relay device %q not found", name)
	}
	devs = slices.Delete(devs, idx, idx+1)
	return writeRelayDevices(homeDir, devs)
}

// RelaySPKIPin returns the lowercase hex SHA-256 digest of a DER certificate's SubjectPublicKeyInfo.
func RelaySPKIPin(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

// RelayCertPin parses the first CERTIFICATE PEM block in certPEM and returns its SPKI SHA-256 hex digest.
func RelayCertPin(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no CERTIFICATE PEM block found")
	}
	return RelaySPKIPin(block.Bytes)
}

// ParseRelayURL parses an https://<host>[:port]#sha256=<64-hex> relay URL into its base URL and
// 32-byte SPKI SHA-256 pin. Plain HTTP, userinfo, query strings, or a missing/invalid pin are refused.
func ParseRelayURL(raw string) (string, [32]byte, error) {
	var pin [32]byte
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" {
		return "", pin, errors.New("relay URL must be https://<host>[:port]#sha256=<64-hex-chars>")
	}
	hexPin, ok := strings.CutPrefix(u.Fragment, "sha256=")
	if !ok || len(hexPin) != 64 {
		return "", pin, errors.New("relay URL requires #sha256=<64-hex-chars> SPKI pin")
	}
	b, err := hex.DecodeString(hexPin)
	if err != nil {
		return "", pin, errors.New("relay URL requires #sha256=<64-hex-chars> SPKI pin")
	}
	copy(pin[:], b)
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), pin, nil
}

// RelayTLSConfig builds the client TLS 1.3 config pinned to spkiPin.
func RelayTLSConfig(spkiPin [32]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // verified against spkiPin and validity window in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || len(cs.PeerCertificates) == 0 {
				return errors.New("relay requires TLS 1.3 with a server certificate")
			}
			leaf := cs.PeerCertificates[0]
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("relay certificate is expired or not yet valid")
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], spkiPin[:]) != 1 {
				return fmt.Errorf("relay certificate SPKI sha256 %x does not match pinned %x", sum, spkiPin)
			}
			return nil
		},
	}
}

const (
	DefaultRelayRatePerMinute       = 300
	DefaultRelayBurst               = 60
	DefaultMaxActiveLeasesPerDevice = 32
)

// The errors of the two 429 replies, which RelayClient tells apart.
const (
	relayRateLimitError = "rate limit exceeded"
	relayLeaseCapError  = "too many active leases for device"
)

type activeRelayLease struct {
	device string
	timer  *time.Timer
	finish func(outcome string, exitCode int, truncated bool) core.AuditEntry
}

type relayBucket struct {
	tokens float64
	last   time.Time
}

// RelayServer serves /v1/check, /v1/mint, and /v1/revoke over HTTPS. Master secrets and
// Lease.RevokeSecret stay on the server; laptops authenticate with per-device bearer tokens and
// receive only ephemeral leases.
type RelayServer struct {
	rt         *core.Runtime
	mu         sync.Mutex
	leases     map[string]*activeRelayLease
	buckets    map[string]*relayBucket
	minting    map[string]int // mints in flight per device, counted against MaxLeases
	RatePerMin int
	Burst      int
	MaxLeases  int
	Now        func() time.Time
}

// NewRelayServer configures rt as a headless relay server (Telegram and Slack approval only, never
// a local GUI dialog) and returns an HTTP handler for the /v1/* endpoints.
func NewRelayServer(rt *core.Runtime) *RelayServer {
	rt.Relay = nil
	rt.RelayServer = true
	rt.ApprovalFunc = core.FirstApproval(TelegramApproval(rt), SlackApproval(rt))
	return &RelayServer{
		rt:         rt,
		leases:     make(map[string]*activeRelayLease),
		buckets:    make(map[string]*relayBucket),
		minting:    make(map[string]int),
		RatePerMin: DefaultRelayRatePerMinute,
		Burst:      DefaultRelayBurst,
		MaxLeases:  DefaultMaxActiveLeasesPerDevice,
		Now:        time.Now,
	}
}

func (s *RelayServer) allowDevice(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RatePerMin <= 0 || s.Burst <= 0 {
		return true
	}
	now := s.Now()
	b := s.buckets[name]
	if b == nil {
		b = &relayBucket{tokens: float64(s.Burst), last: now}
		s.buckets[name] = b
	} else if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(float64(s.Burst), b.tokens+dt*(float64(s.RatePerMin)/60.0))
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// reserveLease takes one of name's MaxLeases slots under the same lock that counts them, so
// concurrent mints cannot all pass the cap before any of them stores its lease. The /v1/mint
// handler gives the slot back under s.mu when MintLease returns, storing the lease in its place.
func (s *RelayServer) reserveLease(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MaxLeases > 0 {
		n := s.minting[name]
		for _, al := range s.leases {
			if al.device == name {
				n++
			}
		}
		if n >= s.MaxLeases {
			return false
		}
	}
	s.minting[name]++
	return true
}

// Close stops all expiry timers and revokes and audits any still-open leases as "unreported".
func (s *RelayServer) Close() {
	s.mu.Lock()
	pending := make([]*activeRelayLease, 0, len(s.leases))
	for id, al := range s.leases {
		al.timer.Stop()
		pending = append(pending, al)
		delete(s.leases, id)
	}
	s.mu.Unlock()
	for _, al := range pending {
		al.finish("unreported", -1, false)
	}
}

func (s *RelayServer) expireLease(leaseID string) {
	s.mu.Lock()
	al := s.leases[leaseID]
	delete(s.leases, leaseID)
	s.mu.Unlock()
	if al != nil {
		al.finish("unreported", -1, false)
	}
}

func (s *RelayServer) authenticate(r *http.Request) (RelayDevice, error) {
	auth := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "Bearer ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return RelayDevice{}, errors.New("missing bearer token")
	}
	devs, err := ListRelayDevices(s.rt.HomeDir)
	if err != nil || len(devs) == 0 {
		return RelayDevice{}, errors.New("no devices enrolled")
	}
	sum := sha256.Sum256([]byte(token))
	want := []byte(hex.EncodeToString(sum[:]))
	var matched RelayDevice
	found := 0
	for _, d := range devs {
		if subtle.ConstantTimeCompare([]byte(d.TokenSHA256), want) == 1 {
			matched = d
			found = 1
		}
	}
	if found != 1 {
		return RelayDevice{}, errors.New("invalid device token")
	}
	return matched, nil
}

type relayMintResponse struct {
	Lease     *core.Lease          `json:"lease,omitempty"`
	Decision  core.PolicyDecision  `json:"decision,omitempty"`
	DecidedAt string               `json:"decided_at,omitempty"`
	Deny      *core.RelayDenyError `json:"deny,omitempty"`
	Error     string               `json:"error,omitempty"`
}

type relayRevokeRequest struct {
	LeaseID   string `json:"lease_id"`
	Outcome   string `json:"outcome"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated,omitempty"`
}

type relayRevokeResponse struct {
	Revoked bool   `json:"revoked"`
	Error   string `json:"error,omitempty"`
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *RelayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	dev, err := s.authenticate(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// A revoke spends no token: it ends a lease a rate-limited mint handed out, and refusing it
	// would leave the lease live until its timer revokes it as "unreported".
	if r.URL.Path != "/v1/revoke" && !s.allowDevice(dev.Name) {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": relayRateLimitError})
		return
	}

	switch r.URL.Path {
	case "/v1/check":
		var req core.ExecRequest
		if err := decodeStrictJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		req.FromAgent, req.Device, req.Via = true, dev.Name, "relay"
		writeJSON(w, http.StatusOK, s.rt.CheckPolicy(req))

	case "/v1/mint":
		var req core.ExecRequest
		if err := decodeStrictJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, relayMintResponse{Error: "invalid request body"})
			return
		}
		if !s.reserveLease(dev.Name) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, relayMintResponse{Error: relayLeaseCapError})
			return
		}
		req.FromAgent, req.Device, req.Via = true, dev.Name, "relay"
		lease, d, entry, finish, err := s.rt.MintLease(r.Context(), req)
		s.mu.Lock()
		s.minting[dev.Name]-- // the reserved slot is freed, or taken by the lease stored below
		if err != nil {
			s.mu.Unlock()
			var rdeny *core.RelayDenyError
			if errors.As(err, &rdeny) {
				writeJSON(w, http.StatusForbidden, relayMintResponse{Deny: rdeny, Error: rdeny.Reason})
				return
			}
			writeJSON(w, http.StatusBadGateway, relayMintResponse{Error: err.Error()})
			return
		}
		ttl := time.Until(lease.ExpiresAt)
		if ttl <= 0 {
			ttl = time.Duration(d.TTLSeconds) * time.Second
		}
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		clientLease := *lease
		if s.leases[clientLease.ID] != nil {
			clientLease.ID = lease.ID + "-" + entry.Task
		}
		al := &activeRelayLease{
			device: dev.Name,
			finish: finish,
		}
		al.timer = time.AfterFunc(ttl, func() { s.expireLease(clientLease.ID) })
		s.leases[clientLease.ID] = al
		s.mu.Unlock()

		writeJSON(w, http.StatusOK, relayMintResponse{
			Lease:     &clientLease,
			Decision:  d,
			DecidedAt: entry.DecidedAt,
		})

	case "/v1/revoke":
		var req relayRevokeRequest
		if err := decodeStrictJSON(w, r, &req); err != nil || req.LeaseID == "" ||
			!slices.Contains([]string{"done", "failed", "stopped", "interrupted", "timed_out"}, req.Outcome) {
			writeJSON(w, http.StatusBadRequest, relayRevokeResponse{Error: "invalid revoke request"})
			return
		}
		s.mu.Lock()
		al := s.leases[req.LeaseID]
		if al == nil || al.device != dev.Name {
			s.mu.Unlock()
			writeJSON(w, http.StatusNotFound, relayRevokeResponse{Error: "unknown lease"})
			return
		}
		delete(s.leases, req.LeaseID)
		al.timer.Stop()
		s.mu.Unlock()

		final := al.finish(req.Outcome, req.ExitCode, req.Truncated)
		writeJSON(w, http.StatusOK, relayRevokeResponse{Revoked: final.Revoked})

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// RelayClient implements core.Relay over HTTPS with TLS 1.3 and SPKI SHA-256 pinning.
type RelayClient struct {
	baseURL string
	spkiPin [32]byte
	tokenFn func(context.Context) (string, error)
	client  *http.Client
}

// NewRelayClient parses rawURL (https://<host>#sha256=<hex>) and returns a pinned TLS 1.3 client.
func NewRelayClient(rawURL string, tokenFn func(context.Context) (string, error)) (*RelayClient, error) {
	baseURL, pin, err := ParseRelayURL(rawURL)
	if err != nil {
		return nil, err
	}
	if tokenFn == nil {
		return nil, errors.New("relay requires a device token provider")
	}
	tr := &http.Transport{
		TLSClientConfig: RelayTLSConfig(pin),
	}
	return &RelayClient{
		baseURL: baseURL,
		spkiPin: pin,
		tokenFn: tokenFn,
		client: &http.Client{
			Transport: tr,
			Timeout:   11 * time.Minute,
		},
	}, nil
}

func (c *RelayClient) postJSON(ctx context.Context, path string, in, out any) (int, error) {
	token, err := c.tokenFn(ctx)
	if err != nil {
		return 0, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, errors.New("relay device token is empty (set MINTRUN_RELAY_TOKEN or run `mintrun secret set relay`)")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New(core.Scrub(err.Error(), []string{token}))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("relay cannot be reached (%s)", core.Scrub(err.Error(), []string{token}))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("relay cannot be reached (%s)", core.Scrub(err.Error(), []string{token}))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("invalid relay response (%s)", core.Scrub(err.Error(), []string{token}))
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return resp.StatusCode, errors.New("relay rejected device token (401 unauthorized)")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &errBody)
		if errBody.Error == relayLeaseCapError {
			return resp.StatusCode, errors.New("relay lease cap reached (429: " + relayLeaseCapError + ")")
		}
		if errBody.Error != "" {
			return resp.StatusCode, fmt.Errorf("relay rate limited (429: %s)", core.Scrub(errBody.Error, []string{token}))
		}
		return resp.StatusCode, errors.New("relay rate limited (429)")
	}
	return resp.StatusCode, nil
}

// CheckPolicy queries POST /v1/check on the relay server. Any transport, auth, rate-limit, or
// decode failure fails closed with BlockedBy: "relay".
func (c *RelayClient) CheckPolicy(ctx context.Context, req core.ExecRequest) core.PolicyDecision {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var d core.PolicyDecision
	code, err := c.postJSON(cctx, "/v1/check", req, &d)
	if err != nil {
		return core.PolicyDecision{
			Allowed:   false,
			BlockedBy: "relay",
			Reason:    "policy denied: " + err.Error(),
		}
	}
	if code != http.StatusOK {
		return core.PolicyDecision{
			Allowed:   false,
			BlockedBy: "relay",
			Reason:    fmt.Sprintf("policy denied: relay check returned HTTP %d", code),
		}
	}
	return d
}

// Mint calls POST /v1/mint on the relay server.
func (c *RelayClient) Mint(ctx context.Context, req core.ExecRequest) (*core.Lease, core.PolicyDecision, string, error) {
	var resp relayMintResponse
	code, err := c.postJSON(ctx, "/v1/mint", req, &resp)
	if code == http.StatusForbidden && resp.Deny != nil {
		return nil, core.PolicyDecision{}, "", resp.Deny
	}
	if err != nil {
		return nil, core.PolicyDecision{}, "", err
	}
	if code != http.StatusOK {
		if resp.Error != "" {
			return nil, core.PolicyDecision{}, "", errors.New(resp.Error)
		}
		return nil, core.PolicyDecision{}, "", fmt.Errorf("relay mint returned HTTP %d", code)
	}
	if resp.Lease == nil || !resp.Lease.Ephemeral {
		return nil, core.PolicyDecision{}, "", errors.New("relay returned a missing or non-ephemeral lease")
	}
	return resp.Lease, resp.Decision, resp.DecidedAt, nil
}

// Revoke calls POST /v1/revoke on the relay server.
func (c *RelayClient) Revoke(ctx context.Context, leaseID, outcome string, exitCode int, truncated bool) (bool, error) {
	var resp relayRevokeResponse
	code, err := c.postJSON(ctx, "/v1/revoke", relayRevokeRequest{
		LeaseID:   leaseID,
		Outcome:   outcome,
		ExitCode:  exitCode,
		Truncated: truncated,
	}, &resp)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		if resp.Error != "" {
			return false, errors.New(resp.Error)
		}
		return false, fmt.Errorf("relay revoke returned HTTP %d", code)
	}
	return resp.Revoked, nil
}
