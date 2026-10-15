package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

var hex32Re = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// CloudflareProvider mints and revokes short-lived, zone-scoped Cloudflare API sub-tokens
// from a master token (`POST /client/v4/user/tokens` and `DELETE /client/v4/user/tokens/{id}`).
type CloudflareProvider struct {
	BaseURL string
	Client  *http.Client
}

func NewCloudflareProvider() *CloudflareProvider {
	return &CloudflareProvider{
		BaseURL: "https://api.cloudflare.com/client/v4",
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CloudflareProvider) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "cloudflare",
		Version:     "0.1.0",
		Kind:        core.KindProvider,
		Description: "Cloudflare JIT Sub-Token Minter (auto-scopes by Zone/Account and revokes on exit)",
		Scopes:      []string{"dns:read", "dns:write", "workers:write", "pages:write", "ssl:write", "cache:purge", "static"},
		Builtin:     true,
	}
}

func (c *CloudflareProvider) Mint(ctx context.Context, masterSecret string, req core.MintRequest) (*core.Lease, error) {
	if masterSecret == "" {
		return nil, errors.New("empty Cloudflare master secret")
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	expiresAt := time.Now().UTC().Add(ttl).Truncate(time.Second)

	// Static mode: inject the stored token into child process without calling /user/tokens API
	// (useful if the user stored an already-scoped token or wants zero-knowledge wrapper only).
	if req.Params["mode"] == "static" || containsPerm(req.Permissions, "static") {
		return &core.Lease{
			ID:       "cf-static",
			Provider: "cloudflare",
			Scope:    req.Scope,
			Env: map[string]string{
				"CLOUDFLARE_API_TOKEN": masterSecret,
				"CF_API_TOKEN":         masterSecret,
			},
			Redact:    []string{masterSecret},
			ExpiresAt: expiresAt,
			Ephemeral: false,
		}, nil
	}

	// Step 1: Resolve Scope (domain name or Zone ID) into a Cloudflare resource map.
	resources := map[string]string{
		"com.cloudflare.api.account.zone.*": "*",
	}
	if req.Scope != "" && req.Scope != "*" {
		zoneID, err := c.resolveZoneID(ctx, masterSecret, req.Scope)
		if err != nil {
			return nil, err
		}
		resources = map[string]string{
			"com.cloudflare.api.account.zone." + zoneID: "*",
		}
	}

	// Step 2: Resolve requested permissions into Cloudflare Permission Group IDs.
	permGroups, err := c.resolvePermissionGroups(ctx, masterSecret, req.Permissions)
	if err != nil {
		return nil, err
	}

	// Step 3: Mint the short-lived child token via POST /user/tokens.
	payload := map[string]any{
		"name":       fmt.Sprintf("mintrun-jit-%d", time.Now().Unix()),
		"expires_on": expiresAt.Format(time.RFC3339),
		"policies": []map[string]any{
			{
				"effect":            "allow",
				"resources":         resources,
				"permission_groups": permGroups,
			},
		},
	}

	var createResp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"result"`
	}

	if err := c.doJSON(ctx, masterSecret, http.MethodPost, "/user/tokens", payload, &createResp); err != nil {
		return nil, err
	}
	if !createResp.Success || createResp.Result.Value == "" {
		return nil, fmt.Errorf("cloudflare token mint rejected: %v", createResp.Errors)
	}

	subToken := createResp.Result.Value
	return &core.Lease{
		ID:       createResp.Result.ID,
		Provider: "cloudflare",
		Scope:    req.Scope,
		Env: map[string]string{
			"CLOUDFLARE_API_TOKEN": subToken,
			"CF_API_TOKEN":         subToken,
		},
		Redact:    []string{subToken, masterSecret},
		ExpiresAt: expiresAt,
		Ephemeral: true,
	}, nil
}

func (c *CloudflareProvider) Revoke(ctx context.Context, masterSecret string, lease *core.Lease) error {
	if lease == nil || !lease.Ephemeral || lease.ID == "" || lease.ID == "cf-static" {
		return nil
	}
	return c.doJSON(ctx, masterSecret, http.MethodDelete, "/user/tokens/"+url.PathEscape(lease.ID), nil, nil)
}

func (c *CloudflareProvider) resolveZoneID(ctx context.Context, masterSecret, scope string) (string, error) {
	scope = strings.TrimPrefix(strings.TrimSpace(scope), "zone:")
	if hex32Re.MatchString(scope) {
		return scope, nil
	}
	var resp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	path := "/zones?name=" + url.QueryEscape(scope)
	if err := c.doJSON(ctx, masterSecret, http.MethodGet, path, nil, &resp); err != nil {
		return "", fmt.Errorf("resolve zone %q: %w", scope, err)
	}
	if len(resp.Result) == 0 || resp.Result[0].ID == "" {
		return "", fmt.Errorf("cloudflare zone %q not found on this account", scope)
	}
	return resp.Result[0].ID, nil
}

type cfPermGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Well-known Cloudflare permission group aliases mapped to substrings in Cloudflare's catalog.
var permKeywordMap = map[string]string{
	"dns:write":     "dns write",
	"dns:read":      "dns read",
	"workers:write": "workers scripts write",
	"workers:read":  "workers scripts read",
	"pages:write":   "pages write",
	"ssl:write":     "ssl and certificates write",
	"cache:purge":   "cache purge",
	"zone:read":     "zone read",
}

func (c *CloudflareProvider) resolvePermissionGroups(ctx context.Context, masterSecret string, requested []string) ([]cfPermGroup, error) {
	if len(requested) == 0 {
		requested = []string{"dns:write", "zone:read"}
	}

	// If caller passed raw 32-hex Cloudflare permission group IDs directly, use them without extra round-trip.
	var direct []cfPermGroup
	allHex := true
	for _, r := range requested {
		if hex32Re.MatchString(r) {
			direct = append(direct, cfPermGroup{ID: r})
		} else {
			allHex = false
		}
	}
	if allHex && len(direct) > 0 {
		return direct, nil
	}

	var catalog struct {
		Success bool          `json:"success"`
		Result  []cfPermGroup `json:"result"`
	}
	if err := c.doJSON(ctx, masterSecret, http.MethodGet, "/user/tokens/permission_groups", nil, &catalog); err != nil {
		return nil, fmt.Errorf("fetch permission groups: %w", err)
	}

	var matched []cfPermGroup
	seen := make(map[string]bool)
	for _, reqPerm := range requested {
		key := strings.ToLower(strings.TrimSpace(reqPerm))
		if hex32Re.MatchString(key) {
			if !seen[key] {
				matched = append(matched, cfPermGroup{ID: key})
				seen[key] = true
			}
			continue
		}
		targetName, ok := permKeywordMap[key]
		if !ok {
			targetName = strings.ReplaceAll(key, ":", " ")
		}
		for _, item := range catalog.Result {
			if strings.Contains(strings.ToLower(item.Name), targetName) && !seen[item.ID] {
				matched = append(matched, cfPermGroup{ID: item.ID, Name: item.Name})
				seen[item.ID] = true
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("could not match requested permissions %v in Cloudflare catalog", requested)
	}
	return matched, nil
}

func (c *CloudflareProvider) doJSON(ctx context.Context, token, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("cloudflare API %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return err
		}
	}
	return nil
}

func containsPerm(list []string, target string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), target) {
			return true
		}
	}
	return false
}
