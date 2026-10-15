package builtin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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

// GitHubProvider mints and revokes short-lived, repository-scoped GitHub App Installation tokens
// (`POST /app/installations/{id}/access_tokens` and `DELETE /installation/token`), or wraps PATs
// in zero-knowledge static mode.
type GitHubProvider struct {
	BaseURL string
	Client  *http.Client
}

func NewGitHubProvider() *GitHubProvider {
	return &GitHubProvider{
		BaseURL: "https://api.github.com",
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *GitHubProvider) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "github",
		Version:     "0.2.0",
		Kind:        core.KindProvider,
		Description: "GitHub JIT Installation Token Minter & Zero-Knowledge PAT Wrapper (auto-revokes on exit)",
		Scopes:      []string{"contents:read", "contents:write", "pull_requests:write", "issues:write", "actions:write", "metadata:read", "static"},
		Builtin:     true,
	}
}

func (g *GitHubProvider) Mint(ctx context.Context, masterSecret string, req core.MintRequest) (*core.Lease, error) {
	if masterSecret == "" {
		return nil, errors.New("empty GitHub master secret")
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)

	// Format for JIT Installation Token minting:
	// 1. "<app_id>:<installation_id>:<rsa_private_key_pem>" (auto-signs RS256 JWT)
	// 2. "<installation_id>:<app_jwt>" or Params["installation_id"]
	instID := req.Params["installation_id"]
	bearer := masterSecret
	if instID == "" && strings.Contains(masterSecret, ":") && !strings.HasPrefix(masterSecret, "gh") {
		if strings.Contains(masterSecret, "-----BEGIN") {
			parts := strings.SplitN(masterSecret, ":", 3)
			if len(parts) == 3 {
				jwtTok, err := signGitHubAppJWT(parts[0], parts[2])
				if err != nil {
					return nil, fmt.Errorf("sign github app JWT: %w", err)
				}
				instID, bearer = parts[1], jwtTok
			}
		} else {
			parts := strings.SplitN(masterSecret, ":", 2)
			instID, bearer = parts[0], parts[1]
		}
	}

	if instID == "" || req.Params["mode"] == "static" || containsPerm(req.Permissions, "static") {
		return &core.Lease{
			ID:       "gh-static",
			Provider: "github",
			Scope:    req.Scope,
			Env: map[string]string{
				"GITHUB_TOKEN": masterSecret,
				"GH_TOKEN":     masterSecret,
			},
			Redact:    []string{masterSecret},
			ExpiresAt: expiresAt,
			Ephemeral: false,
		}, nil
	}

	body := map[string]any{}
	if req.Scope != "" && req.Scope != "*" {
		repo := req.Scope
		if _, after, ok := strings.Cut(repo, "/"); ok {
			repo = after
		}
		body["repositories"] = []string{repo}
	}
	if len(req.Permissions) > 0 {
		perms := make(map[string]string)
		for _, p := range req.Permissions {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), ":"); ok && k != "" && v != "" {
				perms[k] = v
			}
		}
		if len(perms) > 0 {
			body["permissions"] = perms
		}
	}

	var resp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := "/app/installations/" + url.PathEscape(instID) + "/access_tokens"
	if err := g.doGitHubJSON(ctx, bearer, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	if resp.Token == "" {
		return nil, errors.New("github API returned empty installation token")
	}
	return &core.Lease{
		ID:       resp.Token, // GitHub revokes installation tokens using the token itself as Bearer
		Provider: "github",
		Scope:    req.Scope,
		Env: map[string]string{
			"GITHUB_TOKEN": resp.Token,
			"GH_TOKEN":     resp.Token,
		},
		Redact:    []string{resp.Token, bearer, masterSecret},
		ExpiresAt: resp.ExpiresAt,
		Ephemeral: true,
	}, nil
}

func signGitHubAppJWT(appID, pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(pemStr, `\n`, "\n")))
	if block == nil {
		return "", errors.New("invalid PEM block")
	}
	var rsaKey *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		rsaKey = k
	} else if pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := pkcs8.(*rsa.PrivateKey); ok {
			rsaKey = k
		}
	}
	if rsaKey == nil {
		return "", errors.New("unsupported RSA private key format")
	}
	now := time.Now().UTC().Unix()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now - 60, "exp": now + 540, "iss": appID})
	unsigned := hdr + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (g *GitHubProvider) Revoke(ctx context.Context, _ string, lease *core.Lease) error {
	if lease == nil || !lease.Ephemeral || lease.ID == "" || lease.ID == "gh-static" {
		return nil
	}
	return g.doGitHubJSON(ctx, lease.ID, http.MethodDelete, "/installation/token", nil, nil)
}

func (g *GitHubProvider) doGitHubJSON(ctx context.Context, token, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(g.BaseURL, "/")+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("github API %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	if out != nil && len(respBytes) > 0 {
		return json.Unmarshal(respBytes, out)
	}
	return nil
}

// AWSProvider mints short-lived AWS STS credentials via `AssumeRole` signed with 100% stdlib
// AWS Signature Version 4 (including optional inline session policy narrowing), or wraps static IAM keys.
type AWSProvider struct {
	Endpoint string
	Region   string
	Client   *http.Client
}

func NewAWSProvider() *AWSProvider {
	return &AWSProvider{
		Endpoint: "https://sts.amazonaws.com",
		Region:   "us-east-1",
		Client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *AWSProvider) Manifest() core.Manifest {
	return core.Manifest{
		Name:        "aws",
		Version:     "0.4.0",
		Kind:        core.KindProvider,
		Description: "AWS STS AssumeRole JIT Minter & Zero-Knowledge IAM Wrapper (100% stdlib SigV4)",
		Scopes:      []string{"s3:*", "ec2:*", "lambda:*", "dynamodb:*", "cloudformation:*", "static"},
		Builtin:     true,
	}
}

func (a *AWSProvider) Mint(ctx context.Context, masterSecret string, req core.MintRequest) (*core.Lease, error) {
	if masterSecret == "" {
		return nil, errors.New("empty AWS master secret")
	}
	parts := strings.SplitN(strings.TrimSpace(masterSecret), ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("AWS master secret must be formatted as <access_key_id>:<secret_access_key>[:<session_token>]")
	}
	accessKey, secretKey := parts[0], parts[1]

	// Static mode if no Role ARN is given in scope or 'static' permission is requested.
	if req.Scope == "" || !strings.HasPrefix(req.Scope, "arn:aws:") || req.Params["mode"] == "static" || containsPerm(req.Permissions, "static") {
		env := map[string]string{
			"AWS_ACCESS_KEY_ID":     accessKey,
			"AWS_SECRET_ACCESS_KEY": secretKey,
		}
		redact := []string{masterSecret, accessKey, secretKey}
		if len(parts) == 3 && parts[2] != "" {
			env["AWS_SESSION_TOKEN"] = parts[2]
			redact = append(redact, parts[2])
		}
		return &core.Lease{
			ID:        "aws-static",
			Provider:  "aws",
			Scope:     req.Scope,
			Env:       env,
			Redact:    redact,
			ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
			Ephemeral: false,
		}, nil
	}

	dur := req.TTLSeconds
	if dur < 900 {
		dur = 900
	} else if dur > 43200 {
		dur = 43200
	}

	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", req.Scope)
	form.Set("RoleSessionName", fmt.Sprintf("mintrun-jit-%d", time.Now().Unix()))
	form.Set("DurationSeconds", strconv.Itoa(dur))

	if len(req.Permissions) > 0 {
		policyDoc, _ := json.Marshal(map[string]any{
			"Version": "2012-10-17",
			"Statement": []map[string]any{
				{
					"Effect":   "Allow",
					"Action":   req.Permissions,
					"Resource": "*",
				},
			},
		})
		form.Set("Policy", string(policyDoc))
	}

	body := []byte(form.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(parts) == 3 && parts[2] != "" {
		httpReq.Header.Set("X-Amz-Security-Token", parts[2])
	}
	signAWSSigV4(httpReq, accessKey, secretKey, a.Region, "sts", body, time.Now().UTC())

	resp, err := a.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aws STS AssumeRole failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var parsed struct {
		AccessKeyID     string `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
		SecretAccessKey string `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
		SessionToken    string `xml:"AssumeRoleResult>Credentials>SessionToken"`
		Expiration      string `xml:"AssumeRoleResult>Credentials>Expiration"`
		AssumedRoleID   string `xml:"AssumeRoleResult>AssumedRoleUser>AssumedRoleId"`
	}
	if err := xml.Unmarshal(respBytes, &parsed); err != nil || parsed.SecretAccessKey == "" {
		return nil, fmt.Errorf("parse AWS STS AssumeRole response: %w", err)
	}
	expTime, _ := time.Parse(time.RFC3339, parsed.Expiration)
	return &core.Lease{
		ID:       parsed.AssumedRoleID,
		Provider: "aws",
		Scope:    req.Scope,
		Env: map[string]string{
			"AWS_ACCESS_KEY_ID":     parsed.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": parsed.SecretAccessKey,
			"AWS_SESSION_TOKEN":     parsed.SessionToken,
		},
		Redact:    []string{parsed.AccessKeyID, parsed.SecretAccessKey, parsed.SessionToken, accessKey, secretKey, masterSecret},
		ExpiresAt: expTime,
		Ephemeral: true,
	}, nil
}

func (a *AWSProvider) Revoke(_ context.Context, _ string, _ *core.Lease) error {
	// AWS STS temporary credentials expire automatically when DurationSeconds elapses.
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}

func signAWSSigV4(req *http.Request, accessKey, secretKey, region, service string, payload []byte, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256.Sum256(payload)
	payloadHex := hex.EncodeToString(payloadHash[:])

	req.Header.Set("X-Amz-Date", amzDate)
	host := req.URL.Host
	canonicalHeaders := "content-type:" + req.Header.Get("Content-Type") + "\nhost:" + host + "\nx-amz-date:" + amzDate + "\n"
	signedHeaders := "content-type;host;x-amz-date"

	canonicalReq := strings.Join([]string{
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHex,
	}, "\n")

	credScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	canonHash := sha256.Sum256([]byte(canonicalReq))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		hex.EncodeToString(canonHash[:]),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credScope, signedHeaders, signature,
	))
}



