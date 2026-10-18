package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkScrub scrubs one full capped stream (MaxOutputBytes) holding 8 secrets, each planted in
// all 5 forms Scrub redacts.
func BenchmarkScrub(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var secrets, forms []string
	for _, n := range []int{20, 40, 44, 64, 200, 400, 1000, 1700} { // no multiple of 3, so Base64 pads
		s := make([]byte, n)
		for i := range s {
			s[i] = alphabet[rng.IntN(len(alphabet))]
		}
		s[n/2] = '/' // so the URL-encoded form differs from the raw one
		secrets = append(secrets, string(s))
		forms = append(forms, scrubVariants(string(s))...)
	}
	var sb strings.Builder
	for i := 0; sb.Len() < MaxOutputBytes; i++ {
		fmt.Fprintf(&sb, "2026-10-18T12:00:00Z INFO request id=%d path=/v1/items/%d status=200 bytes=%d\n", i, i*7, i*13%9000)
		if i%100 == 0 {
			fmt.Fprintf(&sb, "debug: token=%s\n", forms[(i/100)%len(forms)])
		}
	}
	text := sb.String()[:MaxOutputBytes]
	out := Scrub(text, secrets)
	seen := map[string]bool{}
	for i, f := range forms {
		if seen[f] || !strings.Contains(text, f) || strings.Contains(out, f) {
			b.Fatalf("form %d of secret %d is repeated, not planted, or survives Scrub", i%5, i/5)
		}
		seen[f] = true
	}
	b.ResetTimer()
	for range b.N {
		Scrub(text, secrets)
	}
}

// BenchmarkTailAudit reads the last 20 entries of one provider from a 100,000-line audit log, as
// `mintrun audit -provider aws -limit 20` does.
func BenchmarkTailAudit(b *testing.B) {
	providers := []string{"github", "aws", "gcp", "cloudflare"}
	var buf bytes.Buffer
	for i := range 100_000 {
		line, err := json.Marshal(AuditEntry{
			Timestamp: "2026-10-18T12:00:00Z", Task: fmt.Sprintf("task%022d", i), Via: "mcp", Client: "claude-code",
			Provider: providers[i%len(providers)], Scope: "owner/repo", Permissions: []string{"contents:read"},
			Command: []string{"gh", "pr", "list", "--repo", "owner/repo"}, Outcome: "done",
			LeaseID: fmt.Sprintf("gh-inst-12345-%d", 1760000000+i), Ephemeral: true,
			ExpiresAt: "2026-10-18T13:00:00Z", Revoked: true, DurationMs: int64(i % 5000),
		})
		if err != nil {
			b.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	path := filepath.Join(b.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	tail := func() int {
		f, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		defer f.Close()
		n := 0
		if err := TailAudit(f, "aws", false, 20, func(string, AuditEntry) { n++ }); err != nil {
			b.Fatal(err)
		}
		return n
	}
	if n := tail(); n != 20 {
		b.Fatalf("TailAudit handed over %d entries, want 20", n)
	}
	b.ResetTimer()
	for range b.N {
		tail()
	}
}

// BenchmarkChildEnv builds a clean-mode child environment from a few allowed_env globs and a
// lease's env. It also reads this process's environment, whose size the env-vars metric reports.
func BenchmarkChildEnv(b *testing.B) {
	b.Setenv("AWS_REGION", "us-east-1")
	b.Setenv("AWS_PROFILE", "bench")
	b.Setenv("NODE_OPTIONS", "--max-old-space-size=4096")
	allowed := []string{"AWS_*", "NODE_OPTIONS", "*_PROXY"}
	lease := map[string]string{"AWS_ACCESS_KEY_ID": "bench-key-id", "AWS_SECRET_ACCESS_KEY": "bench-secret", "AWS_SESSION_TOKEN": "bench-token"}
	vars := len(os.Environ())
	b.ResetTimer()
	for range b.N {
		childEnv(true, allowed, lease)
	}
	b.ReportMetric(float64(vars), "env-vars")
}
