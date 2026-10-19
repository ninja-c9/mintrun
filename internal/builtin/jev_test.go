package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// jevFake is a fake TypeSafe API. It records each call and answers with reply, whose n counts
// the calls since the last take from 1.
type jevFake struct {
	url    string
	mu     sync.Mutex
	reply  func(n int) (int, string)
	auth   []string
	bodies [][]byte
}

// newJevFake points jevAPI at a new fake that answers every question with 0, and puts jevAPI and
// the waits back when the test ends.
func newJevFake(t *testing.T) *jevFake {
	f := &jevFake{reply: func(int) (int, string) { return 200, jevAnswer(nil, 0, 0.9) }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.auth = append(f.auth, r.Method+" "+r.Header.Get("Authorization")+" "+r.Header.Get("Content-Type"))
		f.bodies = append(f.bodies, b)
		n, reply := len(f.bodies), f.reply
		f.mu.Unlock()
		status, body := reply(n)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	api, timeout, budget, backoff := jevAPI, jevTimeout, jevBudget, jevBackoff
	t.Cleanup(func() { jevAPI, jevTimeout, jevBudget, jevBackoff = api, timeout, budget, backoff })
	f.url, jevAPI = srv.URL, srv.URL
	return f
}

func (f *jevFake) on(reply func(n int) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply = reply
}

// take returns the calls made since the last take.
func (f *jevFake) take() (auth []string, bodies [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	auth, bodies, f.auth, f.bodies = f.auth, f.bodies, nil, nil
	return auth, bodies
}

// jevAnswer is a valid reply: each noul from p (0 when absent), and a severity whose legend names
// the first criterion whatever the score, so routing that reads the legend fails.
func jevAnswer(p map[string]float64, score, conf float64) string {
	answers := map[string]any{"severity": map[string]any{"type": "score", "score": score, "confidence": conf,
		"legend": "Reads only; changes nothing", "probabilities": []float64{0.1, 0.2, 0.3, 0.4}}}
	for id, q := range jevQuestions {
		if q.Type == "noul" {
			answers[id] = map[string]any{"noul": p[id], "type": "noul"}
		}
	}
	b, _ := json.Marshal(map[string]any{"model": JevModel, "answers": answers})
	return string(b)
}

// jevRuntime is a runtime whose default vault is a file vault holding key as JevKey, or nothing
// when key is empty.
func jevRuntime(t *testing.T, key string) (*core.Runtime, *KeychainVault) {
	home := t.TempDir()
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	reg := core.NewRegistry()
	_ = reg.Register(kv)
	if key != "" {
		if err := kv.SetSecret(context.Background(), JevKey, key); err != nil {
			t.Fatal(err)
		}
	}
	return core.NewRuntime(home, "keychain", reg), kv
}

// blankVault returns a blank value for every key.
type blankVault struct{}

func (blankVault) Manifest() core.Manifest {
	return core.Manifest{Name: "blank", Kind: core.KindVault}
}
func (blankVault) GetSecret(context.Context, string) (string, error) { return " \n", nil }
func (blankVault) SetSecret(context.Context, string, string) error   { return nil }
func (blankVault) DeleteSecret(context.Context, string) error        { return nil }

func TestJevClient(t *testing.T) {
	const key = "tsk_jev_key_canary_8d3f1b"
	ctx := context.Background()
	f := newJevFake(t)
	rt, _ := jevRuntime(t, key)
	req := core.ExecRequest{MintRequest: core.MintRequest{Provider: "github", Scope: "o/r", Permissions: []string{"contents:read"}},
		Command: []string{"gh", "repo", "view"}, Purpose: "show the repo"}
	rule := core.PolicyRule{}
	// noAnswer checks a verdict that got no answer: unknown, the error, and on_error's route.
	noAnswer := func(t *testing.T, v *core.JevVerdict, err, route string, calls int) {
		t.Helper()
		if _, bodies := f.take(); len(bodies) != calls {
			t.Fatalf("calls = %d, want %d", len(bodies), calls)
		}
		if v.Risk != "unknown" || v.Error != err || v.Route != route || v.Labels != nil || v.Severity != nil {
			t.Fatalf("verdict = %+v, want unknown, route %q, error %q", v, route, err)
		}
	}

	t.Run("off", func(t *testing.T) {
		for _, cfg := range []JevConfig{{}, {Mode: "off", Model: JevModel, OnError: "deny"}} {
			if JevScreen(rt, cfg) != nil {
				t.Fatalf("JevScreen(%+v) is not nil", cfg)
			}
		}
	})

	t.Run("request", func(t *testing.T) {
		v := JevScreen(rt, JevConfig{Mode: "escalate"})(req, rule)
		auth, bodies := f.take()
		if want := []string{"POST Bearer " + key + " application/json"}; !slices.Equal(auth, want) {
			t.Fatalf("calls = %q, want %q", auth, want)
		}
		if v.Risk != "low" || v.Route != "" || v.Reason != "" || v.Labels != nil || v.Severity == nil || *v.Severity != 0 || v.Model != JevModel || v.Error != "" {
			t.Fatalf("verdict = %+v, want low", v)
		}
		var body struct {
			Model     string
			Questions map[string]jevQuestion
			State     struct{ Request, Policy map[string]json.RawMessage }
		}
		var top, state map[string]json.RawMessage
		if json.Unmarshal(bodies[0], &body) != nil || json.Unmarshal(bodies[0], &top) != nil || json.Unmarshal(top["state"], &state) != nil {
			t.Fatalf("body = %s", bodies[0])
		}
		keys := func(m map[string]json.RawMessage) []string { return slices.Sorted(maps.Keys(m)) }
		for _, c := range []struct {
			got  []string
			want string
		}{
			{keys(top), "model questions state"},
			{keys(state), "policy request trust"},
			{keys(body.State.Request), "argv client cwd device no_network params permissions provider purpose sandbox scope via"},
			{keys(body.State.Policy), "allowed_permissions allowed_scopes blocked_commands require_approval"},
		} {
			if got := strings.Join(c.got, " "); got != c.want {
				t.Fatalf("keys = %q, want %q", got, c.want)
			}
		}
		if body.Model != "jev-1.13.0" || !strings.Contains(string(state["trust"]), "may have been written by an AI agent") {
			t.Fatalf("model = %q, trust = %s", body.Model, state["trust"])
		}
		types := map[string]string{}
		for id, q := range body.Questions {
			if q.Instructions == "" {
				t.Fatalf("question %q has no instructions", id)
			}
			types[id] = fmt.Sprintf("%s/%d", q.Type, len(q.Criteria))
		}
		want := map[string]string{"exfil": "noul/0", "exfil_b": "noul/0", "destructive": "noul/0", "mismatch": "noul/0",
			"injected": "noul/0", "vague": "noul/0", "scope_creep": "noul/0", "severity": "score/4"}
		if !maps.Equal(types, want) {
			t.Fatalf("questions = %v, want %v", types, want)
		}

		// A model named in settings.json goes out as named.
		JevScreen(rt, JevConfig{Mode: "deny", Model: "jev-1.14.0"})(req, rule)
		if _, bodies := f.take(); len(bodies) != 1 || json.Unmarshal(bodies[0], &body) != nil || body.Model != "jev-1.14.0" {
			t.Fatalf("model = %q, want jev-1.14.0", body.Model)
		}
	})

	t.Run("key", func(t *testing.T) {
		rt, kv := jevRuntime(t, "")
		screen := JevScreen(rt, JevConfig{Mode: "deny"}) // built before the key exists: it is read on first use
		noAnswer(t, screen(req, rule), `jev systemone: secret "jev" not found in vault (run mintrun init jev)`, "ask", 0)
		for _, stored := range []string{"tsk_first_key_1", "tsk_second_key_2"} {
			if err := kv.SetSecret(ctx, JevKey, stored); err != nil {
				t.Fatal(err)
			}
			screen(req, rule)
			// The first key read is kept: the vault is read once per process.
			if auth, _ := f.take(); !slices.Equal(auth, []string{"POST Bearer tsk_first_key_1 application/json"}) {
				t.Fatalf("calls = %q", auth)
			}
		}
		// The file vault refuses a blank value; a plugin vault may return one.
		_ = rt.Registry.Register(blankVault{})
		rt.DefaultVault = "blank"
		noAnswer(t, JevScreen(rt, JevConfig{Mode: "deny"})(req, rule), `jev systemone: secret "jev" is empty (run mintrun init jev)`, "ask", 0)
		rt.DefaultVault = "nope"
		noAnswer(t, JevScreen(rt, JevConfig{Mode: "deny"})(req, rule), `jev systemone: vault plugin "nope" not found`, "ask", 0)
	})

	t.Run("final", func(t *testing.T) {
		screen := JevScreen(rt, JevConfig{Mode: "deny"})
		for _, status := range []int{400, 401, 413, 415, 422, 500} {
			f.on(func(int) (int, string) { return status, `{"error":"bad key ` + key + `"}` + "\n" })
			noAnswer(t, screen(req, rule), fmt.Sprintf(`jev systemone: HTTP %d: {"error":"bad key [MINTRUN:REDACTED]"}`, status), "ask", 1)
		}
		// A body over 1 KiB is not quoted, so no cut can split the key.
		f.on(func(int) (int, string) { return 500, strings.Repeat("x", 1<<10) + key })
		noAnswer(t, screen(req, rule), "jev systemone: HTTP 500", "ask", 1)
	})

	t.Run("backoff", func(t *testing.T) {
		screen := JevScreen(rt, JevConfig{Mode: "deny"})
		jevBackoff, jevBudget = 10*time.Millisecond, 2*time.Second
		f.on(func(n int) (int, string) {
			if n == 1 {
				return 529, "overloaded"
			} else if n == 2 {
				return 429, "slow down"
			}
			return 200, jevAnswer(nil, 0, 0.9)
		})
		if v := screen(req, rule); v.Risk != "low" || v.Error != "" {
			t.Fatalf("verdict = %+v, want low", v)
		}
		if _, bodies := f.take(); len(bodies) != 3 {
			t.Fatalf("calls = %d, want 3", len(bodies))
		}
		// A 429 that never ends stops at the budget, after at most 5 calls: waits of 10, 20, 40,
		// and 80 ms fit in 300 ms, and 160 more do not.
		jevBudget = 300 * time.Millisecond
		f.on(func(int) (int, string) { return 429, `{"error":"rate limited"}` })
		done := make(chan *core.JevVerdict, 1)
		go func() { done <- screen(req, rule) }()
		select {
		case v := <-done:
			if _, bodies := f.take(); len(bodies) < 2 || len(bodies) > 5 || v.Error != "jev systemone: HTTP 429 past the 300ms budget" || v.Route != "ask" {
				t.Fatalf("calls = %d, verdict = %+v", len(bodies), v)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a 429 was retried past the budget")
		}
	})

	t.Run("network", func(t *testing.T) {
		screen := JevScreen(rt, JevConfig{Mode: "deny", OnError: "pass"})
		jevTimeout = 50 * time.Millisecond
		f.on(func(int) (int, string) { time.Sleep(300 * time.Millisecond); return 200, jevAnswer(nil, 0, 0.9) })
		noAnswer(t, screen(req, rule), "jev systemone: POST "+f.url+": timed out", "", 1)
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		jevAPI = dead.URL
		noAnswer(t, screen(req, rule), "jev systemone: POST "+dead.URL+": unreachable", "", 0)
		jevAPI = f.url
	})

	t.Run("send cap", func(t *testing.T) {
		screen := JevScreen(rt, JevConfig{Mode: "deny"})
		f.on(func(int) (int, string) { return 200, jevAnswer(nil, 0, 0.9) })
		// Each byte of an "a" purpose adds one byte to the body, so the largest body is measured, not computed.
		long := req
		long.Purpose = ""
		screen(long, rule)
		_, bodies := f.take()
		long.Purpose = strings.Repeat("a", jevMaxBody-len(bodies[0]))
		if v := screen(long, rule); v.Risk != "low" {
			t.Fatalf("verdict = %+v, want low", v)
		}
		if _, bodies := f.take(); len(bodies) != 1 || len(bodies[0]) != jevMaxBody {
			t.Fatalf("calls = %d, want one of %d bytes", len(bodies), jevMaxBody)
		}
		long.Purpose += "a"
		noAnswer(t, screen(long, rule), "jev systemone: request over 256 KiB, not sent", "ask", 0)
	})

	t.Run("malformed", func(t *testing.T) {
		screen := JevScreen(rt, JevConfig{Mode: "deny"})
		ok := jevAnswer(nil, 0, 0.9)
		for _, reply := range []string{
			strings.Replace(ok, `"model":"jev-1.13.0"`, `"model":"gpt-4"`, 1),
			strings.Replace(ok, `"vague":`, `"vague2":`, 1),
			strings.Replace(ok, `{"noul":0,`, `{"nul":0,`, 1),
			strings.Replace(ok, `"type":"score"`, `"type":"noul"`, 1),
			strings.Replace(ok, `"confidence":0.9`, `"conf":0.9`, 1),
			jevAnswer(map[string]float64{"destructive": 1.5}, 0, 0.9),
			jevAnswer(map[string]float64{"mismatch": -0.1}, 0, 0.9),
			jevAnswer(nil, 3.2, 0.9),
			jevAnswer(nil, 0, 1.2),
			"not json",
			"",
			// A reply over 1 MiB is cut, so it does not decode.
			`{"pad":"` + strings.Repeat("x", 1<<20) + `",` + ok[1:],
		} {
			if reply == ok {
				t.Fatal("a malformed reply is the valid one")
			}
			f.on(func(int) (int, string) { return 200, reply })
			noAnswer(t, screen(req, rule), "jev systemone: malformed reply", "ask", 1)
		}
	})

	t.Run("on_error", func(t *testing.T) {
		f.on(func(int) (int, string) { return 500, "" })
		for _, c := range []struct{ mode, onError, route, reason string }{
			{"escalate", "", "ask", ""},
			{"deny", "escalate", "ask", ""},
			{"escalate", "deny", "deny", `policy denied: semantic screen did not answer and jev.on_error is "deny"`},
			{"deny", "pass", "", ""},
		} {
			v := JevScreen(rt, JevConfig{Mode: c.mode, OnError: c.onError})(req, rule)
			noAnswer(t, v, "jev systemone: HTTP 500", c.route, 1)
			if v.Reason != c.reason {
				t.Fatalf("%+v: reason = %q, want %q", c, v.Reason, c.reason)
			}
		}
	})

	t.Run("route", func(t *testing.T) {
		screens := map[string]func(core.ExecRequest, core.PolicyRule) *core.JevVerdict{
			"deny": JevScreen(rt, JevConfig{Mode: "deny"}), "escalate": JevScreen(rt, JevConfig{Mode: "escalate"})}
		raised := &core.JevThresholds{AskAbove: 0.6, DenyAbove: 0.95, SeverityDeny: 2}
		for _, c := range []struct {
			name, mode  string
			thresholds  *core.JevThresholds
			p           map[string]float64
			score, conf float64
			risk, route string
			reason      string
			labels      []string
			severity    int
		}{
			{"clean", "deny", nil, nil, 0, 0.9, "low", "", "", nil, 0},
			{"destructive", "deny", nil, map[string]float64{"destructive": 0.5}, 1, 0.9, "medium", "ask", "", []string{"destructive"}, 1},
			{"at ask_above", "deny", nil, map[string]float64{"mismatch": 0.35}, 0, 0.9, "medium", "ask", "", []string{"mismatch"}, 0},
			{"below ask_above", "deny", nil, map[string]float64{"mismatch": 0.34}, 0, 0.9, "low", "", "", nil, 0},
			{"vague asks no one", "deny", nil, map[string]float64{"vague": 0.9}, 0, 0.9, "low", "", "", []string{"vague"}, 0},
			{"exfil pair at deny_above", "deny", nil, map[string]float64{"exfil": 0.9, "exfil_b": 0.85}, 0, 0.9, "high", "deny", "policy denied: semantic screen flagged exfil", []string{"exfil"}, 0},
			{"escalate never denies", "escalate", nil, map[string]float64{"exfil": 0.9, "exfil_b": 0.9}, 3, 0.9, "high", "ask", "", []string{"exfil"}, 3},
			{"exfil alone", "deny", nil, map[string]float64{"exfil": 0.9, "exfil_b": 0.2}, 0, 0.9, "medium", "ask", "", []string{"exfil"}, 0},
			{"exfil_b alone", "deny", nil, map[string]float64{"exfil_b": 0.5}, 0, 0.9, "medium", "ask", "", []string{"exfil"}, 0},
			{"severity from score", "deny", nil, nil, 2.6, 0.9, "high", "deny", "policy denied: semantic screen flagged severity 3/3", nil, 3},
			{"unsure severity", "deny", nil, nil, 3, 0.5, "medium", "ask", "", nil, 3},
			{"unsure below 0.6", "deny", nil, nil, 1, 0.59, "medium", "ask", "", nil, 1},
			{"sure at 0.6", "deny", nil, nil, 1, 0.6, "low", "", "", nil, 1},
			{"labels in order", "escalate", nil, map[string]float64{"injected": 0.8, "exfil": 0.5}, 0, 0.9, "medium", "ask", "", []string{"exfil", "injected"}, 0},
			{"raised ask_above", "deny", raised, map[string]float64{"destructive": 0.5}, 0, 0.9, "low", "", "", nil, 0},
			{"raised deny_above", "deny", raised, map[string]float64{"exfil": 0.9, "exfil_b": 0.9}, 0, 0.9, "medium", "ask", "", []string{"exfil"}, 0},
			{"lowered severity_deny", "deny", raised, nil, 2, 0.9, "high", "deny", "policy denied: semantic screen flagged severity 2/3", nil, 2},
			{"unset fields keep defaults", "deny", &core.JevThresholds{AskAbove: 0.6}, map[string]float64{"exfil": 0.9, "exfil_b": 0.9}, 0, 0.9, "high", "deny", "policy denied: semantic screen flagged exfil", []string{"exfil"}, 0},
		} {
			f.on(func(int) (int, string) { return 200, jevAnswer(c.p, c.score, c.conf) })
			v := screens[c.mode](req, core.PolicyRule{Jev: c.thresholds})
			if _, bodies := f.take(); len(bodies) != 1 {
				t.Fatalf("%s: calls = %d, want 1", c.name, len(bodies))
			}
			if v.Risk != c.risk || v.Route != c.route || v.Reason != c.reason || !slices.Equal(v.Labels, c.labels) ||
				v.Severity == nil || *v.Severity != c.severity || v.Model != JevModel || v.Error != "" {
				t.Fatalf("%s: verdict = %+v, want %s %q %q %q severity %d", c.name, v, c.risk, c.route, c.reason, c.labels, c.severity)
			}
		}
	})
}

// TestJevStateNeverCarriesSecrets runs a command through ExecBlind with the screen on and checks
// what reached the fake API: the purpose and both homes, shortened, are there (the positive
// control), and no master, lease, output, Jev key, or absolute home is.
func TestJevStateNeverCarriesSecrets(t *testing.T) {
	const key, master = "tsk_jev_key_canary_5f2a9c", "cf_master_canary_77d1e0"
	ctx := context.Background()
	f := newJevFake(t)
	userHome, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", userHome)
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	reg := core.NewRegistry()
	_ = reg.Register(kv)
	_ = reg.Register(&relayTestProvider{})
	for k, v := range map[string]string{JevKey: key, "cf-relay": master} {
		if err := kv.SetSecret(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	rt := core.NewRuntime(home, "keychain", reg)
	rt.Screen = JevScreen(rt, JevConfig{Mode: "deny"})
	rt.ApprovalFunc = func(context.Context, core.ExecRequest) (bool, error) { return false, nil }
	work := filepath.Join(home, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	req := core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "cf-relay", Scope: "zone-1", Params: map[string]string{"note": filepath.Join(userHome, "p")}},
		Command:     []string{"sh", "-c", `printf '%s%s\n' OUT_ CANARY; printf '%s\n' "$CF_API_TOKEN"`, filepath.Join(userHome, "file")},
		WorkingDir:  work,
		Purpose:     "PURPOSE_CANARY reads " + filepath.Join(userHome, "notes"),
	}
	res, err := rt.ExecBlind(ctx, req)
	if err != nil || res.ExitCode != 0 || res.Stdout != "OUT_CANARY\n[MINTRUN:REDACTED]\n" {
		t.Fatalf("ExecBlind = %+v, %v", res, err)
	}
	auth, bodies := f.take()
	if len(bodies) != 1 || !slices.Equal(auth, []string{"POST Bearer " + key + " application/json"}) {
		t.Fatalf("calls = %q", auth)
	}
	body := string(bodies[0])
	for _, want := range []string{`"purpose":"PURPOSE_CANARY reads ~/notes"`, `"cwd":"$MINTRUN_HOME/work"`, `"~/file"`, `"note":"~/p"`, `"provider":"cf-relay"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body lacks %s: %s", want, body)
		}
	}
	for _, leak := range []string{master, key, "lease-cf-12345", "cf_jit_secret_token_987654", "revoke-only-server-secret-9999", "OUT_CANARY", userHome, home} {
		if strings.Contains(body, leak) {
			t.Fatalf("body holds %q: %s", leak, body)
		}
	}

	// An error that echoes the key reaches the audit log scrubbed.
	f.on(func(int) (int, string) { return 401, `{"error":"bad key ` + key + `"}` })
	if _, err := rt.ExecBlind(ctx, req); err == nil || !strings.Contains(err.Error(), "approval rejected") {
		t.Fatalf("ExecBlind error = %v, want the approval rejected", err)
	}
	entries := readAuditLines(t, home)
	if e := entries[len(entries)-1]; e.JevRisk != "unknown" || e.JevError != `jev systemone: HTTP 401: {"error":"bad key [MINTRUN:REDACTED]"}` {
		t.Fatalf("audit entry = %+v", e)
	}
	if log, err := os.ReadFile(filepath.Join(home, "audit.jsonl")); err != nil || strings.Contains(string(log), key) || strings.Contains(string(log), master) {
		t.Fatalf("audit.jsonl holds a secret (%v): %s", err, log)
	}
}
