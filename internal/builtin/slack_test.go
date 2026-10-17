package builtin

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ninja-c9/mintrun/internal/core"
)

func TestSlackApproval(t *testing.T) {
	const user, bot, token, dm, ts = "U0OWNER", "U0BOT", "xoxb-1-TEST-slacktoken", "D0DM", "1700000000.000100"
	oldAPI, oldTimeout, oldPoll := slackAPI, slackTimeout, slackPoll
	t.Cleanup(func() { slackAPI, slackTimeout, slackPoll = oldAPI, oldTimeout, oldPoll })
	slackPoll = 10 * time.Millisecond
	slackAPI = failingAPI(t) // the config checks below must refuse before sending anything

	t.Setenv("MINTRUN_VAULT_KEY", "slack-test-passphrase")
	home := t.TempDir()
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	reg := core.NewRegistry()
	if err := reg.Register(kv); err != nil {
		t.Fatal(err)
	}
	approve := SlackApproval(core.NewRuntime(home, "keychain", reg))
	req := core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "github", Scope: "owner/repo", Permissions: []string{"contents:read"}, Params: map[string]string{"installation_id": "7"}},
		Vault:       "agent-chosen", // never where the approval config is read from
		Command:     []string{"gh", "pr", "list", "x\n✅ Allowed <!channel> <@U0EVIL> <https://example.com|details> &amp;"},
	}
	ctx := context.Background()

	if _, err := approve(ctx, req); err == nil || err.Error() != `slack approval: not configured: secret "approval-slack" not found in vault (run mintrun init slack)` {
		t.Fatalf("no config: got %v, want a not-configured error naming mintrun init slack once", err)
	}
	for _, bad := range []string{"SECRETVALUE", "U0OWNER:SECRETVALUE", "u0owner:xoxb-SECRETVALUE", "C0CHAN:xoxb-SECRETVALUE",
		":xoxb-SECRETVALUE", "U0OWNER:xoxb-SECRET/VALUE", "U0OWNER:xoxp-SECRETVALUE"} {
		if err := kv.SetSecret(ctx, SlackApprovalKey, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := approve(ctx, req); err == nil || !strings.Contains(err.Error(), "must be <user_id>:<bot_token>") || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("config %q: got %v, want a format error that quotes no secret", bad, err)
		}
	}
	stored := ""
	setUser := func(u string) {
		if stored != u {
			if err := kv.SetSecret(ctx, SlackApprovalKey, u+":"+token+"\n"); err != nil {
				t.Fatal(err)
			}
			stored = u
		}
	}

	type reply struct {
		status     int // 0 drops the connection
		retryAfter int
		body       string
	}
	allow := []map[string][]string{{"white_check_mark": {user}}}
	cases := []struct {
		name         string
		cfgUser      string // the user ID in the config; user when empty
		timeout      time.Duration
		cancelOnPoll bool                  // the caller cancels once polling starts, as FirstApproval does
		polls        []map[string][]string // each answered reactions.get's reactions besides the bot's; the last repeats
		fails        map[string]reply      // "<method> <n>" (n counts that method's calls) gets this reply instead
		ok           bool
		err          string
		outcome      string
	}{
		{name: "allow", polls: allow, ok: true, outcome: "✅ Allowed"},
		{name: "other users and other emoji are ignored", polls: []map[string][]string{
			{"white_check_mark": {"U0OTHER"}, "heavy_check_mark": {user}, "+1": {user}},
			{"white_check_mark": {"U0OTHER"}, "heavy_check_mark": {user}, "+1": {user}, "x": {user}},
		}, outcome: "⛔ Denied"},
		{name: "deny wins over allow", polls: []map[string][]string{{"white_check_mark": {user}, "x": {user}}}, outcome: "⛔ Denied"},
		{name: "dropped connections, server errors and rate limits are retried", polls: allow, fails: map[string]reply{
			"reactions.get 1": {status: 0},
			"reactions.get 2": {status: http.StatusServiceUnavailable, body: `{"ok":false,"error":"service_unavailable"}`},
			"reactions.get 3": {status: http.StatusOK, body: "<html>"},
			"reactions.get 4": {status: http.StatusTooManyRequests, retryAfter: 1, body: `{"ok":false,"error":"ratelimited"}`},
		}, ok: true, outcome: "✅ Allowed"},
		{name: "no answer", timeout: 100 * time.Millisecond, err: "slack: no answer within 100ms", outcome: "⌛ Expired"},
		{name: "answered elsewhere", cancelOnPoll: true, polls: allow, err: "context canceled", outcome: "⌛ Closed"},
		{name: "an API error is never retried", polls: allow, fails: map[string]reply{
			"reactions.get 1": {status: http.StatusOK, body: `{"ok":false,"error":"missing_scope","needed":"reactions:read"}`},
		}, err: "slack reactions.get: HTTP 200: missing_scope (needed: reactions:read)", outcome: "⚠️ Not approved"},
		{name: "both reactions must land", polls: allow, fails: map[string]reply{
			"reactions.add 2": {status: http.StatusOK, body: `{"ok":false,"error":"missing_scope","needed":"reactions:write"}`},
		}, err: "slack reactions.add: HTTP 200: missing_scope (needed: reactions:write)", outcome: "⚠️ Not approved"},
		{name: "a config naming the bot itself denies", cfgUser: bot, outcome: "⛔ Denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgUser := cmp.Or(tc.cfgUser, user)
			setUser(cfgUser)
			slackTimeout = cmp.Or(tc.timeout, 5*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var (
				mu     sync.Mutex
				calls  = map[string]int{}
				polled int
				posted string
				added  []string
				edits  []string
				until  time.Time // the last 429's Retry-After: no call may come sooner
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method := strings.TrimPrefix(r.URL.Path, "/")
				if err := r.ParseForm(); err != nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+token ||
					r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || strings.Contains(r.URL.String()+r.Form.Encode(), token) {
					t.Errorf("unexpected request %s %s (form error %v): the token belongs in the Authorization header only", r.Method, r.URL.Path, err)
				}
				f := r.PostForm
				msg := func(tsKey string) {
					if f.Get("channel") != dm || f.Get(tsKey) != ts {
						t.Errorf("%s on channel %q, %s %q: want the DM %q and the message %q", method, f.Get("channel"), tsKey, f.Get(tsKey), dm, ts)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if now := time.Now(); now.Before(until) {
					t.Errorf("%s came %s before Retry-After passed", method, until.Sub(now))
				}
				calls[method]++
				if method == "reactions.get" && tc.cancelOnPoll {
					cancel()
				}
				if fail, ok := tc.fails[fmt.Sprint(method, " ", calls[method])]; ok {
					if fail.status == 0 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
					if fail.retryAfter > 0 {
						w.Header().Set("Retry-After", strconv.Itoa(fail.retryAfter))
						until = time.Now().Add(time.Duration(fail.retryAfter) * time.Second)
					}
					w.WriteHeader(fail.status)
					_, _ = w.Write([]byte(fail.body))
					return
				}
				out := map[string]any{"ok": true}
				switch method {
				case "chat.postMessage":
					for k, v := range map[string]string{"channel": cfgUser, "mrkdwn": "false", "parse": "none", "link_names": "false", "unfurl_links": "false", "unfurl_media": "false"} {
						if f.Get(k) != v {
							t.Errorf("chat.postMessage %s=%q, want %q", k, f.Get(k), v)
						}
					}
					posted = f.Get("text")
					out["channel"], out["ts"] = dm, ts
				case "reactions.add":
					msg("timestamp")
					added = append(added, f.Get("name"))
				case "reactions.get":
					msg("timestamp")
					if f.Get("full") != "true" {
						t.Errorf("reactions.get full=%q, want true: without it Slack may list only some of the users", f.Get("full"))
					}
					if !slices.Equal(added, []string{"white_check_mark", "x"}) {
						t.Errorf("polled after adding %q, want ✅ and ❌ added first", added)
					}
					users := map[string][]string{}
					for _, name := range added {
						users[name] = append(users[name], bot)
					}
					if polled++; len(tc.polls) > 0 {
						for name, us := range tc.polls[min(polled, len(tc.polls))-1] {
							users[name] = append(users[name], us...)
						}
					}
					var reactions []map[string]any
					for _, name := range slices.Sorted(maps.Keys(users)) { // ✅ comes before ❌
						reactions = append(reactions, map[string]any{"name": name, "users": users[name], "count": len(users[name])})
					}
					out["message"] = map[string]any{"type": "message", "ts": ts, "reactions": reactions}
				case "chat.update":
					msg("ts")
					if f.Get("parse") != "none" || f.Get("link_names") != "false" {
						t.Errorf("chat.update parse=%q link_names=%q, want none and false", f.Get("parse"), f.Get("link_names"))
					}
					edits = append(edits, f.Get("text"))
				default:
					t.Errorf("unexpected method %q", method)
				}
				_ = json.NewEncoder(w).Encode(out)
			}))
			defer srv.Close()
			slackAPI = srv.URL

			ok, err := approve(ctx, req)
			if ok != tc.ok || (err == nil) != (tc.err == "") || err != nil && !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("got (%v, %v), want (%v, %q)", ok, err, tc.ok, tc.err)
			}
			mu.Lock()
			defer mu.Unlock()
			// Every <, > and & is escaped, so no argument can mention @channel, a user, or a link.
			want := "🔐 mintrun approval request\n\nProvider: \"github\"\nVault: \"agent-chosen\"\nScope: \"owner/repo\"\n" +
				"Permissions: \"contents:read\"\nParams: \"installation_id\"=\"7\"\n" +
				"Command: \"gh\" \"pr\" \"list\" \"x\\n✅ Allowed &lt;!channel&gt; &lt;@U0EVIL&gt; &lt;https://example.com|details&gt; &amp;amp;\"\n" +
				"Working directory: (not set: mintrun's own)"
			if posted != want+"\n\nReact ✅ to allow or ❌ to deny." {
				t.Errorf("message:\n%s\nwant:\n%s", posted, want)
			}
			if len(edits) != 1 || !strings.HasPrefix(edits[0], want+"\n\n"+tc.outcome) {
				t.Errorf("edits %q, want one that appends %q", edits, tc.outcome)
			}
		})
	}

	// The token rides in the Authorization header, and no error may quote it, even one Slack echoes.
	setUser(user)
	slackTimeout = time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth for ` + token + `"}`))
	}))
	slackAPI = srv.URL
	if _, err := approve(ctx, req); err == nil || !strings.Contains(err.Error(), "slack chat.postMessage: HTTP 200: invalid_auth for "+core.RedactedPlaceholder) {
		t.Fatalf("echoed token: got %v, want it scrubbed", err)
	}
	srv.Close()
	if _, err := approve(ctx, req); err == nil || strings.Contains(err.Error(), token) || !strings.HasPrefix(err.Error(), "slack chat.postMessage: ") {
		t.Fatalf("unreachable: got %v", err)
	}

	// A long request is cut short enough to fit once escaped, and the cut splits neither an entity
	// nor a rune.
	for _, fill := range []string{"<", "&", "é"} {
		for pad := range 5 {
			long := slackText(core.ExecRequest{Command: []string{strings.Repeat("a", pad) + strings.Repeat(fill, 2000)}})
			body, cut := strings.CutSuffix(long, "\n\n⚠️ TRUNCATED: the request is longer than this message. Deny unless you know the rest.")
			if !cut || len(body) > 3500 || !utf8.ValidString(long) || strings.ContainsAny(body, "<>") ||
				strings.Count(body, "&") != strings.Count(body, "&amp;")+strings.Count(body, "&lt;")+strings.Count(body, "&gt;") {
				t.Fatalf("fill %q, pad %d: %d bytes, valid UTF-8 %v, tail %q", fill, pad, len(long), utf8.ValidString(long), long[max(0, len(long)-130):])
			}
		}
	}
}
