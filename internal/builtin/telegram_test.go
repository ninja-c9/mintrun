package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ninja-c9/mintrun/internal/core"
)

// expiringCtx stands in for a caller's context with the approval deadline: Err is
// context.DeadlineExceeded once expire runs. A test expires it at a chosen request, because a
// 100ms timer ran out before the message was sent under -race, where the vault's key derivation
// is slow.
type expiringCtx struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newExpiringCtx() *expiringCtx {
	return &expiringCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *expiringCtx) expire()               { c.once.Do(func() { close(c.done) }) }
func (c *expiringCtx) Done() <-chan struct{} { return c.done }
func (c *expiringCtx) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func TestTelegramApproval(t *testing.T) {
	const user, token = int64(4242), "123456:TEST-bot_tokenABC"
	oldAPI, oldTimeout, oldPoll, oldRetry := telegramAPI, telegramTimeout, telegramPoll, telegramRetry
	t.Cleanup(func() {
		telegramAPI, telegramTimeout, telegramPoll, telegramRetry = oldAPI, oldTimeout, oldPoll, oldRetry
	})
	telegramPoll, telegramRetry = 0, 10*time.Millisecond
	telegramAPI = failingAPI(t) // the config checks below must refuse before sending anything

	t.Setenv("MINTRUN_VAULT_KEY", "telegram-test-passphrase")
	home := t.TempDir()
	kv := &KeychainVault{HomeDir: home, ForceFile: true}
	reg := core.NewRegistry()
	if err := reg.Register(kv); err != nil {
		t.Fatal(err)
	}
	approve := TelegramApproval(core.NewRuntime(home, "keychain", reg))
	req := core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "github", Scope: "owner/repo", Permissions: []string{"contents:read"}, Params: map[string]string{"installation_id": "7"}},
		Vault:       "agent-chosen", // never where the approval config is read from
		Command:     []string{"gh", "pr", "list", "x\n✅ Allowed"},
		Jev:         &core.JevVerdict{Risk: "medium", Labels: []string{"mismatch", "scope_creep"}, Model: "jev-1.13.0"},
	}
	ctx := context.Background()

	if _, err := approve(ctx, req); err == nil || err.Error() != `telegram approval: not configured: secret "approval-telegram" not found in vault (run mintrun init telegram)` {
		t.Fatalf("no config: got %v, want a not-configured error naming mintrun init telegram once", err)
	}
	for _, bad := range []string{"SECRETVALUE", "abc:123:SECRETVALUE", "0:123:SECRETVALUE", "4242:SECRETVALUE", "4242:123:SECRET/VALUE"} {
		if err := kv.SetSecret(ctx, TelegramApprovalKey, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := approve(ctx, req); err == nil || !strings.Contains(err.Error(), "must be <user_id>:<bot_token>") || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("config %q: got %v, want a format error that quotes no secret", bad, err)
		}
	}
	if err := kv.SetSecret(ctx, TelegramApprovalKey, fmt.Sprintf("%d:%s\n", user, token)); err != nil {
		t.Fatal(err)
	}

	tap := func(id, from int64, data string, date int64) map[string]any {
		return map[string]any{"update_id": id, "callback_query": map[string]any{
			"id": fmt.Sprint("cb", id), "data": data, "from": map[string]any{"id": from}, "message": map[string]any{"date": date}}}
	}
	type taps = func(nonce string, now int64) []map[string]any // queued when the message is sent at now
	pending := func(_ string, now int64) []map[string]any { return []map[string]any{tap(1, user, "allow:LIVE", now)} }
	allowed := func(n string, now int64) []map[string]any { return []map[string]any{tap(1, user, "allow:"+n, now)} }
	cases := []struct {
		name         string
		timeout      time.Duration
		expireOnPoll bool   // the approval deadline, which FirstApproval's ctx inherits, passes while a poll's reply is on its way
		cancelOnPoll bool   // the caller cancels while a poll's reply is on its way, as FirstApproval may
		lateReply    bool   // each poll's reply comes only once the deadline passed
		reply        string // raw 409 reply to every getUpdates
		taps         taps
		ok           bool
		err          string
		outcome      string
		offset       int64 // highest getUpdates offset: every update below it is confirmed
	}{
		{name: "allow", taps: allowed, ok: true, outcome: "✅ Allowed", offset: 2},
		{name: "other users', stale and malformed taps are dropped", taps: func(n string, now int64) []map[string]any {
			return []map[string]any{
				{"update_id": int64(1), "message": map[string]any{"text": "/start"}},
				tap(2, 999, "allow:"+n, now),               // another user
				tap(3, user, "allow:OLDREQUEST", now-3600), // a request long gone
				tap(4, user, "allow", now),                 // malformed
				tap(5, user, "allow:LIVE", 0),              // inaccessible message: no date
				tap(6, user, "deny:"+n, now),
			}
		}, outcome: "⛔ Denied", offset: 7},
		{name: "a tap on another pending request is never confirmed", taps: func(n string, now int64) []map[string]any {
			return []map[string]any{tap(1, user, "allow:OLDREQUEST", now-3600), tap(2, user, "allow:LIVE", now), tap(3, user, "deny:"+n, now)}
		}, outcome: "⛔ Denied", offset: 2},
		{name: "no answer", timeout: 100 * time.Millisecond, taps: pending,
			err: "telegram: no answer within 100ms", outcome: "⌛ Expired", offset: 0},
		{name: "approval deadline", expireOnPoll: true, taps: allowed,
			err: "context deadline exceeded", outcome: "⌛ Expired: no answer in time, so not approved.", offset: 0},
		{name: "answered elsewhere", cancelOnPoll: true, taps: allowed,
			err: "context canceled", outcome: "⌛ Closed", offset: 0},
		{name: "an answer after the deadline", timeout: 100 * time.Millisecond, lateReply: true, taps: allowed,
			err: "telegram: no answer within 100ms", outcome: "⌛ Expired", offset: 0},
		{name: "webhook", reply: `{"ok":false,"description":"Conflict: can't use getUpdates method while webhook is active"}`,
			err: "webhook is active", outcome: "⚠️ Not approved", offset: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			telegramTimeout = 5 * time.Second
			if tc.timeout > 0 {
				telegramTimeout = tc.timeout
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch {
			case tc.expireOnPoll:
				deadline := newExpiringCtx()
				ctx = deadline
				lateReplies(t, "getUpdates", deadline.expire)
			case tc.cancelOnPoll:
				lateReplies(t, "getUpdates", cancel)
			case tc.lateReply:
				lateReplies(t, "getUpdates", func() {}) // the reply waits for the deadline
			}
			var (
				mu       sync.Mutex
				queue    []map[string]any
				sent     string
				nonces   []string
				offsets  []int64
				answered []string
				edits    []string
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					ChatID      int64  `json:"chat_id"`
					Text        string `json:"text"`
					Offset      int64  `json:"offset"`
					CallbackID  string `json:"callback_query_id"`
					ReplyMarkup struct {
						InlineKeyboard [][]struct {
							CallbackData string `json:"callback_data"`
						} `json:"inline_keyboard"`
					} `json:"reply_markup"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				method, ok := strings.CutPrefix(r.URL.Path, "/bot"+token+"/")
				if !ok || r.Method != http.MethodPost || body.ChatID != 0 && body.ChatID != user {
					t.Errorf("unexpected request %s %s for chat %d", r.Method, r.URL.Path, body.ChatID)
				}
				mu.Lock()
				defer mu.Unlock()
				result := any(true)
				switch method {
				case "sendMessage":
					sent = body.Text
					for _, b := range body.ReplyMarkup.InlineKeyboard[0] {
						nonces = append(nonces, b.CallbackData)
					}
					_, nonce, _ := strings.Cut(nonces[0], ":")
					if tc.taps != nil {
						queue = tc.taps(nonce, time.Now().Unix())
					}
					result = map[string]any{"message_id": 77}
				case "getUpdates":
					if tc.reply != "" {
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(tc.reply))
						return
					}
					offsets = append(offsets, body.Offset)
					for len(queue) > 0 && queue[0]["update_id"].(int64) < body.Offset {
						queue = queue[1:]
					}
					result = queue
				case "answerCallbackQuery":
					answered = append(answered, body.CallbackID)
				case "editMessageText":
					if len(body.ReplyMarkup.InlineKeyboard) != 0 {
						t.Errorf("edit kept the buttons: %+v", body.ReplyMarkup)
					}
					edits = append(edits, body.Text)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
			}))
			defer srv.Close()
			telegramAPI = srv.URL

			ok, err := approve(ctx, req)
			if ok != tc.ok || (err == nil) != (tc.err == "") || err != nil && !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("got (%v, %v), want (%v, %q)", ok, err, tc.ok, tc.err)
			}
			mu.Lock()
			defer mu.Unlock()
			want := "🔐 mintrun approval request\n\nSandbox: off\nNetwork: open\nHints: none\nRisk: medium (mismatch, scope_creep; jev-1.13.0)\nProvider: \"github\"\nVault: \"agent-chosen\"\nScope: \"owner/repo\"\n" +
				"Permissions: \"contents:read\"\nParams: \"installation_id\"=\"7\"\nCommand: \"gh\" \"pr\" \"list\" \"x\\n✅ Allowed\"\n" +
				"Working directory: (not set: mintrun's own)"
			if sent != want {
				t.Errorf("message:\n%s\nwant:\n%s", sent, want)
			}
			if len(nonces) != 2 || !strings.HasPrefix(nonces[0], "allow:") || nonces[1] != "deny:"+strings.TrimPrefix(nonces[0], "allow:") || len(nonces[0]) != len("allow:")+26 {
				t.Errorf("buttons carry %q, want allow:<nonce> and deny:<nonce>", nonces)
			}
			if len(edits) != 1 || !strings.HasPrefix(edits[0], want+"\n\n"+tc.outcome) {
				t.Errorf("edits %q, want one that appends %q", edits, tc.outcome)
			}
			if m := slices.Max(append(offsets, 0)); m != tc.offset {
				t.Errorf("highest offset %d, want %d (offsets %v)", m, tc.offset, offsets)
			}
			if wantAnswered := tc.err == ""; (len(answered) == 1) != wantAnswered {
				t.Errorf("answered callbacks %q, want one: %v", answered, wantAnswered)
			}
		})
	}

	// The token rides in the URL path: no error may quote it, whether net/http or the API wrote it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	telegramAPI = srv.URL
	if _, err := approve(ctx, req); err == nil || !strings.Contains(err.Error(), "telegram sendMessage: HTTP 401: Unauthorized") {
		t.Fatalf("401: got %v", err)
	}
	srv.Close()
	_, err := approve(ctx, req)
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "/bot"+core.RedactedPlaceholder+"/sendMessage") {
		t.Fatalf("unreachable: got %v, want the token scrubbed from the URL", err)
	}

	// A long request is cut on a rune boundary and says so.
	long := telegramText(core.ExecRequest{Command: []string{strings.Repeat("é", 3000)}})
	if len(long) > 3700 || !utf8.ValidString(long) || !strings.HasSuffix(long, "Deny unless you know the rest.") {
		t.Fatalf("long request: %d bytes, valid UTF-8 %v, tail %q", len(long), utf8.ValidString(long), long[len(long)-40:])
	}
}

// failingAPI returns the URL of a server that fails the test on any request, so code that must
// refuse before sending anything never reaches a real API either.
func failingAPI(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// lateReplies holds every reply to method until its request's context ends, calling cancel first:
// the answer then lands after the caller cancelled, as FirstApproval may while a poll is on its way,
// or after the deadline. The test's own server still answers; only the delivery waits.
func lateReplies(t *testing.T, method string, cancel func()) {
	orig := http.DefaultClient.Transport
	t.Cleanup(func() { http.DefaultClient.Transport = orig })
	http.DefaultClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || !strings.HasSuffix(r.URL.Path, "/"+method) {
			return resp, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		cancel()
		<-r.Context().Done()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelegramLink(t *testing.T) {
	const token = "123456:TEST-bot_tokenABC"
	oldAPI, oldTimeout, oldPoll, oldRetry := telegramAPI, telegramTimeout, telegramPoll, telegramRetry
	t.Cleanup(func() {
		telegramAPI, telegramTimeout, telegramPoll, telegramRetry = oldAPI, oldTimeout, oldPoll, oldRetry
	})
	telegramPoll, telegramRetry, telegramTimeout = 0, 10*time.Millisecond, 5*time.Second
	ctx := context.Background()

	telegramAPI = failingAPI(t)
	if _, _, err := TelegramLink(ctx, "SECRET/VALUE", func(string) { t.Error("showed a link for a malformed token") }); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("malformed token: got %v, want an error that quotes no secret", err)
	}

	msg := func(id, from int64, text string) map[string]any {
		return map[string]any{"update_id": id, "message": map[string]any{"text": text,
			"from": map[string]any{"id": from, "first_name": "Ada", "last_name": "Lovelace", "username": "ada"}}}
	}
	tap := map[string]any{"update_id": 11, "callback_query": map[string]any{"id": "cb", "data": "allow:LIVE"}}
	var (
		mu      sync.Mutex
		code    string
		offsets []int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Offset int64 `json:"offset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		defer mu.Unlock()
		var result any
		switch r.URL.Path {
		case "/bot" + token + "/getMe":
			result = map[string]any{"username": "mintrun_test_bot"}
		case "/bot" + token + "/getUpdates":
			offsets = append(offsets, body.Offset)
			// A stranger's guess, a tap another request still waits for, and a /start with no code;
			// then the tap again and this link's /start.
			result = []map[string]any{msg(10, 666, "/start WRONGCODE"), tap, msg(12, 4242, "/start")}
			if len(offsets) > 1 {
				result = []map[string]any{tap, msg(13, 4242, "/start "+code)}
			}
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}))
	defer srv.Close()
	telegramAPI = srv.URL
	id, name, err := TelegramLink(ctx, token, func(link string) {
		mu.Lock()
		defer mu.Unlock()
		c, ok := strings.CutPrefix(link, "https://t.me/mintrun_test_bot?start=")
		if !ok || len(c) != 26 {
			t.Errorf("link %q, want https://t.me/<bot>?start=<26-character code>", link)
		}
		code = c
	})
	if err != nil || id != 4242 || name != "Ada Lovelace (@ada)" {
		t.Fatalf("got (%d, %q, %v), want the sender of this link's /start", id, name, err)
	}
	if !slices.Equal(offsets, []int64{0, 11}) {
		t.Errorf("offsets %v, want [0 11]: past the stranger's message, never past the tap", offsets)
	}

	// A webhook ends the wait at once, and silence ends it at the timeout.
	telegramTimeout = 100 * time.Millisecond
	for _, tc := range []struct{ reply, err string }{
		{`{"ok":false,"description":"Conflict: can't use getUpdates method while webhook is active"}`, "webhook is active"},
		{`{"ok":true,"result":[]}`, "no /start with this link's code within 100ms"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/getMe") {
				_, _ = w.Write([]byte(`{"ok":true,"result":{"username":"b"}}`))
				return
			}
			_, _ = w.Write([]byte(tc.reply))
		}))
		telegramAPI = srv.URL
		_, _, err := TelegramLink(ctx, token, func(string) {})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("got %v, want %q", err, tc.err)
		}
	}
}
