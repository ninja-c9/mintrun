package builtin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// TelegramApprovalKey is the default-vault key that holds "<user_id>:<bot_token>" for TelegramApproval.
const TelegramApprovalKey = "approval-telegram"

// Vars so tests can point at a fake Bot API and shorten the waits.
var (
	telegramAPI     = "https://api.telegram.org"
	telegramTimeout = 10 * time.Minute
	telegramPoll    = 25 // getUpdates long-poll seconds
	telegramRetry   = 2 * time.Second
)

var telegramTokenRe = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

type telegramUpdate struct {
	UpdateID      int64 `json:"update_id"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Message struct {
			Date int64 `json:"date"`
		} `json:"message"`
	} `json:"callback_query"`
}

// TelegramApproval asks through a Telegram bot: it messages the user named in the default vault's
// approval-telegram secret ("<user_id>:<bot_token>") with Allow and Deny buttons, and only that
// user's tap on this request's buttons answers. The secret comes from rt.DefaultVault, never
// req.Vault, because an agent that picked the vault could route approvals to a bot it controls.
// Not configured, unreachable, or no answer within telegramTimeout is an error, so FirstApproval
// keeps waiting for the other channels.
func TelegramApproval(rt *core.Runtime) func(context.Context, core.ExecRequest) (bool, error) {
	return func(ctx context.Context, req core.ExecRequest) (bool, error) {
		vault, err := rt.Registry.Vault(rt.DefaultVault)
		if err != nil {
			return false, fmt.Errorf("telegram approval: %v", err)
		}
		cfg, err := vault.GetSecret(ctx, TelegramApprovalKey)
		if err != nil {
			return false, fmt.Errorf("telegram approval: not configured (mintrun secret set %s): %v", TelegramApprovalKey, err)
		}
		user, token, _ := strings.Cut(strings.TrimSpace(cfg), ":")
		userID, err := strconv.ParseInt(user, 10, 64)
		if err != nil || userID <= 0 || !telegramTokenRe.MatchString(token) {
			// Neither cfg nor err is quoted: both can hold the token.
			return false, fmt.Errorf("telegram approval: %s must be <user_id>:<bot_token>", TelegramApprovalKey)
		}
		return telegramApprove(ctx, token, userID, req)
	}
}

func telegramApprove(ctx context.Context, token string, user int64, req core.ExecRequest) (bool, error) {
	nonce := rand.Text()
	text := telegramText(req)
	keyboard := [][]map[string]string{{
		{"text": "✅ Allow", "callback_data": "allow:" + nonce},
		{"text": "⛔ Deny", "callback_data": "deny:" + nonce},
	}}
	var sent struct {
		MessageID int64 `json:"message_id"`
	}
	if err := telegramCall(ctx, token, "sendMessage", map[string]any{"chat_id": user, "text": text,
		"reply_markup": map[string]any{"inline_keyboard": keyboard}}, &sent); err != nil {
		return false, err
	}
	outcome := "⌛ Closed: answered on another channel, or canceled."
	defer func() {
		// Best effort, even once ctx is done: show the outcome and drop the buttons.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = telegramCall(ctx, token, "editMessageText", map[string]any{"chat_id": user, "message_id": sent.MessageID,
			"text": text + "\n\n" + outcome, "reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{}}}, nil)
	}()

	pollCtx, cancel := context.WithTimeout(ctx, telegramTimeout)
	defer cancel()
	var offset int64
	for pollCtx.Err() == nil {
		var updates []telegramUpdate
		err := telegramCall(pollCtx, token, "getUpdates", map[string]any{"offset": offset, "timeout": telegramPoll}, &updates)
		if err != nil && strings.Contains(err.Error(), "webhook") {
			outcome = "⚠️ Not approved: this bot has a webhook, so mintrun cannot read taps. Use a dedicated bot."
			return false, err
		}
		// An offset confirms (deletes) every update below it, so it never passes a recent tap on
		// another request: that tap belongs to the mintrun process still waiting for it.
		blocked := false
		for _, u := range updates {
			cq := u.CallbackQuery
			fromUser := cq != nil && cq.From.ID == user
			if fromUser && (cq.Data == "allow:"+nonce || cq.Data == "deny:"+nonce) {
				if !blocked {
					offset = u.UpdateID + 1
				}
				// Best effort: confirm through this tap so later polls skip it, and stop the spinner.
				_ = telegramCall(pollCtx, token, "getUpdates", map[string]any{"offset": offset, "timeout": 0}, nil)
				_ = telegramCall(pollCtx, token, "answerCallbackQuery", map[string]any{"callback_query_id": cq.ID}, nil)
				if strings.HasPrefix(cq.Data, "deny:") {
					outcome = "⛔ Denied"
					return false, nil
				}
				outcome = "✅ Allowed"
				return true, nil
			}
			if fromUser && (strings.HasPrefix(cq.Data, "allow:") || strings.HasPrefix(cq.Data, "deny:")) &&
				cq.Message.Date >= time.Now().Add(-2*telegramTimeout).Unix() {
				blocked = true
			}
			if !blocked {
				offset = u.UpdateID + 1
			}
		}
		// Retry an error; while another request's tap is queued, a long poll returns at once.
		if err != nil || blocked {
			select {
			case <-pollCtx.Done():
			case <-time.After(telegramRetry):
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	outcome = fmt.Sprintf("⌛ Expired: no answer within %s, so not approved.", telegramTimeout)
	return false, fmt.Errorf("telegram: no answer within %s", telegramTimeout)
}

// telegramText quotes every agent-supplied field, so no argument can fake a line or a verdict,
// and goes out as plain text (no parse_mode), so nothing in it is markup.
func telegramText(req core.ExecRequest) string {
	quote := func(list []string) string {
		q := make([]string, len(list))
		for i, s := range list {
			q[i] = strconv.Quote(s)
		}
		return strings.Join(q, " ")
	}
	params := make([]string, 0, len(req.Params))
	for k, v := range req.Params {
		params = append(params, strconv.Quote(k)+"="+strconv.Quote(v))
	}
	sort.Strings(params)
	text := fmt.Sprintf("🔐 mintrun approval request\n\nProvider: %q\nScope: %q\nPermissions: %s\nParams: %s\nCommand: %s",
		req.Provider, req.Scope, quote(req.Permissions), strings.Join(params, " "), quote(req.Command))
	if len(text) > 3500 { // Telegram caps a message at 4096 characters
		text = strings.ToValidUTF8(text[:3500], "") + "\n\n⚠️ TRUNCATED: the request is longer than this message. Deny unless you know the rest."
	}
	return text
}

// telegramCall POSTs one Bot API method and decodes its result into out (when non-nil). The token
// rides in the URL path, which net/http errors quote, so every error is scrubbed of it.
func telegramCall(ctx context.Context, token, method string, body, out any) error {
	err := func() error {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(telegramPoll+15)*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, telegramAPI+"/bot"+token+"/"+method, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var r struct {
			OK          bool            `json:"ok"`
			Description string          `json:"description"`
			Result      json.RawMessage `json:"result"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r) != nil {
			return fmt.Errorf("HTTP %d, malformed reply", resp.StatusCode)
		}
		if !r.OK {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, r.Description)
		}
		if out != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}()
	if err != nil {
		return fmt.Errorf("telegram %s: %s", method, core.Scrub(err.Error(), []string{token}))
	}
	return nil
}
