package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// SlackApprovalKey is the default-vault key that holds "<user_id>:<bot_token>" for SlackApproval.
const SlackApprovalKey = "approval-slack"

// Vars so tests can point at a fake Web API and shorten the waits.
var (
	slackAPI     = "https://slack.com/api"
	slackTimeout = 10 * time.Minute
	slackPoll    = 3 * time.Second // reactions.get is Tier 3: 50+ calls a minute
)

var (
	slackUserRe  = regexp.MustCompile(`^[UW][A-Z0-9]+$`)
	slackTokenRe = regexp.MustCompile(`^xoxb-[A-Za-z0-9-]+$`)
	// Slack reads &, < and > as control characters in any text; escaped, no field can open
	// <!channel>, <@U…> or a <url|label> link.
	slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
)

// SlackApproval asks through a Slack bot: it DMs the user named in the default vault's
// approval-slack secret ("<user_id>:<bot_token>"), adds ✅ and ❌ to the message, and polls its
// reactions until that user picks one; ❌ wins over ✅. Polling needs no public endpoint, only the
// bot scopes chat:write, reactions:read and reactions:write. The secret comes from rt.DefaultVault,
// never req.Vault, as in TelegramApproval. Not configured, unreachable, an API error, or no answer
// within slackTimeout is an error, so FirstApproval keeps waiting for the other channels.
func SlackApproval(rt *core.Runtime) func(context.Context, core.ExecRequest) (bool, error) {
	return func(ctx context.Context, req core.ExecRequest) (bool, error) {
		vault, err := rt.Registry.Vault(rt.DefaultVault)
		if err != nil {
			return false, fmt.Errorf("slack approval: %v", err)
		}
		cfg, err := vault.GetSecret(ctx, SlackApprovalKey)
		if err != nil {
			return false, fmt.Errorf("slack approval: not configured: %v", err)
		}
		user, token, err := ParseSlackConfig(cfg)
		if err != nil {
			return false, fmt.Errorf("slack approval: %v", err)
		}
		return slackApprove(ctx, token, user, req)
	}
}

// ParseSlackConfig splits an approval-slack value into the member ID and the bot token. The error
// never quotes cfg, which holds the token.
func ParseSlackConfig(cfg string) (string, string, error) {
	user, token, _ := strings.Cut(strings.TrimSpace(cfg), ":")
	if !slackUserRe.MatchString(user) || !slackTokenRe.MatchString(token) {
		return "", "", fmt.Errorf("%s must be <user_id>:<bot_token>", SlackApprovalKey)
	}
	return user, token, nil
}

func slackApprove(ctx context.Context, token, user string, req core.ExecRequest) (bool, error) {
	text := slackText(req)
	var sent struct {
		Channel string `json:"channel"` // the DM's own ID, which the other methods need
		TS      string `json:"ts"`
	}
	// A user ID as the channel posts to that user's DM with the bot.
	if _, err := slackCall(ctx, token, "chat.postMessage", url.Values{"channel": {user}, "text": {text + "\n\nReact ✅ to allow or ❌ to deny."},
		"mrkdwn": {"false"}, "parse": {"none"}, "link_names": {"false"}, "unfurl_links": {"false"}, "unfurl_media": {"false"}}, &sent); err != nil {
		return false, err
	}
	outcome := "⌛ Closed: answered on another channel, or canceled."
	defer func() {
		// Best effort, even once ctx is done: replace the prompt with the outcome.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = slackCall(ctx, token, "chat.update", url.Values{"channel": {sent.Channel}, "ts": {sent.TS},
			"text": {text + "\n\n" + outcome}, "parse": {"none"}, "link_names": {"false"}}, nil)
	}()
	const unusable = "⚠️ Not approved: mintrun could not use this message's reactions. Its error says why."

	// Both reactions land before the first poll: they make the answer one tap, and a config that
	// names the bot itself then reads as ❌, never as ✅ alone.
	for _, name := range []string{"white_check_mark", "x"} {
		if _, err := slackCall(ctx, token, "reactions.add", url.Values{"channel": {sent.Channel}, "timestamp": {sent.TS}, "name": {name}}, nil); err != nil {
			if ctx.Err() == nil {
				outcome = unusable
			}
			return false, err
		}
	}
	pollCtx, cancel := context.WithTimeout(ctx, slackTimeout)
	defer cancel()
	for pollCtx.Err() == nil {
		var got struct {
			Message struct {
				Reactions []struct {
					Name  string   `json:"name"`
					Users []string `json:"users"`
				} `json:"reactions"`
			} `json:"message"`
		}
		// full=true lists every user who reacted, not only the first few.
		retry, err := slackCall(pollCtx, token, "reactions.get", url.Values{"channel": {sent.Channel}, "timestamp": {sent.TS}, "full": {"true"}}, &got)
		if pollCtx.Err() != nil {
			break // a reply read once the caller cancelled or the deadline passed answers nothing
		}
		if err != nil && retry == 0 {
			outcome = unusable
			return false, err
		}
		if err == nil {
			allow, deny := false, false
			for _, r := range got.Message.Reactions {
				if slices.Contains(r.Users, user) { // only the stored user answers
					allow = allow || r.Name == "white_check_mark"
					deny = deny || r.Name == "x"
				}
			}
			if deny {
				outcome = "⛔ Denied"
				return false, nil
			}
			if allow {
				outcome = "✅ Allowed"
				return true, nil
			}
		}
		select {
		case <-pollCtx.Done():
		case <-time.After(max(retry, slackPoll)):
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	outcome = fmt.Sprintf("⌛ Expired: no answer within %s, so not approved.", slackTimeout)
	return false, fmt.Errorf("slack: no answer within %s", slackTimeout)
}

// slackText quotes every agent-supplied field (core.ApprovalText) and escapes the result. The cut
// comes first, short enough that the escaped text still fits, since escaping can grow a byte
// fivefold; an entity made after the cut is never split.
func slackText(req core.ExecRequest) string {
	const header, budget = "🔐 mintrun approval request", 3500 // chat.update refuses text over 4,000 characters
	raw := core.ApprovalText(header, req, math.MaxInt)
	limit, size := len(raw), 0
	for i := range len(raw) {
		if size += len(slackEscape.Replace(raw[i : i+1])); size > budget {
			limit = i
			break
		}
	}
	return slackEscape.Replace(core.ApprovalText(header, req, limit))
}

// slackCall POSTs one Web API method as a form and decodes the reply into out (when non-nil). The
// token rides in the Authorization header, and every error is scrubbed of it all the same. A
// failure also returns how long to wait before another try: Retry-After on a 429 (at least
// slackPoll), slackPoll after a dropped connection, a server error or a malformed reply, and 0
// when Slack refused the call, which another try will not fix.
func slackCall(ctx context.Context, token, method string, form url.Values, out any) (time.Duration, error) {
	retry := slackPoll
	err := func() error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackAPI+"/"+method, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
				retry = max(retry, time.Duration(s)*time.Second)
			}
			return fmt.Errorf("HTTP 429: rate limited for %s", retry)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return err
		}
		var r struct {
			OK     bool   `json:"ok"`
			Error  string `json:"error"`
			Needed string `json:"needed"`
		}
		if json.Unmarshal(body, &r) != nil {
			return fmt.Errorf("HTTP %d, malformed reply", resp.StatusCode)
		}
		if !r.OK {
			if resp.StatusCode < 500 {
				retry = 0
			}
			if r.Needed != "" {
				r.Error += " (needed: " + r.Needed + ")"
			}
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, r.Error)
		}
		if out != nil {
			return json.Unmarshal(body, out)
		}
		return nil
	}()
	if err != nil {
		return retry, fmt.Errorf("slack %s: %s", method, core.Scrub(err.Error(), []string{token}))
	}
	return 0, nil
}
