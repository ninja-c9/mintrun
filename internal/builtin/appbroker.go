package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// The macOS app listens on <home>/app.sock. mintrun opens one connection per approval and one per
// running task, each carrying newline-delimited JSON with "v":1.
const (
	appTimeout  = time.Second // for every dial, and for AppTrack's one write
	appMaxReply = 4 << 10     // AppApproval's reply line, newline included
)

// appRequest is the request the app shows. Sandbox is mintrun's verdict (checkPolicy sets
// req.Sandbox from it before asking), sent when false too, so the app can tell "off" from an older
// mintrun that sends no key. Every other field but via and ttl_seconds comes from the agent, so the
// app quotes each one as core.ApprovalText does (rule 4) and says when it shortens one.
type appRequest struct {
	Sandbox     bool              `json:"sandbox"`
	Provider    string            `json:"provider"`
	Scope       string            `json:"scope,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
	Command     []string          `json:"command"`
	Cwd         string            `json:"cwd,omitempty"`
	Purpose     string            `json:"purpose,omitempty"`
	Client      string            `json:"client,omitempty"`
	Via         string            `json:"via,omitempty"`
	TTLSeconds  int               `json:"ttl_seconds,omitempty"`
}

// appDial connects to the app. Where no app listens, or the home is too long for a socket path,
// it fails at once.
func appDial(ctx context.Context, rt *core.Runtime) (net.Conn, error) {
	d := net.Dialer{Timeout: appTimeout}
	return d.DialContext(ctx, "unix", filepath.Join(rt.HomeDir, "app.sock"))
}

// AppApproval asks the mintrun app. It sends {"v":1,"type":"approve","task":…,"request":{…}} and
// reads one reply line of at most 4 KiB, {"task":…,"decision":"allow"|"deny"}. Only a failed dial
// calls fallback (OSApproval), so a running app replaces the dialog while Telegram and Slack still
// race. Once connected, a reply for another task, a malformed or oversized line, or a closed
// connection is an error, never an approval, and no dialog follows. When ctx ends (another channel
// answered, or ApprovalTimeout passed), the connection closes and the app drops the card.
//
// The socket is trusted as policy.json is, with no owner or peer check: any process running as
// this user can listen on it and answer, but such a process can already edit the home and read the
// keystore (rule 23). This channel isolates nothing from it.
func AppApproval(rt *core.Runtime, fallback func(context.Context, core.ExecRequest) (bool, error)) func(context.Context, core.ExecRequest) (bool, error) {
	return func(ctx context.Context, req core.ExecRequest) (bool, error) {
		conn, err := appDial(ctx, rt)
		if err != nil {
			return fallback(ctx, req)
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() }) // also ends a blocked write or read
		defer stop()
		// No error quotes a net error, which names the socket and so the home: the reason reaches
		// agents and audit.jsonl (rule 36).
		fail := func(msg string) (bool, error) {
			if ctx.Err() != nil {
				msg = ctx.Err().Error() // the connection closed because ctx ended
			}
			return false, errors.New("app approval: " + msg)
		}

		line, _ := json.Marshal(struct {
			V       int        `json:"v"`
			Type    string     `json:"type"`
			Task    string     `json:"task"`
			Request appRequest `json:"request"`
		}{1, "approve", req.Task, appRequest{Sandbox: req.Sandbox, Provider: req.Provider, Scope: req.Scope,
			Permissions: req.Permissions, Params: req.Params, Command: req.Command, Cwd: req.WorkingDir,
			Purpose: req.Purpose, Client: req.Client, Via: req.Via, TTLSeconds: req.TTLSeconds}})
		if _, err := conn.Write(append(line, '\n')); err != nil {
			return fail("could not send the request")
		}
		reply, err := bufio.NewReader(io.LimitReader(conn, appMaxReply)).ReadBytes('\n')
		if err != nil {
			return fail("the app sent no reply line of at most 4 KiB")
		}
		var answer struct {
			Task     string `json:"task"`
			Decision string `json:"decision"`
		}
		switch {
		case json.Unmarshal(reply, &answer) != nil:
			return fail("malformed reply")
		case answer.Task != req.Task:
			return fail("reply for another task")
		case answer.Decision == "allow":
			return true, nil
		case answer.Decision == "deny":
			return false, nil
		}
		return fail("unknown decision")
	}
}

// AppTrack returns a Runtime.Track that shows each run in the app. It sends
// {"v":1,"type":"started","entry":…} and closes the returned channel, which stops the run, on a
// {"type":"stop"} line. The connection stays open until ctx ends, once the run's final audit entry
// is written, so a connection that closes with no entry for its task means mintrun died. No app,
// or one that does not take the line within appTimeout, means no tracking (a nil channel), never a
// run held up. The socket is trusted as AppApproval's is.
func AppTrack(rt *core.Runtime) func(context.Context, core.AuditEntry) <-chan struct{} {
	return func(ctx context.Context, started core.AuditEntry) <-chan struct{} {
		conn, err := appDial(ctx, rt)
		if err != nil {
			return nil
		}
		line, _ := json.Marshal(struct {
			V     int             `json:"v"`
			Type  string          `json:"type"`
			Entry core.AuditEntry `json:"entry"`
		}{1, "started", started})
		// ctx lasts the whole run, so only this deadline bounds a write to an app that stopped reading.
		_ = conn.SetWriteDeadline(time.Now().Add(appTimeout))
		if _, err := conn.Write(append(line, '\n')); err != nil {
			conn.Close()
			return nil
		}
		context.AfterFunc(ctx, func() { conn.Close() })
		stopped := make(chan struct{})
		go func() { // returns once ctx closes the connection, if no stop came first
			lines := bufio.NewScanner(conn)
			for lines.Scan() {
				var msg struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(lines.Bytes(), &msg) == nil && msg.Type == "stop" {
					close(stopped)
					return
				}
			}
		}()
		return stopped
	}
}
