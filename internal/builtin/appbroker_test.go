package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// appListen serves app.sock from a short temporary home: macOS caps a socket path at 104 bytes,
// which a t.TempDir path can pass.
func appListen(t *testing.T) (*core.Runtime, *net.UnixListener) {
	t.Helper()
	home, err := os.MkdirTemp("", "mr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(home, "app.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &core.Runtime{HomeDir: home}, ln
}

// appAccept takes the one connection a call makes, as the app would. Nothing on it waits more
// than 5 s, and the test closes it, so a call that would hang fails the test instead.
func appAccept(t *testing.T, ln *net.UnixListener) (net.Conn, *bufio.Reader) {
	t.Helper()
	_ = ln.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("no connection: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

func TestAppApproval(t *testing.T) {
	long := strings.Repeat("a", 4000) // more than the dialog, Telegram or Slack shows
	req := core.ExecRequest{
		MintRequest: core.MintRequest{Provider: "github", Scope: "owner/repo", Permissions: []string{"contents:read"},
			TTLSeconds: 300, Params: map[string]string{"installation_id": "7"}},
		Vault: "agent-chosen", Command: []string{"gh", "pr", "list", "x\n✅ Allowed", long}, WorkingDir: "src/app",
		Purpose: "triage", Client: "claude-code", Via: "mcp", Task: "TASK1", Approve: true, CleanEnv: true, FromAgent: true,
	}
	// The exact line pins what the app decodes: the sandbox, sent when off too, every request field,
	// and the command whole.
	wantSent := `{"v":1,"type":"approve","task":"TASK1","request":{"sandbox":false,"provider":"github","scope":"owner/repo",` +
		`"permissions":["contents:read"],"params":{"installation_id":"7"},"command":["gh","pr","list","x\n✅ Allowed","` + long + `"],` +
		`"cwd":"src/app","purpose":"triage","client":"claude-code","via":"mcp","ttl_seconds":300}}` + "\n"
	var fallbacks atomic.Int32
	fallback := func(_ context.Context, got core.ExecRequest) (bool, error) {
		fallbacks.Add(1)
		if !reflect.DeepEqual(got, req) {
			return false, errors.New("the fallback got another request")
		}
		return true, nil
	}
	type result struct {
		ok  bool
		err error
	}
	// ask runs AppApproval in the background, as FirstApproval does, while the test plays the app.
	ask := func(ctx context.Context, rt *core.Runtime, req core.ExecRequest) <-chan result {
		done := make(chan result, 1)
		go func() {
			ok, err := AppApproval(rt, fallback)(ctx, req)
			done <- result{ok, err}
		}()
		return done
	}
	answer := func(t *testing.T, done <-chan result) result {
		t.Helper()
		select {
		case r := <-done:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("AppApproval did not return")
		}
		return result{}
	}

	allow := `{"task":"TASK1","decision":"allow"}`
	cases := []struct {
		name, reply string // the app writes reply after the request line, then hangs up
		ok          bool
		err         string
	}{
		{"allow", allow + "\n", true, ""},
		{"deny", `{"task":"TASK1","decision":"deny"}` + "\n", false, ""},
		{"a 4 KiB line", allow + strings.Repeat(" ", 4095-len(allow)) + "\n", true, ""},
		{"a line over 4 KiB", allow + strings.Repeat(" ", 4096-len(allow)) + "\n", false, "the app sent no reply line of at most 4 KiB"},
		{"no newline", allow, false, "the app sent no reply line of at most 4 KiB"},
		{"no reply", "", false, "the app sent no reply line of at most 4 KiB"},
		{"another task", `{"task":"TASK2","decision":"allow"}` + "\n", false, "reply for another task"},
		{"no task", `{"decision":"allow"}` + "\n", false, "reply for another task"},
		{"malformed", "allow\n", false, "malformed reply"},
		{"unknown decision", `{"task":"TASK1","decision":"yes"}` + "\n", false, "unknown decision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, ln := appListen(t)
			done := ask(context.Background(), rt, req)
			conn, r := appAccept(t, ln)
			if sent, err := r.ReadString('\n'); sent != wantSent {
				t.Fatalf("request line %q (%v), want %q", sent, err, wantSent)
			}
			_, _ = io.WriteString(conn, tc.reply)
			conn.Close()
			got := answer(t, done)
			wantErr := "app approval: " + tc.err
			if got.ok != tc.ok || (got.err == nil) != (tc.err == "") || got.err != nil && got.err.Error() != wantErr {
				t.Fatalf("got (%v, %v), want (%v, %q)", got.ok, got.err, tc.ok, wantErr)
			}
		})
	}
	// The sandbox comes from req.Sandbox, which checkPolicy sets from its verdict. The other flags
	// differ from it in both requests, so a line that took one of them fails.
	t.Run("sandbox on", func(t *testing.T) {
		rt, ln := appListen(t)
		on := req
		on.Sandbox, on.Approve, on.CleanEnv, on.FromAgent = true, false, false, false
		done := ask(context.Background(), rt, on)
		conn, r := appAccept(t, ln)
		want := strings.Replace(wantSent, `"sandbox":false`, `"sandbox":true`, 1)
		if sent, err := r.ReadString('\n'); sent != want {
			t.Fatalf("request line %q (%v), want %q", sent, err, want)
		}
		_, _ = io.WriteString(conn, allow+"\n")
		conn.Close()
		if got := answer(t, done); !got.ok || got.err != nil {
			t.Fatalf("got (%v, %v), want (true, nil)", got.ok, got.err)
		}
	})

	// When ctx ends (another channel answered, or ApprovalTimeout passed), the connection closes,
	// which tells the app to drop the card.
	for _, tc := range []struct {
		err     string
		timeout time.Duration
	}{{"context canceled", 5 * time.Second}, {"context deadline exceeded", 500 * time.Millisecond}} {
		t.Run(tc.err, func(t *testing.T) {
			rt, ln := appListen(t)
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			done := ask(ctx, rt, req)
			_, r := appAccept(t, ln)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatal(err)
			}
			if tc.err == "context canceled" {
				cancel()
			}
			if _, err := r.ReadByte(); err != io.EOF {
				t.Fatalf("the app read %v, want EOF", err)
			}
			if got := answer(t, done); got.ok || got.err == nil || got.err.Error() != "app approval: "+tc.err {
				t.Fatalf("got (%v, %v), want (false, %q)", got.ok, got.err, "app approval: "+tc.err)
			}
		})
	}
	// An app that hangs up before it takes the request. The error quotes no net error, which names
	// the socket and so the home (rule 36).
	t.Run("hang-up", func(t *testing.T) {
		rt, ln := appListen(t)
		big := req
		big.Command = []string{strings.Repeat("x", 4<<20)} // more than a socket buffer holds
		done := ask(context.Background(), rt, big)
		conn, _ := appAccept(t, ln)
		conn.Close()
		if got := answer(t, done); got.ok || got.err == nil || got.err.Error() != "app approval: could not send the request" {
			t.Fatalf("got (%v, %v), want (false, %q)", got.ok, got.err, "app approval: could not send the request")
		}
	})
	if n := fallbacks.Load(); n != 0 {
		t.Fatalf("the fallback ran %d times after the app took the connection", n)
	}

	// Only a failed dial asks the fallback: no socket, one an app left behind when it quit, or a
	// home too long for a socket path.
	stale, ln := appListen(t)
	ln.SetUnlinkOnClose(false)
	ln.Close()
	for name, home := range map[string]string{"no socket": t.TempDir(), "stale socket": stale.HomeDir,
		"long home": filepath.Join(t.TempDir(), strings.Repeat("h", 104))} {
		fallbacks.Store(0)
		ok, err := AppApproval(&core.Runtime{HomeDir: home}, fallback)(context.Background(), req)
		if !ok || err != nil || fallbacks.Load() != 1 {
			t.Fatalf("%s: got (%v, %v) after %d fallbacks, want the fallback's (true, nil) once", name, ok, err, fallbacks.Load())
		}
	}
}

func TestAppTrack(t *testing.T) {
	started := core.AuditEntry{Timestamp: "2026-10-17T00:00:00Z", Task: "TASK1", Via: "mcp", Client: "claude-code",
		Provider: "github", Scope: "owner/repo", Command: []string{"gh", "pr", "list"}, Purpose: "triage",
		LeaseID: "gh-inst-7-1", Ephemeral: true}
	entry, err := json.Marshal(started)
	if err != nil {
		t.Fatal(err)
	}
	wantSent := `{"v":1,"type":"started","entry":` + string(entry) + "}\n"
	// track calls AppTrack and plays the app, which takes the connection and checks the started line.
	track := func(t *testing.T, ctx context.Context) (<-chan struct{}, net.Conn, *bufio.Reader) {
		t.Helper()
		rt, ln := appListen(t)
		stopped := AppTrack(rt)(ctx, started) // the line fits the socket buffer before the app accepts
		conn, r := appAccept(t, ln)
		if sent, err := r.ReadString('\n'); sent != wantSent {
			t.Fatalf("started line %q (%v), want %q", sent, err, wantSent)
		}
		return stopped, conn, r
	}

	t.Run("stop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stopped, conn, r := track(t, ctx)
		_, _ = io.WriteString(conn, `{"type":"ping"}`+"\nstop\n")
		select {
		case <-stopped:
			t.Fatal("a line that is not a stop stopped the run")
		case <-time.After(100 * time.Millisecond):
		}
		_, _ = io.WriteString(conn, `{"type":"stop"}`+"\n")
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("a stop line did not stop the run")
		}
		// The connection stays open until the run's final audit entry, so the app can tell a
		// finished run from a mintrun that died.
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := r.ReadByte(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("after a stop the app read %v, want the connection still open", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		cancel()
		if _, err := r.ReadByte(); err != io.EOF {
			t.Fatalf("after ctx ended the app read %v, want EOF", err)
		}
	})

	t.Run("ctx end", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stopped, _, r := track(t, ctx)
		cancel()
		if _, err := r.ReadByte(); err != io.EOF {
			t.Fatalf("after ctx ended the app read %v, want EOF", err)
		}
		select {
		case <-stopped:
			t.Fatal("the run stopped with no stop line")
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("no app", func(t *testing.T) {
		if stopped := AppTrack(&core.Runtime{HomeDir: t.TempDir()})(context.Background(), started); stopped != nil {
			t.Fatal("no app, yet AppTrack returned a channel")
		}
	})

	// ExecBlind calls Track before the command starts, so a stuck write would hold up the run.
	t.Run("an app that stops reading", func(t *testing.T) {
		rt, ln := appListen(t)
		big := started
		big.Command = []string{strings.Repeat("x", 4<<20)} // more than a socket buffer holds
		done := make(chan (<-chan struct{}), 1)
		go func() { done <- AppTrack(rt)(context.Background(), big) }()
		appAccept(t, ln) // and never read
		select {
		case stopped := <-done:
			if stopped != nil {
				t.Fatal("a write that timed out still tracks the run")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("AppTrack waited on an app that stopped reading")
		}
	})
}
