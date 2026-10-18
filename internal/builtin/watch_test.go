package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

func TestWatchServer(t *testing.T) {
	// Use a short /tmp directory so the unix socket path fits within macOS's 104-byte sun_path limit.
	home, err := os.MkdirTemp("", "mrw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	if _, err := NewWatchServer(&core.Runtime{}).ListenUnix(); err == nil {
		t.Fatal("expected ListenUnix with empty HomeDir to fail")
	}

	// Write a stale regular file at app.sock: ListenUnix should replace it cleanly.
	sockPath := filepath.Join(home, "app.sock")
	if err := os.WriteFile(sockPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := core.NewRuntime(home, "keychain", core.NewRegistry())
	var logBuf bytes.Buffer
	srv := NewWatchServer(rt)
	srv.Out = &logBuf
	ln, err := srv.ListenUnix()
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- srv.ServeUnix(ctx, ln)
	}()
	defer func() {
		cancel()
		srv.Close()
		<-done
	}()

	// A second WatchServer on the same home must refuse while the first is listening.
	if _, err := NewWatchServer(rt).ListenUnix(); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("expected second ListenUnix to fail with already listening, got: %v", err)
	}

	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()

	// 1. GET / serves dashboard HTML with security headers.
	resp, err := http.Get(httpSrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("GET /: status=%d X-Frame-Options=%q", resp.StatusCode, resp.Header.Get("X-Frame-Options"))
	}

	postWatch := func(path, body string, withHeader bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, httpSrv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if withHeader {
			req.Header.Set("X-Mintrun-Watch", "1")
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	getState := func() WatchState {
		t.Helper()
		r, err := http.Get(httpSrv.URL + "/api/state")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var st WatchState
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	// 2. CSRF protection: POST without X-Mintrun-Watch: 1 returns 403 Forbidden.
	if r := postWatch("/api/pause", `{"paused":true}`, false); r.StatusCode != http.StatusForbidden {
		r.Body.Close()
		t.Fatalf("expected 403 without X-Mintrun-Watch header, got %d", r.StatusCode)
	} else {
		r.Body.Close()
	}

	// 3. Pause / Resume toggle via POST /api/pause.
	if r := postWatch("/api/pause", `{"paused":true}`, true); r.StatusCode != http.StatusOK {
		r.Body.Close()
		t.Fatalf("pause true failed: %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	if st := getState(); !st.Paused {
		t.Fatal("expected state.Paused == true")
	}
	if d := rt.CheckPolicy(core.ExecRequest{MintRequest: core.MintRequest{Provider: "github"}, Command: []string{"true"}}); d.Allowed || d.BlockedBy != "paused" {
		t.Fatalf("expected paused runtime to block, got %+v", d)
	}
	if r := postWatch("/api/pause", `{"paused":false}`, true); r.StatusCode != http.StatusOK {
		r.Body.Close()
		t.Fatalf("pause false failed: %d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	if st := getState(); st.Paused {
		t.Fatal("expected state.Paused == false")
	}

	// 4. AppApproval round-trip (allow and deny) via WatchServer.
	ask := AppApproval(rt, func(context.Context, core.ExecRequest) (bool, error) {
		t.Fatal("fallback should not be called when WatchServer is listening")
		return false, nil
	})
	for _, decision := range []string{"allow", "deny"} {
		resCh := make(chan bool, 1)
		errCh := make(chan error, 1)
		taskID := "task-" + decision
		go func() {
			ok, err := ask(ctx, core.ExecRequest{
				Task:        taskID,
				MintRequest: core.MintRequest{Provider: "github", Scope: "org/repo", Permissions: []string{"contents:read"}},
				Command:     []string{"gh", "pr", "list"},
				Sandbox:     true,
				NoNetwork:   true,
				Purpose:     "list pull requests",
				Client:      "Claude Code",
			})
			if err != nil {
				errCh <- err
				return
			}
			resCh <- ok
		}()

		var pending WatchApproval
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			st := getState()
			if len(st.Approvals) == 1 && st.Approvals[0].Task == taskID {
				pending = st.Approvals[0]
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if pending.Task != taskID || !strings.Contains(pending.Text, "Sandbox: on\nNetwork: blocked\n") {
			t.Fatalf("pending approval not found or missing Sandbox/Network header: %+v", pending)
		}

		r := postWatch("/api/decide", `{"task":"`+taskID+`","decision":"`+decision+`"}`, true)
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("decide %s status=%d", decision, r.StatusCode)
		}
		select {
		case err := <-errCh:
			t.Fatalf("AppApproval(%s) err: %v", decision, err)
		case ok := <-resCh:
			if ok != (decision == "allow") {
				t.Fatalf("AppApproval(%s) = %v", decision, ok)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("AppApproval(%s) timed out", decision)
		}
	}

	// 5. AppTrack round-trip + POST /api/stop.
	trackCtx, trackCancel := context.WithCancel(ctx)
	defer trackCancel()
	stopCh := AppTrack(rt)(trackCtx, core.AuditEntry{
		Task:      "task-run-1",
		Provider:  "cloudflare",
		Command:   []string{"wrangler", "deploy"},
		Sandbox:   true,
		NoNetwork: false,
	})
	if stopCh == nil {
		t.Fatal("AppTrack returned nil channel")
	}
	deadline := time.Now().Add(3 * time.Second)
	foundActive := false
	for time.Now().Before(deadline) {
		st := getState()
		if len(st.Active) == 1 && st.Active[0].Task == "task-run-1" {
			foundActive = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !foundActive {
		t.Fatal("active task-run-1 not listed in /api/state")
	}

	if r := postWatch("/api/stop", `{"task":"task-run-1"}`, true); r.StatusCode != http.StatusOK {
		r.Body.Close()
		t.Fatalf("POST /api/stop status=%d", r.StatusCode)
	} else {
		r.Body.Close()
	}
	select {
	case <-stopCh:
	case <-time.After(3 * time.Second):
		t.Fatal("stopCh did not close after POST /api/stop")
	}
	trackCancel()

	// 6. Error branches on unknown tasks / invalid JSON / unknown endpoints / malformed socket lines.
	for _, c := range []struct {
		path string
		body string
		code int
	}{
		{"/api/decide", `{"task":"unknown","decision":"allow"}`, http.StatusBadRequest},
		{"/api/decide", `{"task":"unknown","decision":"invalid"}`, http.StatusBadRequest},
		{"/api/stop", `{"task":"unknown"}`, http.StatusBadRequest},
		{"/api/pause", `{bad`, http.StatusBadRequest},
		{"/api/unknown", `{}`, http.StatusNotFound},
	} {
		r := postWatch(c.path, c.body, true)
		r.Body.Close()
		if r.StatusCode != c.code {
			t.Fatalf("POST %s (%s): status=%d, want %d", c.path, c.body, r.StatusCode, c.code)
		}
	}
	if r, err := http.Get(httpSrv.URL + "/unknown"); err != nil {
		t.Fatal(err)
	} else {
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Fatalf("GET /unknown status=%d", r.StatusCode)
		}
	}

	// Send malformed / unsupported lines over app.sock to verify handleConn ignores them cleanly.
	for _, msg := range []string{"not-json\n", `{"v":2,"type":"approve"}` + "\n", `{"v":1,"type":"approve"}` + "\n", `{"v":1,"type":"started"}` + "\n"} {
		c, err := net.DialTimeout("unix", sockPath, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(msg))
		_ = c.Close()
	}
}
