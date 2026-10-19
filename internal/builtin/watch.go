package builtin

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// WatchApproval represents a pending approval card received over <home>/app.sock.
type WatchApproval struct {
	Task       string     `json:"task"`
	ReceivedAt string     `json:"received_at"`
	Text       string     `json:"text"`
	Request    appRequest `json:"request"`
	decideCh   chan string
}

// WatchActiveTask represents a running child process tracked over <home>/app.sock.
type WatchActiveTask struct {
	Task   string          `json:"task"`
	Entry  core.AuditEntry `json:"entry"`
	stopFn func()
}

// WatchState is the JSON snapshot returned by GET /api/state.
type WatchState struct {
	Paused    bool              `json:"paused"`
	Approvals []WatchApproval   `json:"approvals"`
	Active    []WatchActiveTask `json:"active"`
	Audit     []core.AuditEntry `json:"audit"`
}

// WatchServer listens on <home>/app.sock and serves the local HTTP control plane and web UI.
// Every HTTP request must name the loopback address it arrived on in Host, so a page that
// rebinds its DNS name to 127.0.0.1 is refused. Every /api/ request must carry Token in
// X-Mintrun-Token, so another user on the machine, who can reach the port but cannot read the
// URL watch prints, is refused. Every POST also needs X-Mintrun-Watch: 1.
type WatchServer struct {
	rt  *core.Runtime
	Out io.Writer
	// Token is this run's secret, set by NewWatchServer. An empty Token refuses every /api/ request.
	Token     string
	mu        sync.Mutex
	ln        net.Listener
	sockPath  string
	approvals map[string]*WatchApproval
	active    map[string]*WatchActiveTask
}

// NewWatchServer creates a WatchServer for rt.
func NewWatchServer(rt *core.Runtime) *WatchServer {
	return &WatchServer{
		rt:        rt,
		Out:       io.Discard,
		Token:     rand.Text(),
		approvals: make(map[string]*WatchApproval),
		active:    make(map[string]*WatchActiveTask),
	}
}

// DashboardURL is the exact URL the operator must open: the dashboard on addr with this run's
// token in the #fragment, which a browser never sends to a server. Anything that reads the URL
// (the `mintrun watch` banner, the macOS menu bar app) must use this shape, and nothing else.
func (s *WatchServer) DashboardURL(addr string) string {
	return fmt.Sprintf("http://%s/#%s", addr, s.Token)
}

func watchCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return watchCause(oe.Err)
	}
	return err
}

// ListenUnix binds <home>/app.sock (mode 0600). If another process is already listening on
// <home>/app.sock, ListenUnix refuses instead of unlinking the live socket.
func (s *WatchServer) ListenUnix() (net.Listener, error) {
	if s.rt == nil || s.rt.HomeDir == "" {
		return nil, errors.New("watch requires a mintrun home directory")
	}
	if err := os.MkdirAll(s.rt.HomeDir, 0o700); err != nil {
		return nil, errors.New("prepare home directory: " + watchCause(err).Error())
	}
	sockPath := filepath.Join(s.rt.HomeDir, "app.sock")
	if conn, err := net.DialTimeout("unix", sockPath, 150*time.Millisecond); err == nil {
		_ = conn.Close()
		return nil, errors.New("another app is already listening on app.sock")
	}
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("remove stale app.sock: " + watchCause(err).Error())
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, errors.New("listen app.sock: " + watchCause(err).Error())
	}
	_ = os.Chmod(sockPath, 0o600)
	s.mu.Lock()
	s.ln = ln
	s.sockPath = sockPath
	s.mu.Unlock()
	return ln, nil
}

// ServeUnix accepts connections on ln until ln is closed or ctx ends.
func (s *WatchServer) ServeUnix(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer s.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

// Close closes the Unix listener, removes <home>/app.sock, and cancels any pending approvals.
func (s *WatchServer) Close() {
	s.mu.Lock()
	ln := s.ln
	sockPath := s.sockPath
	s.ln = nil
	s.sockPath = ""
	for k, a := range s.approvals {
		close(a.decideCh)
		delete(s.approvals, k)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if sockPath != "" {
		_ = os.Remove(sockPath)
	}
}

func (s *WatchServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(io.LimitReader(conn, 64<<10)).ReadBytes('\n')
	if err != nil {
		return
	}
	var env struct {
		V       int             `json:"v"`
		Type    string          `json:"type"`
		Task    string          `json:"task"`
		Request appRequest      `json:"request"`
		Entry   core.AuditEntry `json:"entry"`
	}
	if json.Unmarshal(line, &env) != nil || env.V != 1 {
		return
	}
	switch env.Type {
	case "approve":
		if env.Task == "" {
			return
		}
		req := core.ExecRequest{
			MintRequest: core.MintRequest{
				Provider:    env.Request.Provider,
				Scope:       env.Request.Scope,
				Permissions: env.Request.Permissions,
				Params:      env.Request.Params,
				TTLSeconds:  env.Request.TTLSeconds,
			},
			Command:    env.Request.Command,
			WorkingDir: env.Request.Cwd,
			Sandbox:    env.Request.Sandbox,
			NoNetwork:  env.Request.NoNetwork,
			Purpose:    env.Request.Purpose,
			Client:     env.Request.Client,
			Via:        env.Request.Via,
			Jev:        env.Request.Jev,
		}
		text := core.ApprovalText("mintrun approval request ("+env.Task+")", req, 3500)
		item := &WatchApproval{
			Task:       env.Task,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Text:       text,
			Request:    env.Request,
			decideCh:   make(chan string, 1),
		}
		s.mu.Lock()
		s.approvals[env.Task] = item
		out := s.Out
		s.mu.Unlock()
		if out != nil {
			_, _ = fmt.Fprintf(out, "\n=== APPROVAL REQUEST [%s] ===\n%s\n", env.Task, text)
		}
		defer func() {
			s.mu.Lock()
			delete(s.approvals, env.Task)
			s.mu.Unlock()
		}()

		connDone := make(chan struct{})
		go func() {
			defer close(connDone)
			_, _ = io.Copy(io.Discard, conn)
		}()

		select {
		case decision, ok := <-item.decideCh:
			if !ok || (decision != "allow" && decision != "deny") {
				return
			}
			reply, _ := json.Marshal(struct {
				Task     string `json:"task"`
				Decision string `json:"decision"`
			}{env.Task, decision})
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write(append(reply, '\n'))
		case <-connDone:
		case <-ctx.Done():
		}

	case "started":
		task := env.Entry.Task
		if task == "" {
			return
		}
		var once sync.Once
		stopFn := func() {
			once.Do(func() {
				_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte(`{"type":"stop"}` + "\n"))
			})
		}
		s.mu.Lock()
		s.active[task] = &WatchActiveTask{
			Task:   task,
			Entry:  env.Entry,
			stopFn: stopFn,
		}
		out := s.Out
		s.mu.Unlock()
		if out != nil {
			_, _ = fmt.Fprintf(out, "[started] task=%s provider=%q cmd=%q\n", task, env.Entry.Provider, env.Entry.Command)
		}
		defer func() {
			s.mu.Lock()
			delete(s.active, task)
			s.mu.Unlock()
			if out != nil {
				_, _ = fmt.Fprintf(out, "[finished] task=%s\n", task)
			}
		}()
		_, _ = io.Copy(io.Discard, conn)
	}
}

// Decide resolves a pending approval task ("allow" or "deny").
func (s *WatchServer) Decide(task, decision string) bool {
	if decision != "allow" && decision != "deny" {
		return false
	}
	s.mu.Lock()
	item := s.approvals[task]
	if item != nil {
		delete(s.approvals, task)
	}
	s.mu.Unlock()
	if item == nil {
		return false
	}
	select {
	case item.decideCh <- decision:
		return true
	default:
		return false
	}
}

// StopTask sends {"type":"stop"} to a tracked running task.
func (s *WatchServer) StopTask(task string) bool {
	s.mu.Lock()
	item := s.active[task]
	s.mu.Unlock()
	if item == nil {
		return false
	}
	item.stopFn()
	return true
}

// SetPaused creates or removes <home>/paused.
func (s *WatchServer) SetPaused(paused bool) error {
	p := filepath.Join(s.rt.HomeDir, "paused")
	if paused {
		if err := os.MkdirAll(s.rt.HomeDir, 0o700); err != nil {
			return watchCause(err)
		}
		return watchCause(os.WriteFile(p, []byte("paused\n"), 0o600))
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return watchCause(err)
	}
	return nil
}

// State returns a snapshot of the enclave pause state, pending approvals, active tasks, and recent audit entries.
func (s *WatchServer) State() WatchState {
	_, err := os.Lstat(filepath.Join(s.rt.HomeDir, "paused"))
	paused := !errors.Is(err, fs.ErrNotExist)

	s.mu.Lock()
	approvals := make([]WatchApproval, 0, len(s.approvals))
	for _, a := range s.approvals {
		approvals = append(approvals, *a)
	}
	active := make([]WatchActiveTask, 0, len(s.active))
	for _, t := range s.active {
		active = append(active, *t)
	}
	s.mu.Unlock()

	slices.SortFunc(approvals, func(a, b WatchApproval) int { return cmp.Compare(a.Task, b.Task) })
	slices.SortFunc(active, func(a, b WatchActiveTask) int { return cmp.Compare(a.Task, b.Task) })

	var audit []core.AuditEntry
	if f, err := os.Open(filepath.Join(s.rt.HomeDir, "audit.jsonl")); err == nil {
		_ = core.TailAudit(f, "", false, 20, func(_ string, e core.AuditEntry) {
			audit = append(audit, e)
		})
		_ = f.Close()
	}
	slices.Reverse(audit)
	return WatchState{
		Paused:    paused,
		Approvals: approvals,
		Active:    active,
		Audit:     audit,
	}
}

// loopbackHost reports whether r's Host is 127.0.0.1, [::1], or localhost with the port r arrived on.
func loopbackHost(r *http.Request) bool {
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	if !ok {
		return false
	}
	port := strconv.Itoa(addr.Port)
	switch r.Host {
	case "127.0.0.1:" + port, "[::1]:" + port, "localhost:" + port:
		return true
	}
	return false
}

func (s *WatchServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	if !loopbackHost(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden Host header"})
		return
	}
	// GET / serves only the static page, which a browser loads before it can send a header; the
	// page reads the token from the URL's #fragment, which never reaches the server.
	if strings.HasPrefix(r.URL.Path, "/api/") &&
		(s.Token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Mintrun-Token")), []byte(s.Token)) != 1) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or wrong X-Mintrun-Token header"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, watchDashboardHTML)
	case r.Method == http.MethodGet && r.URL.Path == "/api/state":
		writeJSON(w, http.StatusOK, s.State())
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/"):
		if r.Header.Get("X-Mintrun-Watch") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing X-Mintrun-Watch header"})
			return
		}
		switch r.URL.Path {
		case "/api/decide":
			var req struct {
				Task     string `json:"task"`
				Decision string `json:"decision"`
			}
			if err := decodeStrictJSON(w, r, &req); err != nil || !s.Decide(req.Task, req.Decision) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or unknown approval task"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		case "/api/stop":
			var req struct {
				Task string `json:"task"`
			}
			if err := decodeStrictJSON(w, r, &req); err != nil || !s.StopTask(req.Task) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or unknown running task"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		case "/api/pause":
			var req struct {
				Paused bool `json:"paused"`
			}
			if err := decodeStrictJSON(w, r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pause request"})
				return
			}
			if err := s.SetPaused(req.Paused); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"paused": req.Paused})
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

const watchDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mintrun watch — Enclave Control Plane</title>
<style>
  :root { color-scheme: dark; --bg: #0b0f17; --card: #131b2e; --border: #24324f; --text: #e6edf3; --muted: #8b949e; --green: #2ea043; --red: #da3633; --amber: #d29922; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
  h1 { font-size: 18px; margin: 0; }
  h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin: 24px 0 12px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 12px; }
  pre { margin: 8px 0; white-space: pre-wrap; word-break: break-word; font-size: 12px; background: #070a10; padding: 10px; border-radius: 6px; border: 1px solid var(--border); }
  button { font-family: inherit; font-size: 12px; font-weight: 600; padding: 6px 14px; border-radius: 6px; border: 1px solid transparent; cursor: pointer; color: #fff; margin-right: 8px; }
  .btn-allow { background: var(--green); }
  .btn-deny, .btn-stop { background: var(--red); }
  .btn-pause { background: var(--amber); color: #000; }
  .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
  .badge-ok { background: rgba(46,160,67,0.2); color: #3fb950; border: 1px solid var(--green); }
  .badge-paused { background: rgba(218,54,51,0.2); color: #f85149; border: 1px solid var(--red); }
</style>
</head>
<body>
<header>
  <div><h1>mintrun watch</h1></div>
  <div id="pause-box"></div>
</header>
<h2>Pending Approvals (<span id="app-count">0</span>)</h2>
<div id="approvals"></div>
<h2>Running Tasks (<span id="act-count">0</span>)</h2>
<div id="active"></div>
<h2>Recent Audit Log</h2>
<div id="audit"></div>
<script>
const token = location.hash.slice(1);
async function post(path, body) {
  await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-Mintrun-Watch':'1','X-Mintrun-Token':token}, body:JSON.stringify(body)});
  await refresh();
}
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
async function refresh() {
  const r = await fetch('/api/state', {headers:{'X-Mintrun-Token':token}});
  if (!r.ok) {
    document.getElementById('pause-box').textContent = 'Refused: open the whole URL mintrun watch printed, #token included.';
    return;
  }
  const s = await r.json();
  document.getElementById('pause-box').innerHTML = s.paused
    ? '<span class="badge badge-paused">PAUSED</span> <button class="btn-allow" onclick="post(\'/api/pause\',{paused:false})">Resume</button>'
    : '<span class="badge badge-ok">ACTIVE</span> <button class="btn-pause" onclick="post(\'/api/pause\',{paused:true})">Pause All</button>';
  document.getElementById('app-count').textContent = (s.approvals||[]).length;
  document.getElementById('approvals').innerHTML = (s.approvals||[]).map(a =>
    '<div class="card"><pre>'+esc(a.text)+'</pre>' +
    '<button class="btn-allow" onclick="post(\'/api/decide\',{task:\''+esc(a.task)+'\',decision:\'allow\'})">Allow</button>' +
    '<button class="btn-deny" onclick="post(\'/api/decide\',{task:\''+esc(a.task)+'\',decision:\'deny\'})">Deny</button></div>'
  ).join('') || '<div class="card">No pending approval requests.</div>';
  document.getElementById('act-count').textContent = (s.active||[]).length;
  document.getElementById('active').innerHTML = (s.active||[]).map(t =>
    '<div class="card"><div><b>'+esc(t.entry.provider)+'</b> · task '+esc(t.task)+' · sandbox='+esc(t.entry.sandbox)+' · no_network='+esc(t.entry.no_network)+'</div>' +
    '<pre>'+esc((t.entry.command||[]).join(' '))+'</pre>' +
    '<button class="btn-stop" onclick="post(\'/api/stop\',{task:\''+esc(t.task)+'\'})">Stop (SIGKILL)</button></div>'
  ).join('') || '<div class="card">No running tasks.</div>';
  document.getElementById('audit').innerHTML = (s.audit||[]).map(e =>
    '<div class="card"><b>'+esc(e.outcome||'started')+'</b> · '+esc(e.provider)+' · exit='+esc(e.exit_code)+' · '+esc(e.timestamp)+
    '<pre>'+esc((e.command||[]).join(' '))+(e.error ? '\nerror: '+esc(e.error) : '')+'</pre></div>'
  ).join('') || '<div class="card">No audit entries yet.</div>';
}
refresh();
setInterval(refresh, 750);
</script>
</body>
</html>
`
