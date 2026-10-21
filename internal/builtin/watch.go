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
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>mintrun</title>
<style>
:root{--bg:#f5f5f7;--card:#fff;--label:rgba(0,0,0,.85);--label2:rgba(0,0,0,.5);--sep:rgba(60,60,67,.18);--fill:rgba(120,120,128,.12);--bar:rgba(245,245,247,.72);--accent:#007aff;--red:#d70015;--green:#1f7a35;--orange:#c93400}
@media (prefers-color-scheme:dark){:root{--bg:#1e1e1e;--card:#2c2c2e;--label:rgba(255,255,255,.88);--label2:rgba(235,235,245,.6);--sep:rgba(84,84,88,.6);--fill:rgba(120,120,128,.24);--bar:rgba(30,30,30,.72);--accent:#0a84ff;--red:#ff8078;--green:#30d158;--orange:#ff9f0a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--label);font:14px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;-webkit-font-smoothing:antialiased}
header{position:sticky;top:0;z-index:1;display:flex;align-items:center;gap:10px;padding:10px max(16px,calc(50% - 364px));background:var(--bar);-webkit-backdrop-filter:saturate(180%) blur(20px);backdrop-filter:saturate(180%) blur(20px);border-bottom:.5px solid var(--sep)}
h1{font-size:15px;font-weight:600;margin:0;flex:1}
main{max-width:760px;margin:0 auto;padding:4px 16px 48px}
h2{font-size:13px;font-weight:600;color:var(--label2);margin:22px 4px 6px}
.pill{font-size:12px;font-weight:500;padding:2px 10px;border-radius:999px;background:var(--fill);color:var(--label2)}
.pill.ok{color:var(--green)}.pill.paused{color:var(--orange)}
button{font:inherit;font-size:13px;font-weight:500;line-height:20px;border:0;border-radius:7px;padding:3px 14px;cursor:pointer;background:var(--fill);color:var(--label)}
button.default{background:var(--accent);color:#fff}
button.danger{background:none;color:var(--red);padding:3px 8px}
button:disabled{opacity:.4;cursor:default}
button:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:1px}
.banner{margin:14px 0 0;padding:10px 14px;border-radius:10px;background:var(--card);border-left:4px solid var(--orange)}
.group{background:var(--card);border-radius:10px;box-shadow:0 0 0 .5px var(--sep)}
.group:empty{display:none}
.empty{margin:0;padding:11px 14px;color:var(--label2)}
.row{padding:9px 14px}.row+.row{border-top:.5px solid var(--sep)}
.line{display:flex;align-items:center;gap:10px}
.grow{flex:1;min-width:0}
.mono{font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
.clip{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{font-size:12px;color:var(--label2)}
.req{background:var(--card);border-radius:12px;padding:14px 16px;margin-bottom:12px;box-shadow:0 0 0 .5px var(--sep),0 4px 16px rgba(0,0,0,.06)}
.req h3{font-size:15px;font-weight:600;margin:0}
.cmd{background:var(--fill);border-radius:7px;padding:8px 10px;margin:10px 0;white-space:pre-wrap;word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:8px 0}
dt{color:var(--label2)}dd{margin:0;min-width:0;overflow-wrap:anywhere}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 0}
.tag{font-size:12px;padding:1px 8px;border-radius:6px;background:var(--fill)}
.good{color:var(--green)}.warn{color:var(--orange)}.bad{color:var(--red)}
.actions{display:flex;justify-content:flex-end;gap:8px;margin-top:14px}
.err{color:var(--red);font-size:13px;margin:8px 0 0}
details summary{cursor:pointer;list-style:none}details summary::-webkit-details-marker{display:none}
.more{margin-top:10px}.more>summary{color:var(--accent);font-size:13px;display:inline}
pre{white-space:pre-wrap;word-break:break-all;margin:8px 0 0;color:var(--label2)}
.row>summary::after{content:"";width:6px;height:6px;border:solid var(--label2);border-width:0 1.5px 1.5px 0;transform:rotate(-45deg);margin:0 2px 0 4px;flex:none}
.row[open]>summary::after{transform:rotate(45deg)}
</style>
</head>
<body>
<header>
<h1>mintrun</h1>
<span class="pill" id="pill">Connecting</span>
<button id="pause" disabled>Pause</button>
</header>
<main>
<p class="banner" id="status" hidden></p>
<p class="banner" id="paused" hidden>Paused. mintrun refuses every new request until you resume. Commands already running keep running.</p>
<h2>Waiting for you</h2>
<div id="approvals" aria-live="polite"></div>
<p class="group empty" id="approvals-empty">No requests waiting.</p>
<h2>Running</h2>
<div class="group" id="active"></div>
<p class="group empty" id="active-empty">Nothing running.</p>
<h2>Recent activity</h2>
<div class="group" id="audit"></div>
<p class="group empty" id="audit-empty">No activity yet.</p>
</main>
<script>
'use strict';
var token = location.hash.slice(1);
var paused = false;
var HINTS = {'delete':'Deletes something','force':'Forces or skips a safety check','network-tool':'Uses a network tool','encode':'Encodes data','shell':'Runs a shell or redirects output','external-url':'Calls a site outside the service'};
var LABELS = {exfil:'May send data out',destructive:'May destroy data',mismatch:'Does not match its reason',injected:'Looks injected',vague:'Reason is vague',scope_creep:'Asks for more than it needs'};
var VIA = {mcp:'MCP',cli:'Command line',relay:'Team relay'};
var NAMES = {github:'GitHub',aws:'AWS',gcp:'Google Cloud',cloudflare:'Cloudflare'};
var OUTCOMES = {done:['Finished','good'],failed:['Failed','bad'],blocked:['Blocked by policy','warn'],denied:['Denied','warn'],no_answer:['No answer in time','warn'],stopped:['Stopped','warn'],interrupted:['Interrupted','warn'],timed_out:['Timed out','bad'],minted:['Credential issued',''],unreported:['No report from device','bad']};

// show makes control and bidi characters visible, so agent text cannot hide or reorder what you read.
function show(s, keepNL) {
  return String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, function (c) {
    return keepNL && c === '\n' ? c : '\\u' + ('000' + c.charCodeAt(0).toString(16)).slice(-4);
  });
}
function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function argv(a) {
  return (a || []).map(function (x) { return x === '' || /[\s"'\\]/.test(x) ? JSON.stringify(x) : x; }).map(function (x) { return show(x); }).join(' ');
}
function list(dl, pairs) {
  pairs.forEach(function (p) { if (p[1]) dl.append(el('dt', null, p[0]), el('dd', null, p[1])); });
  return dl;
}
function tag(box, text, cls, title) {
  var t = el('span', 'tag ' + (cls || ''), text);
  if (title) t.title = title;
  box.append(t);
}
function ago(ts) {
  var d = (Date.now() - Date.parse(ts)) / 1000;
  if (!(d >= 0)) return ts || '';
  if (d < 45) return 'just now';
  if (d < 3600) return Math.max(1, Math.round(d / 60)) + ' min ago';
  if (d < 86400) return Math.round(d / 3600) + ' h ago';
  return new Date(ts).toLocaleString();
}
function when(ts) {
  var s = el('span', null, ago(ts));
  s.dataset.ts = ts || '';
  s.title = ts ? new Date(ts).toLocaleString() : '';
  return s;
}
function dur(sec) {
  return sec < 60 ? sec + ' seconds' : sec < 3600 ? Math.round(sec / 60) + ' min' : Math.round(sec / 360) / 10 + ' hours';
}
// svc names a provider alias type@account as "Type (account)".
function svc(p, scope) {
  var s = String(p || ''), i = s.indexOf('@'), t = i < 0 ? s : s.slice(0, i);
  return show((NAMES[t] || t) + (i < 0 ? '' : ' (' + s.slice(i + 1) + ')') + (scope ? ', ' + scope : ''));
}
function from(client, via) {
  return [show(client), VIA[via] || show(via)].filter(Boolean).join(' via ');
}
function line(text, key) {
  var ls = String(text || '').split('\n');
  for (var i = 0; i < ls.length; i++) if (ls[i].indexOf(key) === 0) return ls[i].slice(key.length);
  return '';
}
function unquote(q) {
  try { return JSON.parse(q); } catch (e) { return q; }
}
function isStatic(perms, params) {
  return (perms || []).indexOf('static') >= 0 || (params && params.mode === 'static');
}

async function post(path, body) {
  var r = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Mintrun-Watch': '1', 'X-Mintrun-Token': token}, body: JSON.stringify(body)});
  var j = await r.json().catch(function () { return {}; });
  if (!r.ok) throw new Error(j.error || 'mintrun watch answered ' + r.status);
  return j;
}
async function act(btns, errBox, path, body) {
  btns.forEach(function (b) { b.disabled = true; });
  if (errBox) errBox.hidden = true;
  try {
    await post(path, body);
    await refresh();
  } catch (e) {
    if (errBox) { errBox.textContent = 'Could not send: ' + e.message; errBox.hidden = false; } else alert('Could not send: ' + e.message);
  }
  btns.forEach(function (b) { b.disabled = false; });
}

function approvalCard(a) {
  var r = a.request || {}, c = el('section', 'req');
  var head = el('div', 'line');
  head.append(el('h3', 'grow', 'Allow this command?'));
  var asked = el('span', 'sub', 'Asked ');
  asked.append(when(a.received_at));
  head.append(asked);
  c.append(head, el('div', 'cmd mono', argv(r.command)));
  var dev = line(a.text, 'Device: ');
  var params = Object.keys(r.params || {}).sort().map(function (k) { return show(k) + '=' + show(r.params[k]); }).join(', ');
  c.append(list(el('dl'), [
    ['Service', svc(r.provider, r.scope)],
    ['Access', (r.permissions || []).map(function (p) { return show(p); }).join(', ')],
    ['Options', params],
    ['Folder', r.cwd ? show(r.cwd) : "Not set (mintrun's own folder)"],
    ['Reason', r.purpose ? '"' + show(r.purpose) + '"' : ''],
    ['From', from(r.client, r.via)],
    ['Device', dev ? show(unquote(dev)) : ''],
    ['Credential', r.ttl_seconds ? 'Asked to last ' + dur(r.ttl_seconds) : '']
  ]));
  var tags = el('div', 'tags');
  tag(tags, r.sandbox ? 'Sandboxed' : 'Not sandboxed', r.sandbox ? 'good' : '', r.sandbox ? "Runs in the OS sandbox: it cannot read mintrun's folder or the keychain by path." : 'Runs as you, with your files and keychain.');
  tag(tags, r.no_network ? 'Network blocked' : 'Network open', r.no_network ? 'good' : '');
  if (isStatic(r.permissions, r.params)) tag(tags, 'Static mode: uses the stored secret itself', 'warn');
  line(a.text, 'Hints: ').split(', ').forEach(function (h) { if (HINTS.hasOwnProperty(h)) tag(tags, HINTS[h], 'warn'); });
  if (r.jev && r.jev.risk) {
    var risk = {low: 'good', medium: 'warn', high: 'bad'}[r.jev.risk] || '';
    tag(tags, 'Risk: ' + show(r.jev.risk), risk, 'From the optional semantic screen. It can only ask or deny, never allow.');
    (r.jev.labels || []).forEach(function (l) { if (LABELS.hasOwnProperty(l)) tag(tags, LABELS[l], risk || 'warn'); });
  }
  c.append(tags);
  var more = el('details', 'more');
  more.append(el('summary', null, 'Show full request'), el('pre', 'mono', show(a.text, true)));
  c.append(more);
  var err = el('p', 'err');
  err.hidden = true;
  err.setAttribute('role', 'alert');
  var acts = el('div', 'actions'), allow = el('button', null, 'Allow'), deny = el('button', 'default', 'Deny');
  allow.addEventListener('click', function () { act([allow, deny], err, '/api/decide', {task: a.task, decision: 'allow'}); });
  deny.addEventListener('click', function () { act([allow, deny], err, '/api/decide', {task: a.task, decision: 'deny'}); });
  acts.append(allow, deny);
  c.append(err, acts);
  return c;
}

function activeRow(t) {
  var e = t.entry || {}, row = el('div', 'row line'), left = el('div', 'grow');
  left.append(el('div', 'mono clip', argv(e.command)));
  var sub = el('div', 'sub', svc(e.provider) + (e.sandbox ? ', sandboxed' : '') + ', started ');
  sub.append(when(e.ts));
  left.append(sub);
  var stop = el('button', 'danger', 'Stop');
  stop.addEventListener('click', function () {
    if (confirm('Stop this command? mintrun ends it and everything it started.')) act([stop], null, '/api/stop', {task: t.task});
  });
  row.append(left, stop);
  return row;
}

function credential(e) {
  if (!e.lease_id || e.outcome === 'minted') return '';
  if (!e.ephemeral) return 'Static mode: the stored secret itself was used';
  if (e.revoked) return 'Revoked early';
  return 'Not revoked early: it expires on its own' + (e.expires_at ? ' at ' + new Date(e.expires_at).toLocaleString() : '');
}
function auditRow(e) {
  var row = el('details', 'row'), sum = el('summary', 'line'), left = el('div', 'grow');
  left.append(el('div', 'mono clip', argv(e.command) || '(no command)'));
  var sub = el('div', 'sub', svc(e.provider) + ', ');
  sub.append(when(e.ts));
  left.append(sub);
  var o = OUTCOMES[e.outcome] || [show(e.outcome) || 'Unknown', ''];
  sum.append(left, el('span', o[1], o[0]));
  row.append(sum, list(el('dl'), [
    ['Command', argv(e.command)],
    ['Service', svc(e.provider, e.scope)],
    ['Access', (e.permissions || []).map(function (p) { return show(p); }).join(', ')],
    ['Reason', e.purpose ? '"' + show(e.purpose) + '"' : ''],
    ['From', from(e.client, e.via)],
    ['Device', show(e.device)],
    ['Blocked by', show(e.blocked_by)],
    ['Exit code', e.outcome && e.outcome !== 'blocked' && e.outcome !== 'minted' ? String(e.exit_code) : ''],
    ['Took', e.duration_ms ? (e.duration_ms / 1000).toFixed(1) + ' s' : ''],
    ['Sandbox', e.sandbox ? 'On' + (e.no_network ? ', network blocked' : ', network open') : ''],
    ['Credential', credential(e)],
    ['Risk', e.jev_risk ? show(e.jev_risk) : ''],
    ['Error', show(e.error)],
    ['Lease ID', show(e.lease_id)],
    ['Task', show(e.task)]
  ]));
  return row;
}

// sync keeps one element per key, so an open disclosure or a focused button survives each poll.
function sync(id, items, keyOf, make) {
  var box = document.getElementById(id), old = box._m || new Map(), m = new Map(), prev = null;
  items.forEach(function (it, i) {
    var k = keyOf(it);
    if (m.has(k)) k += '#' + i;
    var node = old.get(k) || make(it);
    m.set(k, node);
    var want = prev ? prev.nextSibling : box.firstChild;
    if (want !== node) box.insertBefore(node, want);
    prev = node;
  });
  old.forEach(function (node, k) { if (!m.has(k)) node.remove(); });
  box._m = m;
  document.getElementById(id + '-empty').hidden = items.length > 0;
}

function render(s) {
  paused = !!s.paused;
  var pill = document.getElementById('pill'), btn = document.getElementById('pause');
  pill.textContent = paused ? 'Paused' : 'Watching';
  pill.className = 'pill ' + (paused ? 'paused' : 'ok');
  btn.textContent = paused ? 'Resume' : 'Pause';
  btn.title = paused ? 'Let mintrun take requests again' : 'Refuse every new request until you resume';
  btn.disabled = false;
  document.getElementById('paused').hidden = !paused;
  var n = (s.approvals || []).length;
  document.title = n ? '(' + n + ') mintrun' : 'mintrun';
  sync('approvals', s.approvals || [], function (a) { return a.task; }, approvalCard);
  sync('active', s.active || [], function (t) { return t.task; }, activeRow);
  sync('audit', s.audit || [], function (e) { return [e.ts, e.task, e.outcome].join('|'); }, auditRow);
  document.querySelectorAll('[data-ts]').forEach(function (t) { t.textContent = ago(t.dataset.ts); });
}

function status(msg) {
  var b = document.getElementById('status');
  b.textContent = msg;
  b.hidden = !msg;
  if (msg) {
    document.getElementById('pill').textContent = 'Not connected';
    document.getElementById('pill').className = 'pill';
    document.getElementById('pause').disabled = true;
  }
}

async function refresh() {
  var r;
  try {
    r = await fetch('/api/state', {headers: {'X-Mintrun-Token': token}, cache: 'no-store'});
  } catch (e) {
    return status("Can't reach mintrun watch. Is it still running?");
  }
  if (r.status === 403) return status('Refused: open the whole URL mintrun watch printed, #token included.');
  var s = r.ok && await r.json().catch(function () { return null; });
  if (!s) return status('mintrun watch answered ' + r.status + '.');
  status('');
  render(s);
}

document.getElementById('pause').addEventListener('click', function () {
  act([this], null, '/api/pause', {paused: !paused});
});
(async function loop() {
  await refresh();
  setTimeout(loop, 750);
})();
</script>
</body>
</html>
`
