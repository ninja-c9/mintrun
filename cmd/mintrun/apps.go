package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ninja-c9/mintrun/internal/builtin"
)

const appsUsage = "usage: mintrun apps status|connect|disconnect [-app claude-code,claude-desktop,cursor] [-dry-run] [-command <absolute path>]"

// appTarget is an AI app whose MCP config `mintrun apps` manages.
type appTarget struct {
	id, config string
	cli        string // Claude Code's claude CLI, which edits its config; "" for the others
	found      bool
	missing    string // why found is false
}

type appStatus struct {
	App       string `json:"app"`
	Found     bool   `json:"found"`
	Config    string `json:"config"`
	Installed bool   `json:"installed"`
	Matches   bool   `json:"matches"`
	Error     string `json:"error,omitempty"`
}

// appChange reports a connect or disconnect. Old and New are the entry's command before and after,
// never its args or env, which can hold a secret.
type appChange struct {
	App    string `json:"app"`
	Config string `json:"config"`
	Change string `json:"change"` // add, update, remove or none
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	Error  string `json:"error,omitempty"`
}

// cmdApps adds mintrun to, or removes it from, the MCP configs of Claude Code, Claude Desktop and
// Cursor without asking, and prints one JSON row per app, for the macOS app. Claude Code changes
// through its own CLI; the other two files get a byte-level splice, so nothing else in them changes.
// Without -app, connect and disconnect skip an app that is not found.
func cmdApps(ctx context.Context, args []string) {
	if len(args) == 0 || !slices.Contains([]string{"status", "connect", "disconnect"}, args[0]) {
		fatal(appsUsage)
	}
	fset := flag.NewFlagSet("apps", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	pick := fset.String("app", "", "")
	dryRun := fset.Bool("dry-run", false, "")
	command := fset.String("command", "", "")
	if err := fset.Parse(args[1:]); err != nil || fset.NArg() > 0 {
		fatal(appsUsage)
	}
	self := *command
	if self == "" {
		p, err := mintrunPath()
		if err != nil {
			fatal("%v", err)
		}
		self = p
	} else if fi, err := os.Stat(self); !filepath.IsAbs(self) || err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		fatal("-command must be the absolute path of an executable file")
	}
	targets := appTargets()
	if targets == nil {
		fatal("cannot find the home directory")
	}
	var picked []string
	if *pick != "" {
		picked = strings.Split(*pick, ",")
	}
	for _, id := range picked {
		if !slices.ContainsFunc(targets, func(t appTarget) bool { return t.id == id }) {
			fatal("unknown app %q (use claude-code, claude-desktop or cursor)", id)
		}
	}

	rows, failed := []any{}, false
	for _, t := range targets {
		if picked != nil && !slices.Contains(picked, t.id) || picked == nil && !t.found && args[0] != "status" {
			continue
		}
		if args[0] == "status" {
			r := appStatus{App: t.id, Found: t.found, Config: t.config}
			_, raw, chain, err := readApp(t.config)
			if err == nil && len(chain) == 3 {
				r.Installed = true
				_, r.Matches, err = entryCommand(raw, chain[2], self)
			}
			if err != nil {
				r.Error, failed = err.Error(), true
			}
			rows = append(rows, r)
			continue
		}
		c := appChange{App: t.id, Config: t.config, Change: "none"}
		if err := connectApp(ctx, t, args[0] == "connect", *dryRun, self, &c); err != nil {
			c.Error, failed = err.Error(), true
		}
		rows = append(rows, c)
	}
	out, _ := marshalJSON(rows, "  ")
	fmt.Println(string(out))
	if failed {
		exitFunc(1)
	}
}

// appTargets lists the apps with their configs from mcpConfigs, or nil without a home directory.
// Claude Code is found when its CLI is on PATH (an absolute match only, rule 14), the others when
// the directory their config lives in exists, which only the app itself creates.
func appTargets() []appTarget {
	conf := map[string]string{}
	for _, c := range mcpConfigs() {
		conf[c.name] = c.path
	}
	if len(conf) == 0 {
		return nil
	}
	var ts []appTarget
	for _, a := range [][2]string{{"claude-code", "Claude Code"}, {"claude-desktop", "Claude Desktop"}, {"cursor", "Cursor"}} {
		t := appTarget{id: a[0], config: conf[a[1]]}
		if t.id == "claude-code" {
			if p, err := exec.LookPath("claude"); err == nil {
				t.cli = p
			}
			t.found, t.missing = t.cli != "", "the claude CLI is not on PATH"
		} else {
			dir := filepath.Dir(t.config)
			t.found, t.missing = isDir(dir), dir+" does not exist"
		}
		ts = append(ts, t)
	}
	return ts
}

// connectApp adds or updates (connect), or removes (disconnect), t's mintrun entry and fills c.
func connectApp(ctx context.Context, t appTarget, connect, dryRun bool, self string, c *appChange) error {
	if !t.found {
		return errors.New(t.missing)
	}
	real, raw, chain, err := readApp(t.config)
	if err != nil {
		return err
	}
	installed, matches := len(chain) == 3, false
	if installed {
		if c.Old, matches, err = entryCommand(raw, chain[2], self); err != nil {
			return err
		}
	}
	switch {
	case connect:
		c.New = self
		if matches {
			return nil
		}
		c.Change = "add"
		if installed {
			c.Change = "update"
		}
	case installed:
		c.Change = "remove"
	default:
		return nil
	}

	if t.cli != "" {
		if c.Change == "update" {
			if extra := extraKeys(raw, chain[2]); extra != nil {
				return fmt.Errorf("its mintrun entry also sets %s, which `claude mcp add` cannot carry over; edit or remove that entry yourself", strings.Join(extra, ", "))
			}
		}
		if dryRun {
			return nil
		}
		if c.Change != "add" {
			if err := runClaude(ctx, t.cli, "mcp", "remove", "-s", "user", "mintrun"); err != nil {
				return err
			}
		}
		if connect {
			return runClaude(ctx, t.cli, "mcp", "add", "-s", "user", "mintrun", "--", self, "mcp")
		}
		return nil
	}

	base := raw
	if base == nil {
		base = []byte("{\n}\n") // a new file
	}
	var out []byte
	if connect {
		out, err = spliceConnect(base, self)
	} else {
		out, err = spliceDisconnect(base)
	}
	if err != nil {
		return err
	}
	// The edit must leave valid JSON that reads as intended, or the file stays as it was.
	ok := false
	if chain, err := mcpChain(out); err == nil && (len(chain) == 3) == connect {
		ok = !connect
		if connect {
			_, ok, _ = entryCommand(out, chain[2], self)
		}
	}
	if !ok {
		return errors.New("mintrun could not edit it safely, so it is left unchanged")
	}
	if dryRun {
		return nil
	}
	return writeConfig(real, raw, out)
}

// readApp reads an MCP config: its path with symlinks resolved, its bytes (nil when there is no
// file), and mcpChain's objects. A symlink that cannot be followed is an error, never replaced.
// No error quotes the file, which can hold other servers' API keys.
func readApp(path string) (real string, raw []byte, chain []jsonObject, err error) {
	real, err = filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		if _, err := os.Lstat(path); err == nil {
			return "", nil, nil, errors.New("it is a symlink to nothing, so it is left unchanged")
		}
		return path, nil, nil, nil
	}
	if err == nil {
		raw, err = os.ReadFile(real)
	}
	if err == nil {
		chain, err = mcpChain(raw)
	}
	return real, raw, chain, err
}

// writeConfig writes out over real (symlinks resolved) through WriteFileAtomic with the file's mode,
// 0600 for a new file, unless the file no longer holds raw (nil: there was no file).
func writeConfig(real string, raw, out []byte) error {
	now, err := os.ReadFile(real)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if (err == nil) != (raw != nil) || !bytes.Equal(now, raw) {
		return errors.New("it changed while mintrun was editing it, so it is left unchanged; try again")
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(real); err == nil {
		mode = fi.Mode().Perm()
	}
	return builtin.WriteFileAtomic(real, out, mode)
}

// runClaude runs the claude CLI with its output on stderr, since stdout carries mintrun's JSON. The
// error never quotes that output, which could quote the config.
func runClaude(ctx context.Context, cli string, args ...string) error {
	cmd := exec.CommandContext(ctx, cli, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("claude %s %s failed (%v)", args[0], args[1], err)
	}
	return nil
}

// extraKeys names the entry's keys that `claude mcp add` cannot write back: any besides type,
// command, args, and an empty env, which is what it writes itself. Never their values.
func extraKeys(raw []byte, entry jsonObject) []string {
	var extra []string
	for _, m := range entry.members {
		var env map[string]json.RawMessage
		switch {
		case m.key == "type", m.key == "command", m.key == "args":
		case m.key == "env" && json.Unmarshal(raw[m.valStart:m.end], &env) == nil && len(env) == 0:
		default:
			extra = append(extra, strconv.Quote(m.key))
		}
	}
	return extra
}

// entryCommand returns the entry's command and whether it runs self with the arguments ["mcp"].
// It reads command and args by their exact keys, as the apps do; a value of another type does not
// match.
func entryCommand(raw []byte, entry jsonObject, self string) (string, bool, error) {
	var cmd string
	var args []string
	for _, f := range []struct {
		key string
		v   any
	}{{"command", &cmd}, {"args", &args}} {
		i, err := entry.find(f.key)
		if err != nil {
			return "", false, err
		}
		if i >= 0 {
			_ = json.Unmarshal(raw[entry.members[i].valStart:entry.members[i].end], f.v)
		}
	}
	return cmd, cmd == self && slices.Equal(args, []string{"mcp"}), nil
}

// jsonObject is an object's place in a file: the offset of its '{', and its members in order.
type jsonObject struct {
	open    int
	members []jsonMember
}

type jsonMember struct {
	key                  string
	start, valStart, end int // the key's opening quote, the value's first byte, just past the value
}

// parseObject reads the object whose '{' is at raw[open]; raw must be valid JSON.
func parseObject(raw []byte, open int) (jsonObject, error) {
	obj := jsonObject{open: open}
	dec := json.NewDecoder(bytes.NewReader(raw[open:]))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return obj, errors.New("not an object")
	}
	for dec.More() {
		from := open + int(dec.InputOffset()) // at or after the previous value: only a comma and whitespace before the key
		key, err := dec.Token()
		if err != nil {
			return obj, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return obj, err
		}
		end := open + int(dec.InputOffset())
		obj.members = append(obj.members, jsonMember{key.(string), from + bytes.IndexByte(raw[from:], '"'), end - len(v), end})
	}
	return obj, nil
}

// find returns the index of key in o, or -1. A duplicate key is an error, so mintrun never changes
// one copy while the app reads the other.
func (o jsonObject) find(key string) (int, error) {
	i := -1
	for j, m := range o.members {
		if m.key == key {
			if i >= 0 {
				return 0, fmt.Errorf("it has more than one %q key in one object", key)
			}
			i = j
		}
	}
	return i, nil
}

// mcpChain finds mcpServers.mintrun in the MCP config raw: it returns the root object, then
// mcpServers when present, then the mintrun entry when present. A root, mcpServers or mintrun value
// that is not an object is an error, and so is a duplicate key on the way.
func mcpChain(raw []byte) ([]jsonObject, error) {
	if !json.Valid(raw) {
		return nil, errors.New("it is not valid JSON")
	}
	root, err := parseObject(raw, len(raw)-len(bytes.TrimLeft(raw, " \t\r\n")))
	if err != nil {
		return nil, errors.New("it is not a JSON object")
	}
	chain := []jsonObject{root}
	for _, key := range []string{"mcpServers", "mintrun"} {
		o := chain[len(chain)-1]
		i, err := o.find(key)
		if err != nil || i < 0 {
			return chain, err
		}
		child, err := parseObject(raw, o.members[i].valStart)
		if err != nil {
			return nil, fmt.Errorf("its %s is not a JSON object", key)
		}
		chain = append(chain, child)
	}
	return chain, nil
}

// spliceConnect sets the mintrun entry in raw to run self with ["mcp"]. A new entry becomes the first
// member of mcpServers, which is added first when missing; an existing one gets command and args
// replaced in place and keeps its other keys. No other byte changes.
func spliceConnect(raw []byte, self string) ([]byte, error) {
	chain, err := mcpChain(raw)
	if err == nil && len(chain) == 1 {
		raw = insertFirst(raw, chain[0], "mcpServers", "{"+leadWS(raw, chain[0])+"}")
		chain, err = mcpChain(raw)
	}
	if err != nil {
		return nil, err
	}
	if len(chain) == 2 {
		entry, _ := marshalJSON(mcpEntry{Command: self, Args: []string{"mcp"}}, "")
		return insertFirst(raw, chain[1], "mintrun", string(entry)), nil
	}
	cmd, _ := marshalJSON(self, "")
	for _, kv := range [][2]string{{"args", `["mcp"]`}, {"command", string(cmd)}} {
		if i, _ := chain[2].find(kv[0]); i >= 0 {
			m := chain[2].members[i]
			raw = slices.Concat(raw[:m.valStart], []byte(kv[1]), raw[m.end:])
		} else {
			raw = insertFirst(raw, chain[2], kv[0], kv[1])
		}
		if chain, err = mcpChain(raw); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// spliceDisconnect removes the mintrun entry from raw: the member, its leading whitespace, and one
// comma next to it, so it undoes spliceConnect's insert byte for byte.
func spliceDisconnect(raw []byte) ([]byte, error) {
	chain, err := mcpChain(raw)
	if err != nil || len(chain) < 3 {
		return raw, err
	}
	i, _ := chain[1].find("mintrun") // mcpChain refused a duplicate
	from, to := chain[1].members[i].start, chain[1].members[i].end
	for jsonSpace(raw[from-1]) {
		from--
	}
	next := to
	for jsonSpace(raw[next]) {
		next++
	}
	if raw[next] == ',' {
		to = next + 1
	} else if raw[from-1] == ',' {
		from--
	}
	return slices.Concat(raw[:from], raw[to:]), nil
}

// insertFirst adds "key": val to obj as its first member, after leadWS.
func insertFirst(raw []byte, obj jsonObject, key, val string) []byte {
	m := leadWS(raw, obj) + strconv.Quote(key) + ": " + val
	if len(obj.members) > 0 {
		m += ","
	}
	return slices.Concat(raw[:obj.open+1], []byte(m), raw[obj.open+1:])
}

// leadWS is the whitespace before obj's first member or, in an empty object, a newline and the
// indentation of the line holding its '{' plus two spaces.
func leadWS(raw []byte, obj jsonObject) string {
	if len(obj.members) > 0 {
		return string(raw[obj.open+1 : obj.members[0].start])
	}
	line := raw[bytes.LastIndexByte(raw[:obj.open], '\n')+1 : obj.open]
	return "\n" + string(line[:len(line)-len(bytes.TrimLeft(line, " \t"))]) + "  "
}

func jsonSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
