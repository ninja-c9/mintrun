package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// appRow decodes one row of `mintrun apps`: a status row or a change row.
type appRow struct {
	App       string `json:"app"`
	Found     bool   `json:"found"`
	Config    string `json:"config"`
	Installed bool   `json:"installed"`
	Matches   bool   `json:"matches"`
	Change    string `json:"change"`
	Old       string `json:"old"`
	New       string `json:"new"`
	Error     string `json:"error"`
}

// runApps runs `mintrun apps args…` and decodes the rows it printed. Stdout must hold only JSON,
// and no output may hold the leak canary.
func runApps(t *testing.T, args ...string) ([]appRow, cliResult) {
	t.Helper()
	r := runCLI(t, "", nil, append([]string{"apps"}, args...)...)
	if strings.Contains(r.out+r.err, leak) {
		t.Fatalf("apps %q leaked:\n%s%s", args, r.out, r.err)
	}
	var rows []appRow
	if r.out != "" {
		if err := json.Unmarshal([]byte(r.out), &rows); err != nil {
			t.Fatalf("apps %q printed more than JSON (%v):\n%s", args, err, r.out)
		}
	}
	return rows, r
}

// wantApps fails t unless `mintrun apps cmd args…` printed want and exited with code.
func wantApps(t *testing.T, code int, want []appRow, cmd string, args ...string) {
	t.Helper()
	rows, r := runApps(t, append([]string{cmd}, args...)...)
	if r.code != code || r.exited != (code != 0) || !slices.Equal(rows, want) {
		t.Fatalf("apps %s %q: exit %d, rows %+v, stderr %q; want exit %d, rows %+v", cmd, args, r.code, rows, r.err, code, want)
	}
}

// fileIs fails t unless path holds want with mode perm.
func fileIs(t *testing.T, path, want string, perm fs.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want || fi.Mode().Perm() != perm {
		t.Fatalf("%s holds %q with mode %v; want %q with mode %v", path, b, fi.Mode().Perm(), want, perm)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// appEntry is the entry `mintrun apps connect` writes for self.
func appEntry(self string) string { return `{"command":` + jsonString(self) + `,"args":["mcp"]}` }

// TestCLIApps runs `mintrun apps` against the three apps in a fake HOME. A change must be the
// documented byte splice or claude CLI call, a refusal must leave the file as it was, and no output
// may quote another server's config.
func TestCLIApps(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		home, self := setupEnv(t)
		t.Chdir(home) // bin/mintrun exists here, so only its being relative refuses it
		plain := filepath.Join(home, "plain")
		writeFile(t, plain, "#!/bin/sh\n") // 0600: not executable
		const badCommand = "-command must be the absolute path of an executable file"
		for _, tc := range []struct {
			args []string
			want string
		}{
			{nil, appsUsage},
			{[]string{"list"}, appsUsage},
			{[]string{"status", "extra"}, appsUsage},
			{[]string{"connect", "-bogus"}, appsUsage},
			{[]string{"connect", "-app", "vscode", "-command", self}, `unknown app "vscode" (use claude-code, claude-desktop or cursor)`},
			{[]string{"connect", "-command", filepath.Join("bin", "mintrun")}, badCommand},
			{[]string{"connect", "-command", plain}, badCommand},
			{[]string{"connect", "-command", home}, badCommand},
			{[]string{"connect", "-command", filepath.Join(home, "missing")}, badCommand},
		} {
			rows, r := runApps(t, tc.args...)
			if r.code != 1 || !r.exited || rows != nil || r.err != tc.want+"\n" {
				t.Errorf("apps %q: exit %d, rows %+v, stderr %q; want exit 1 and %q", tc.args, r.code, rows, r.err, tc.want)
			}
		}
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("status", func(t *testing.T) {
		home, self := setupEnv(t)
		ps := idePaths()
		wantApps(t, 0, []appRow{
			{App: "claude-code", Found: true, Config: ps[0]},
			{App: "claude-desktop", Config: ps[2]},
			{App: "cursor", Config: ps[1]},
		}, "status", "-command", self)

		writeFile(t, ps[0], `{"mcpServers": {"mintrun": {"command": `+jsonString(self)+`, "args": ["mcp"], "env": {"TOKEN": "`+leak+`"}}}}`)
		writeFile(t, ps[2], `{"mcpServers": {"mintrun": {"command": "/old/mintrun", "args": ["mcp"]}}}`)
		writeFile(t, ps[1], `{"mcpServers": {"mintrun": {"command": `+jsonString(self)+`, "args": ["mcp", "`+leak+`"]}}}`)
		before := snapshot(t, home)
		installed := []appRow{
			{App: "claude-code", Found: true, Config: ps[0], Installed: true, Matches: true},
			{App: "claude-desktop", Found: true, Config: ps[2], Installed: true},
			{App: "cursor", Found: true, Config: ps[1], Installed: true},
		}
		wantApps(t, 0, installed, "status", "-command", self)
		if !reflect.DeepEqual(snapshot(t, home), before) {
			t.Fatal("status changed a file")
		}

		writeFile(t, ps[1], `{"mcpServers": {"mintrun": {"command": `+jsonString(self)+`, "args": ["mcp"], "args": []}}}`)
		installed[2].Error = `it has more than one "args" key in one object`
		wantApps(t, 1, installed, "status", "-command", self)
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("new file", func(t *testing.T) {
		home, self := setupEnv(t)
		cursor := idePaths()[1]
		if err := os.MkdirAll(filepath.Dir(cursor), 0o700); err != nil {
			t.Fatal(err)
		}
		args := []string{"-app", "cursor", "-command", self}
		row := func(change, old, new string) []appRow {
			return []appRow{{App: "cursor", Config: cursor, Change: change, Old: old, New: new}}
		}
		wantApps(t, 0, row("add", "", self), "connect", append(args, "-dry-run")...)
		if _, err := os.Lstat(cursor); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a dry run wrote the config (%v)", err)
		}
		wantApps(t, 0, row("add", "", self), "connect", args...)
		fileIs(t, cursor, "{\n  \"mcpServers\": {\n    \"mintrun\": "+appEntry(self)+"\n  }\n}\n", 0o600)
		wantApps(t, 0, []appRow{{App: "cursor", Found: true, Config: cursor, Installed: true, Matches: true}}, "status", args...)

		fi, err := os.Stat(cursor)
		if err != nil {
			t.Fatal(err)
		}
		wantApps(t, 0, row("none", self, self), "connect", args...)
		wantApps(t, 0, row("remove", self, ""), "disconnect", append(args, "-dry-run")...)
		if now, err := os.Stat(cursor); err != nil || !os.SameFile(fi, now) {
			t.Fatalf("a matching entry or a dry run rewrote the config (%v)", err)
		}
		wantApps(t, 0, row("remove", self, ""), "disconnect", args...)
		fileIs(t, cursor, "{\n  \"mcpServers\": {\n  }\n}\n", 0o600)
		wantApps(t, 0, row("none", "", ""), "disconnect", args...)
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		_, self := setupEnv(t)
		desktop := idePaths()[2]
		for _, tc := range []struct{ before, after, back string }{
			{
				before: "{\n  \"mcpServers\": {\n    \"other\": {\"command\": \"npx\", \"env\": {\"API_KEY\": \"" + leak + "\"}}\n  },\n  \"theme\": \"dark\"\n}\n",
				after:  "{\n  \"mcpServers\": {\n    \"mintrun\": %s,\n    \"other\": {\"command\": \"npx\", \"env\": {\"API_KEY\": \"" + leak + "\"}}\n  },\n  \"theme\": \"dark\"\n}\n",
			},
			{
				before: `{"mcpServers":{"other":{"command":"npx","args":["` + leak + `"]}}}`,
				after:  `{"mcpServers":{"mintrun": %s,"other":{"command":"npx","args":["` + leak + `"]}}}`,
			},
			{
				before: "{\r\n\t\"mcpServers\": {\r\n\t\t\"other\": {\"command\": \"" + leak + "\"}\r\n\t}\r\n}\r\n",
				after:  "{\r\n\t\"mcpServers\": {\r\n\t\t\"mintrun\": %s,\r\n\t\t\"other\": {\"command\": \"" + leak + "\"}\r\n\t}\r\n}\r\n",
			},
			{ // no mcpServers: connect adds it, and disconnect leaves it empty
				before: "{\n  \"theme\": \"dark\"\n}\n",
				after:  "{\n  \"mcpServers\": {\n    \"mintrun\": %s\n  },\n  \"theme\": \"dark\"\n}\n",
				back:   "{\n  \"mcpServers\": {\n  },\n  \"theme\": \"dark\"\n}\n",
			},
			{
				before: "{}",
				after:  "{\n  \"mcpServers\": {\n    \"mintrun\": %s\n  }}",
				back:   "{\n  \"mcpServers\": {\n  }}",
			},
		} {
			writeFile(t, desktop, tc.before)
			wantApps(t, 0, []appRow{{App: "claude-desktop", Config: desktop, Change: "add", New: self}}, "connect", "-app", "claude-desktop", "-command", self)
			fileIs(t, desktop, fmt.Sprintf(tc.after, appEntry(self)), 0o600)
			wantApps(t, 0, []appRow{{App: "claude-desktop", Config: desktop, Change: "remove", Old: self}}, "disconnect", "-app", "claude-desktop", "-command", self)
			fileIs(t, desktop, cmp.Or(tc.back, tc.before), 0o600)
		}
	})

	t.Run("update", func(t *testing.T) {
		_, self := setupEnv(t)
		desktop := idePaths()[2]
		args := []string{"-app", "claude-desktop", "-command", self}
		for _, tc := range []struct{ before, after string }{
			{ // command and args change in place; every other key stays
				before: `{"mcpServers": {"mintrun": {"env": {"TOKEN": "` + leak + `"}, "command": "/old/mintrun", "args": ["serve"], "type": "stdio"}}}`,
				after:  `{"mcpServers": {"mintrun": {"env": {"TOKEN": "` + leak + `"}, "command": %s, "args": ["mcp"], "type": "stdio"}}}`,
			},
			{
				before: `{"mcpServers": {"mintrun": {"command": "/old/mintrun"}}}`,
				after:  `{"mcpServers": {"mintrun": {"args": ["mcp"],"command": %s}}}`,
			},
		} {
			writeFile(t, desktop, tc.before)
			if err := os.Chmod(desktop, 0o640); err != nil {
				t.Fatal(err)
			}
			wantApps(t, 0, []appRow{{App: "claude-desktop", Config: desktop, Change: "update", Old: "/old/mintrun", New: self}}, "connect", args...)
			fileIs(t, desktop, fmt.Sprintf(tc.after, jsonString(self)), 0o640)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		home, self := setupEnv(t)
		cursor := idePaths()[1]
		target := filepath.Join(home, "dotfiles", "mcp.json")
		writeFile(t, target, `{"mcpServers": {}}`)
		link := filepath.Join("..", "dotfiles", "mcp.json")
		if err := os.Chmod(target, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(cursor), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(link, cursor); err != nil {
			t.Fatal(err)
		}
		args := []string{"-app", "cursor", "-command", self}
		wantApps(t, 0, []appRow{{App: "cursor", Config: cursor, Change: "add", New: self}}, "connect", args...)
		fileIs(t, target, "{\"mcpServers\": {\n  \"mintrun\": "+appEntry(self)+"}}", 0o640)
		if got, err := os.Readlink(cursor); err != nil || got != link {
			t.Fatalf("the link reads %q (%v); want %q", got, err, link)
		}

		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		const dangling = "it is a symlink to nothing, so it is left unchanged"
		wantApps(t, 1, []appRow{{App: "cursor", Config: cursor, Change: "none", Error: dangling}}, "connect", args...)
		wantApps(t, 1, []appRow{{App: "cursor", Found: true, Config: cursor, Error: dangling}}, "status", args...)
		if got, err := os.Readlink(cursor); err != nil || got != link {
			t.Fatalf("the link reads %q (%v); want %q", got, err, link)
		}
		if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("connect created the link's target (%v)", err)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		home, self := setupEnv(t)
		cursor := idePaths()[1]
		dup := func(key string) string { return fmt.Sprintf("it has more than one %q key in one object", key) }
		for _, tc := range []struct{ content, want string }{
			{"not json " + leak, "it is not valid JSON"},
			{"", "it is not valid JSON"},
			{`["` + leak + `"]`, "it is not a JSON object"},
			{`"` + leak + `"`, "it is not a JSON object"},
			{"null", "it is not a JSON object"},
			{`{"mcpServers": ["` + leak + `"]}`, "its mcpServers is not a JSON object"},
			{`{"mcpServers": null}`, "its mcpServers is not a JSON object"},
			{`{"mcpServers": {"mintrun": "` + leak + `"}}`, "its mintrun is not a JSON object"},
			{`{"mcpServers": {}, "mcpServers": {"x": "` + leak + `"}}`, dup("mcpServers")},
			{`{"mcpServers": {"mintrun": {}, "mint\u0072un": {"command": "` + leak + `"}}}`, dup("mintrun")}, // an escaped key is the same key
			{`{"mcpServers": {"mintrun": {"command": "/old/mintrun", "command": "` + leak + `"}}}`, dup("command")},
		} {
			writeFile(t, cursor, tc.content)
			for _, cmd := range []string{"status", "connect", "disconnect"} {
				rows, r := runApps(t, cmd, "-app", "cursor", "-command", self)
				if r.code != 1 || len(rows) != 1 || rows[0].Error != tc.want {
					t.Errorf("apps %s on %q: exit %d, rows %+v; want exit 1 and %q", cmd, tc.content, r.code, rows, tc.want)
				}
				fileIs(t, cursor, tc.content, 0o600)
			}
		}
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("not found", func(t *testing.T) {
		home, self := setupEnv(t)
		ps := idePaths()
		wantApps(t, 1, []appRow{{App: "cursor", Config: ps[1], Change: "none", Error: filepath.Join(home, ".cursor") + " does not exist"}},
			"connect", "-app", "cursor", "-command", self)
		if isDir(filepath.Join(home, ".cursor")) {
			t.Fatal("connect created Cursor's directory")
		}
		t.Setenv("PATH", t.TempDir())
		wantApps(t, 1, []appRow{{App: "claude-code", Config: ps[0], Change: "none", Error: "the claude CLI is not on PATH"}},
			"disconnect", "-app", "claude-code", "-command", self)
		if _, r := runApps(t, "connect", "-command", self); r.code != 0 || r.exited || r.out != "[]\n" {
			t.Fatalf("connect with no app found: exit %d, stdout %q; want 0 and []", r.code, r.out)
		}
		// A relative PATH entry never finds claude (rule 14).
		t.Chdir(home)
		t.Setenv("PATH", "bin")
		wantApps(t, 0, []appRow{
			{App: "claude-code", Config: ps[0]},
			{App: "claude-desktop", Config: ps[2]},
			{App: "cursor", Config: ps[1]},
		}, "status", "-command", self)
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("all found", func(t *testing.T) {
		home, self := setupEnv(t)
		ps := idePaths()
		if err := os.MkdirAll(filepath.Dir(ps[1]), 0o700); err != nil {
			t.Fatal(err)
		}
		wantApps(t, 0, []appRow{
			{App: "claude-code", Config: ps[0], Change: "add", New: self},
			{App: "cursor", Config: ps[1], Change: "add", New: self},
		}, "connect", "-command", self)
		if calls := takeCalls(t, home); calls != "claude mcp add -s user mintrun -- "+self+" mcp\n" {
			t.Fatalf("calls %q", calls)
		}
		if isDir(filepath.Dir(ps[2])) {
			t.Fatal("connect created Claude Desktop's directory")
		}
		wantApps(t, 0, []appRow{
			{App: "claude-code", Config: ps[0], Change: "none"}, // the stub claude wrote no entry
			{App: "cursor", Config: ps[1], Change: "remove", Old: self},
		}, "disconnect", "-command", self)
		wantApps(t, 0, []appRow{
			{App: "claude-desktop", Config: ps[2]},
			{App: "cursor", Found: true, Config: ps[1]},
		}, "status", "-app", "cursor,claude-desktop", "-command", self)
		if calls := takeCalls(t, home); calls != "" {
			t.Errorf("calls %q", calls)
		}
	})

	t.Run("claude code", func(t *testing.T) {
		home, self := setupEnv(t)
		cc := idePaths()[0]
		run := func(code int, want appRow, calls, cmd string, extra ...string) {
			t.Helper()
			wantApps(t, code, []appRow{want}, cmd, append(extra, "-app", "claude-code", "-command", self)...)
			if got := takeCalls(t, home); got != calls {
				t.Fatalf("calls %q; want %q", got, calls)
			}
		}
		row := func(change, old, new, err string) appRow {
			return appRow{App: "claude-code", Config: cc, Change: change, Old: old, New: new, Error: err}
		}
		add, remove := "claude mcp add -s user mintrun -- "+self+" mcp\n", "claude mcp remove -s user mintrun\n"

		run(0, row("add", "", self, ""), add, "connect")
		writeFile(t, cc, `{"numStartups": 3, "mcpServers": {"mintrun": {"type": "stdio", "command": `+jsonString(self)+`, "args": ["mcp"], "env": {}}}}`)
		run(0, row("none", self, self, ""), "", "connect")

		stale := `{"mcpServers": {"mintrun": {"type": "stdio", "command": "/old/mintrun", "args": [], "env": {}}}, "oauthAccount": "` + leak + `"}`
		writeFile(t, cc, stale)
		run(0, row("update", "/old/mintrun", self, ""), "", "connect", "-dry-run")
		run(0, row("update", "/old/mintrun", self, ""), remove+add, "connect")
		fileIs(t, cc, stale, 0o600) // the claude CLI edits it, never mintrun
		run(0, row("remove", "/old/mintrun", "", ""), remove, "disconnect")

		writeFile(t, cc, `{"mcpServers": {"mintrun": {"command": "/old/mintrun", "args": ["mcp"], "env": {"TOKEN": "`+leak+`"}, "cwd": "/x"}}}`)
		run(1, row("update", "/old/mintrun", self, "its mintrun entry also sets \"env\", \"cwd\", which `claude mcp add` cannot carry over; edit or remove that entry yourself"), "", "connect")
		run(0, row("remove", "/old/mintrun", "", ""), remove, "disconnect")
		writeFile(t, cc, `{"mcpServers": {}}`)
		run(0, row("none", "", "", ""), "", "disconnect")

		writeFile(t, cc, stale)
		t.Setenv("MOCK_CLAUDE_EXIT", "1")
		run(1, row("update", "/old/mintrun", self, "claude mcp remove failed (exit status 1)"), remove, "connect")

		// The claude CLI's output goes to stderr: stdout holds only the rows.
		t.Setenv("MOCK_CLAUDE_EXIT", "0")
		writeFile(t, filepath.Join(home, "bin", "claude"), stubLog+"echo CLAUDE-SAYS\n")
		rows, r := runApps(t, "connect", "-app", "claude-code", "-command", self)
		if r.code != 0 || len(rows) != 1 || !strings.Contains(r.err, "CLAUDE-SAYS") {
			t.Fatalf("exit %d, rows %+v, stderr %q", r.code, rows, r.err)
		}

		// CLAUDE_CONFIG_DIR redirects Claude Code's config in apps status/connect/disconnect.
		cdir := filepath.Join(home, "alt-claude")
		altCC := filepath.Join(cdir, ".claude.json")
		t.Setenv("CLAUDE_CONFIG_DIR", cdir)
		writeFile(t, altCC, `{"mcpServers": {"mintrun": {"command": `+jsonString(self)+`, "args": ["mcp"]}}}`)
		wantApps(t, 0, []appRow{{App: "claude-code", Found: true, Config: altCC, Installed: true, Matches: true}}, "status", "-app", "claude-code", "-command", self)
	})

	t.Run("default command", func(t *testing.T) {
		home, self := setupEnv(t)
		wantApps(t, 0, []appRow{{App: "claude-code", Config: idePaths()[0], Change: "add", New: self}}, "connect", "-dry-run", "-app", "claude-code")
		tmp := filepath.Join(home, "go-build1", "b001", "exe", "mintrun")
		writeFile(t, tmp, "")
		osExecutable = func() (string, error) { return tmp, nil } // setupEnv restores it
		if rows, r := runApps(t, "status"); r.code != 1 || rows != nil || !strings.Contains(r.err, "is a temporary `go run` binary") {
			t.Fatalf("exit %d, rows %+v, stderr %q", r.code, rows, r.err)
		}
	})
}

// TestCLIAppsWriteConfig pins the check that leaves a config alone when another program changed it
// while mintrun was editing it.
func TestCLIAppsWriteConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mcp.json")
	const changed = "it changed while mintrun was editing it, so it is left unchanged; try again"
	writeFile(t, p, "now")
	for _, raw := range [][]byte{nil, []byte("before")} {
		if err := writeConfig(p, raw, []byte("out")); err == nil || err.Error() != changed {
			t.Fatalf("raw %q: %v", raw, err)
		}
		fileIs(t, p, "now", 0o600)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := writeConfig(p, []byte("before"), []byte("out")); err == nil || err.Error() != changed {
		t.Fatalf("a removed file: %v", err)
	}
	if err := writeConfig(p, nil, []byte("out")); err != nil {
		t.Fatal(err)
	}
	fileIs(t, p, "out", 0o600)
	if err := writeConfig(filepath.Dir(p), nil, []byte("out")); err == nil {
		t.Fatal("writeConfig wrote over a directory")
	}
}

// TestCLIAppsSplice pins spliceDisconnect on an entry first, in the middle, last and alone, and on
// keys and values that hold quotes and braces.
func TestCLIAppsSplice(t *testing.T) {
	for _, tc := range [][2]string{
		{`{"mcpServers": {"mintrun": {}, "a": {}}}`, `{"mcpServers": { "a": {}}}`},
		{`{"mcpServers": {"a": {}, "mintrun": {}, "b": {}}}`, `{"mcpServers": {"a": {}, "b": {}}}`},
		{`{"mcpServers": {"a": {}, "mintrun": {"command": "x"}}}`, `{"mcpServers": {"a": {}}}`},
		{"{\"mcpServers\": {\n  \"a\": 1,\n  \"mintrun\": {}\n}}", "{\"mcpServers\": {\n  \"a\": 1\n}}"},
		{`{"mcpServers": {"a\"b": "}", "mintrun": {"command": "}\""}}}`, `{"mcpServers": {"a\"b": "}"}}`},
		{`{"mcpServers": {"mintrun": {}}}`, `{"mcpServers": {}}`},
		{`{"mcpServers": {"a": 1}}`, `{"mcpServers": {"a": 1}}`},
	} {
		if got, err := spliceDisconnect([]byte(tc[0])); err != nil || string(got) != tc[1] {
			t.Errorf("spliceDisconnect(%s) = %s, %v; want %s", tc[0], got, err, tc[1])
		}
	}
}
