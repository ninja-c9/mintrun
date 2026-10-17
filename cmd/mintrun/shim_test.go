package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func runAsTool(t *testing.T, arg0 string, args ...string) cliResult {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	inW.Close()
	origArgs := os.Args
	os.Args = append([]string{arg0}, args...)
	defer func() { os.Args = origArgs }()
	return capture(t, inR, nil, main)
}

func TestCLIShim(t *testing.T) {
	t.Run("list install remove and usage", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		writeFile(t, filepath.Join(bin, "gh"), stubLog+"echo gh-real-out\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}

		// shim / shim list is read-only when no shims exist.
		before := snapshot(t, home)
		r := runCLI(t, "", nil, "shim")
		if r.exited || !strings.Contains(r.out, "TOOL") || !strings.Contains(r.out, "gh") || !strings.Contains(r.out, "block") {
			t.Fatalf("shim list:\n%s%s", r.out, r.err)
		}
		if !reflect.DeepEqual(snapshot(t, home), before) {
			t.Fatalf("shim list modified files under %s", home)
		}

		// Usage & validation errors.
		for _, bad := range [][]string{
			{"shim", "list", "extra"},
			{"shim", "nope"},
			{"shim", "install", "-badflag"},
			{"shim", "install", "-mode", "nope", "gh"},
			{"shim", "install", "nosuch"},
			{"shim", "install", "-scope", "acme/widgets"},
			{"shim", "install", "-perms", "contents:read"},
			{"shim", "remove", "nosuch"},
		} {
			if res := runCLI(t, "", nil, bad...); !res.exited || res.code != 1 {
				t.Errorf("%v: code=%d exited=%v, want exit 1:\n%s%s", bad, res.code, res.exited, res.out, res.err)
			}
		}

		// Refuses a temporary `go run` binary.
		origExe := osExecutable
		goBuild := filepath.Join(home, "go-build999", "b001", "exe", "mintrun")
		writeFile(t, goBuild, "")
		osExecutable = func() (string, error) { return goBuild, nil }
		if res := runCLI(t, "", nil, "shim", "install", "gh"); !res.exited || res.code != 1 || !strings.Contains(res.err, "temporary `go run` binary") {
			t.Errorf("go run binary should fail:\n%s%s", res.out, res.err)
		}
		osExecutable = origExe

		// Pre-create .zprofile with an existing line to verify it is preserved and updated.
		writeFile(t, filepath.Join(home, ".zprofile"), "export PATH=\"/usr/local/bin:$PATH\"\n")

		// Install all default shims (block mode).
		r = runCLI(t, "", nil, "shim", "install")
		if r.exited || !strings.Contains(r.out, "Installed block shim(s)") || !strings.Contains(r.out, "export PATH=") || !strings.Contains(r.out, "~/.zshenv") || !strings.Contains(r.out, "~/.zshrc") {
			t.Fatalf("shim install all:\n%s%s", r.out, r.err)
		}
		for _, rc := range []string{".zshenv", ".zshrc", ".zprofile"} {
			data, err := os.ReadFile(filepath.Join(home, rc))
			if err != nil || !strings.Contains(string(data), shimProfileMarker) || !strings.Contains(string(data), dir) {
				t.Errorf("%s not wired with shim PATH: err=%v\n%s", rc, err, data)
			}
		}
		for _, name := range append(shimToolNames(), "mintrun") {
			fi, err := os.Lstat(filepath.Join(dir, name))
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("missing symlink %s: %v", name, err)
			}
		}

		// Install single tool in auto mode with scope, perms, and approve while shimsDir is first on PATH.
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		r = runCLI(t, "", nil, "shim", "install", "-mode", "auto", "-scope", "acme/widgets", "-perms", "contents:read, metadata:read", "-approve", "gh")
		if r.exited || !strings.Contains(r.out, "Installed auto shim(s)") || strings.Contains(r.out, "export PATH=") {
			t.Fatalf("shim install gh auto:\n%s%s", r.out, r.err)
		}
		r = runCLI(t, "", nil, "shim", "ls")
		if r.exited || !strings.Contains(r.out, "active") || !strings.Contains(r.out, "auto") || !strings.Contains(r.out, filepath.Join(bin, "gh")) {
			t.Fatalf("shim ls active:\n%s%s", r.out, r.err)
		}

		// Remove one tool, then all.
		r = runCLI(t, "", nil, "shim", "rm", "gh")
		if r.exited || !strings.Contains(r.out, "Removed shim(s): gh.") {
			t.Fatalf("shim rm gh:\n%s%s", r.out, r.err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gh")); !os.IsNotExist(err) {
			t.Errorf("gh symlink still exists: %v", err)
		}
		// Other shims remain, so .zshrc still has the marker.
		if data, _ := os.ReadFile(filepath.Join(home, ".zshrc")); !strings.Contains(string(data), shimProfileMarker) {
			t.Errorf(".zshrc marker removed while other shims still installed")
		}
		r = runCLI(t, "", nil, "shim", "remove")
		if r.exited {
			t.Fatalf("shim remove all:\n%s%s", r.out, r.err)
		}
		for _, rc := range []string{".zshenv", ".zshrc", ".zprofile"} {
			data, err := os.ReadFile(filepath.Join(home, rc))
			if err != nil || strings.Contains(string(data), shimProfileMarker) {
				t.Errorf("%s still contains shim marker after removing all shims: err=%v\n%s", rc, err, data)
			}
		}
		if zprof, _ := os.ReadFile(filepath.Join(home, ".zprofile")); !strings.Contains(string(zprof), "/usr/local/bin") {
			t.Errorf(".zprofile lost original line:\n%s", zprof)
		}
		// Refuses when <home>/shims/gh is a directory.
		if err := os.Remove(filepath.Join(dir, "gh")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "gh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if res := runCLI(t, "", nil, "shim", "install", "gh"); !res.exited || res.code != 1 || !strings.Contains(res.err, "is a directory") {
			t.Errorf("directory target should fail:\n%s%s", res.out, res.err)
		}
		if err := os.RemoveAll(filepath.Join(dir, "gh")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("block mode redirects agent and never loosens via env", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		writeFile(t, filepath.Join(bin, "gh"), stubLog+"echo SHOULD_NOT_RUN\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		if r := runCLI(t, "", nil, "shim", "install", "gh", "aws", "gcloud", "wrangler", "psql"); r.exited {
			t.Fatalf("install: %s%s", r.out, r.err)
		}
		takeCalls(t, home)

		// 1. Inferred repo from git remote (URL carries leak canary, which must never be printed).
		t.Setenv("MOCK_GIT_URL", "https://tok-"+leak+"@github.com/acme/repo-from-git.git")
		r := runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 126 {
			t.Fatalf("gh block: code=%d exited=%v, want 126:\n%s%s", r.code, r.exited, r.out, r.err)
		}
		if !strings.Contains(r.err, `"mintrun_exec" MCP tool`) ||
			!strings.Contains(r.err, "mintrun exec -provider github -scope acme/repo-from-git -perms contents:read,metadata:read -- gh repo view") {
			t.Errorf("unexpected block hint:\n%s", r.err)
		}
		if strings.Contains(r.out+r.err, leak) {
			t.Errorf("leaked git URL token in:\n%s%s", r.out, r.err)
		}
		if calls := takeCalls(t, home); strings.Contains(calls, "gh ") {
			t.Errorf("gh should not have executed, got calls: %q", calls)
		}

		// 2. Inferred repo from -R / --repo flags on gh.
		for _, args := range [][]string{
			{"pr", "list", "-R", "org1/r1"},
			{"pr", "list", "--repo", "org4/r4"},
			{"pr", "list", "--repo=https://github.com/org2/r2"},
			{"pr", "list", "-R=org3/r3"},
		} {
			res := runAsTool(t, "gh.exe", args...)
			wantRepo := args[len(args)-1]
			if idx := strings.LastIndex(wantRepo, "="); idx >= 0 {
				wantRepo = wantRepo[idx+1:]
			}
			wantRepo = strings.TrimPrefix(wantRepo, "https://github.com/")
			if !res.exited || res.code != 126 || !strings.Contains(res.err, "-scope "+wantRepo) {
				t.Errorf("args %v: code=%d err=%s", args, res.code, res.err)
			}
		}

		// 3. Policy fallback for scope & permissions on aws, default perms on gcloud/wrangler, and <scope>/<perms> placeholders on psql.
		writeFile(t, filepath.Join(home, ".mintrun", "policy.json"),
			`{"aws":{"allowed_scopes":["arn:aws:iam::111122223333:role/Read"],"allowed_permissions":["s3:ListBucket","ec2:*"]}}`)
		r = runAsTool(t, filepath.Join(dir, "aws"), "s3", "ls")
		if !r.exited || r.code != 126 || !strings.Contains(r.err, "-provider aws -scope arn:aws:iam::111122223333:role/Read -perms s3:ListBucket -- aws s3 ls") {
			t.Errorf("aws policy hint:\n%s", r.err)
		}
		if r := runAsTool(t, filepath.Join(dir, "gcloud"), "projects", "list"); !r.exited || r.code != 126 || !strings.Contains(r.err, "-perms cloud-platform.read-only") {
			t.Errorf("gcloud hint:\n%s", r.err)
		}
		if r := runAsTool(t, filepath.Join(dir, "wrangler"), "deploy"); !r.exited || r.code != 126 || !strings.Contains(r.err, "-perms workers:write") {
			t.Errorf("wrangler hint:\n%s", r.err)
		}
		if r := runAsTool(t, filepath.Join(dir, "psql"), "-c", "SELECT 1"); !r.exited || r.code != 126 || !strings.Contains(r.err, "-provider postgres-jit -scope <scope> -perms <perms> -- psql -c SELECT 1") {
			t.Errorf("psql placeholder hint:\n%s", r.err)
		}

		// 4. MINTRUN_SHIM_MODE=auto must NEVER loosen block mode!
		t.Setenv("MINTRUN_SHIM_MODE", "auto")
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 126 {
			t.Errorf("MINTRUN_SHIM_MODE=auto loosened block mode: code=%d\n%s%s", r.code, r.out, r.err)
		}
		if calls := takeCalls(t, home); strings.Contains(calls, "gh ") {
			t.Errorf("gh executed when MINTRUN_SHIM_MODE=auto was set on a block shim: %q", calls)
		}
	})

	t.Run("auto mode wraps via ExecBlind scrubs secrets and respects tightening", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		// Real gh prints its args and the injected GH_TOKEN on both stdout and stderr so we can verify scrubbing and non-recursion.
		writeFile(t, filepath.Join(bin, "gh"), stubLog+`printf 'repo-ok token=%s\n' "$GH_TOKEN"; printf 'err-tok=%s\n' "$GH_TOKEN" >&2`+"\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)

		pat := "ghp_secret_" + leak
		setSecret(t, "github", pat)
		writeFile(t, filepath.Join(home, ".mintrun", "policy.json"),
			`{"github":{"allowed_scopes":["acme/widgets"],"AllowedPermissions":null,"allow_static":true,"clean_env":true}}`)
		if r := runCLI(t, "", nil, "shim", "install", "-mode", "auto", "-scope", "acme/widgets", "-perms", "static", "gh"); r.exited {
			t.Fatalf("shim install auto:\n%s%s", r.out, r.err)
		}
		takeCalls(t, home)

		// Auto-wrap runs the real gh through ExecBlind and scrubs the PAT from stdout and stderr.
		r := runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 0 {
			t.Fatalf("auto gh: code=%d exited=%v:\n%s%s", r.code, r.exited, r.out, r.err)
		}
		if !strings.Contains(r.out, "repo-ok token=[MINTRUN:REDACTED]") || !strings.Contains(r.err, "err-tok=[MINTRUN:REDACTED]") || strings.Contains(r.out+r.err, pat) {
			t.Errorf("stdout/stderr not scrubbed:\n%s%s", r.out, r.err)
		}
		if got := takeCalls(t, home); got != "gh repo view\n" {
			t.Errorf("calls = %q, want %q", got, "gh repo view\n")
		}

		// MINTRUN_SHIM_MODE=block tightens auto mode to block without running gh.
		t.Setenv("MINTRUN_SHIM_MODE", "block")
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 126 || !strings.Contains(r.err, "direct execution of \"gh\" is blocked") {
			t.Errorf("MINTRUN_SHIM_MODE=block did not tighten auto shim: code=%d\n%s", r.code, r.err)
		}
		if got := takeCalls(t, home); got != "" {
			t.Errorf("gh ran under MINTRUN_SHIM_MODE=block: %q", got)
		}
		t.Setenv("MINTRUN_SHIM_MODE", "")

		// Policy denial inside auto mode exits 126 and never runs gh.
		if r := runCLI(t, "", nil, "shim", "install", "-mode", "auto", "-scope", "other/repo", "-perms", "static", "gh"); r.exited {
			t.Fatalf("reinstall: %s%s", r.out, r.err)
		}
		takeCalls(t, home)
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 126 || !strings.Contains(r.err, "policy denied: scope \"other/repo\"") {
			t.Errorf("auto policy denial: code=%d\n%s", r.code, r.err)
		}
		if got := takeCalls(t, home); got != "" {
			t.Errorf("gh ran on policy denial: %q", got)
		}

		// Non-policy error inside auto mode (e.g. missing vault secret) exits 1.
		if r := runCLI(t, "", nil, "shim", "install", "-mode", "auto", "-scope", "acme/widgets", "-perms", "static", "gh"); r.exited {
			t.Fatalf("reinstall: %s%s", r.out, r.err)
		}
		if r := runCLI(t, "", nil, "secret", "delete", "github"); r.exited {
			t.Fatalf("secret delete: %s%s", r.out, r.err)
		}
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 1 || !strings.Contains(r.err, "run mintrun init github") {
			t.Errorf("auto missing secret: code=%d\n%s", r.code, r.err)
		}

		// Relative PATH entries are rejected (rule 14), and missing real binary exits 127.
		if err := os.Remove(filepath.Join(bin, "gh")); err != nil {
			t.Fatal(err)
		}
		relDir := t.TempDir()
		writeFile(t, filepath.Join(relDir, "gh"), stubLog+"echo RELATIVE_RAN\n")
		if err := os.Chmod(filepath.Join(relDir, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		origWd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(relDir); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chdir(origWd) }()
		t.Setenv("PATH", dir+string(os.PathListSeparator)+"."+string(os.PathListSeparator)+bin)
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 127 || !strings.Contains(r.err, `executable "gh" not found on PATH outside shims`) {
			t.Errorf("relative PATH should fail with 127: code=%d\n%s%s", r.code, r.out, r.err)
		}
		if got := takeCalls(t, home); got != "" {
			t.Errorf("relative gh ran: %q", got)
		}
	})

	t.Run("mintrun exec with block shim first on PATH does not recurse", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		writeFile(t, filepath.Join(bin, "gh"), stubLog+"echo real-gh-via-exec\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		setSecret(t, "github", "ghp_pat_"+leak)
		writeFile(t, filepath.Join(home, ".mintrun", "policy.json"),
			`{"github":{"allowed_scopes":["acme/widgets"],"allow_static":true}}`)
		if r := runCLI(t, "", nil, "shim", "install", "gh"); r.exited {
			t.Fatalf("install: %s%s", r.out, r.err)
		}
		takeCalls(t, home)

		r := runCLI(t, "", nil, "exec", "-provider", "github", "-scope", "acme/widgets", "-perms", "static", "--", "gh", "repo", "view")
		if !r.exited || r.code != 0 || !strings.Contains(r.out, "real-gh-via-exec") {
			t.Fatalf("mintrun exec with shim on PATH: code=%d\n%s%s", r.code, r.out, r.err)
		}
	})

	t.Run("fail-closed shims config and doctorShims", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			corrupt func(t *testing.T, dir, cfgPath string)
			wantErr string
		}{
			{"unreadable directory", func(t *testing.T, dir, cfgPath string) {
				if err := os.Remove(cfgPath); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.MkdirAll(cfgPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}, "shims/config.json cannot be read (is a directory)"},
			{"dangling symlink", func(t *testing.T, dir, cfgPath string) {
				_ = os.RemoveAll(cfgPath)
				if err := os.Symlink(cfgPath+".missing", cfgPath); err != nil {
					t.Fatal(err)
				}
			}, "shims/config.json cannot be read (no such file or directory)"},
			{"malformed JSON", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"gh":`)
			}, "shims/config.json is malformed"},
			{"unknown field", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"gh":{"modes":"auto"}}`)
			}, `shims/config.json is malformed (json: unknown field "modes")`},
			{"unknown tool", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"curl":{"mode":"auto"}}`)
			}, `shims/config.json has unknown tool "curl"`},
			{"invalid mode", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"gh":{"mode":"bypass"}}`)
			}, `shims/config.json tool "gh" has invalid mode "bypass"`},
		} {
			t.Run(c.name, func(t *testing.T) {
				home, _ := setupEnv(t)
				dir := filepath.Join(home, ".mintrun", "shims")
				cfgPath := filepath.Join(dir, "config.json")
				if r := runCLI(t, "", nil, "shim", "install", "gh"); r.exited {
					t.Fatalf("install: %s%s", r.out, r.err)
				}
				c.corrupt(t, dir, cfgPath)
				r := runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
				if !r.exited || r.code != 126 || !strings.Contains(r.err, c.wantErr) {
					t.Errorf("shim run: code=%d want 126 with %q:\n%s", r.code, c.wantErr, r.err)
				}
				if strings.Contains(r.err, home) {
					t.Errorf("error leaked local path %q:\n%s", home, r.err)
				}
				doc := runCLI(t, "", nil, "doctor")
				if !doc.exited || doc.code != 1 || !strings.Contains(doc.out, "FAIL  shims: "+c.wantErr) {
					t.Errorf("doctor: code=%d\n%s%s", doc.code, doc.out, doc.err)
				}
			})
		}

		// doctorShims checks symlink states and PATH ordering.
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		writeFile(t, filepath.Join(bin, "gh"), stubLog+"exit 0\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		if r := runCLI(t, "", nil, "shim", "install", "gh"); r.exited {
			t.Fatalf("install: %s%s", r.out, r.err)
		}
		// 1. bin is before dir on PATH -> warn.
		t.Setenv("PATH", bin+string(os.PathListSeparator)+dir)
		doc := runCLI(t, "", nil, "doctor")
		if doc.exited || !strings.Contains(doc.out, "warn  shim gh (block):") {
			t.Errorf("doctor warn PATH order:\n%s", doc.out)
		}
		// 2. dir is first on PATH -> ok.
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		doc = runCLI(t, "", nil, "doctor")
		if doc.exited || !strings.Contains(doc.out, "ok    shim gh: block mode") {
			t.Errorf("doctor ok shim:\n%s", doc.out)
		}
		// 3. Symlink points to another existing binary -> warn.
		otherBin := filepath.Join(home, "other-mintrun")
		writeFile(t, otherBin, "#!/bin/sh\n")
		if err := os.Remove(filepath.Join(dir, "gh")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(otherBin, filepath.Join(dir, "gh")); err != nil {
			t.Fatal(err)
		}
		doc = runCLI(t, "", nil, "doctor")
		if doc.exited || !strings.Contains(doc.out, "warn  shim gh:") || !strings.Contains(doc.out, "not this binary") {
			t.Errorf("doctor warn other binary:\n%s", doc.out)
		}
		// 4. Dangling symlink -> FAIL.
		if err := os.Remove(otherBin); err != nil {
			t.Fatal(err)
		}
		doc = runCLI(t, "", nil, "doctor")
		if !doc.exited || doc.code != 1 || !strings.Contains(doc.out, "FAIL  shim gh:") || !strings.Contains(doc.out, "points to a missing binary") {
			t.Errorf("doctor FAIL dangling symlink:\n%s", doc.out)
		}
		// 5. Regular file instead of symlink -> FAIL.
		if err := os.Remove(filepath.Join(dir, "gh")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "gh"), "not a symlink")
		doc = runCLI(t, "", nil, "doctor")
		if !doc.exited || doc.code != 1 || !strings.Contains(doc.out, "FAIL  shim gh:") || !strings.Contains(doc.out, "is not a symlink") {
			t.Errorf("doctor FAIL regular file:\n%s", doc.out)
		}
	})
}
