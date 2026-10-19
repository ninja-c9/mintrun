package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
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
			{"shim", "install", "-provider", "github@work"},
			{"shim", "install", "-provider", "aws@work", "gh"},
			{"shim", "install", "-provider", "github@Work", "gh"},
			{"shim", "install", "-provider", "github@", "gh"},
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
		r = runCLI(t, "y\n", nil, "shim", "install")
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
		if r.exited || !strings.Contains(r.out, "Removed shim(s): gh.") || strings.Contains(r.out, "[y/N]") {
			t.Fatalf("shim rm gh:\n%s%s", r.out, r.err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gh")); !os.IsNotExist(err) {
			t.Errorf("gh symlink still exists: %v", err)
		}
		// Other shims remain, so nothing is offered and .zshrc keeps the line.
		if data, _ := os.ReadFile(filepath.Join(home, ".zshrc")); !strings.Contains(string(data), shimProfileMarker) {
			t.Errorf(".zshrc marker removed while other shims still installed")
		}
		r = runCLI(t, "y\n", nil, "shim", "remove")
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

	t.Run("shell profiles change only on a yes, each backed up first", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		line := "export PATH='" + dir + "':\"$PATH\" # mintrun-shim"
		zshenv, zshrc, bashrc := filepath.Join(home, ".zshenv"), filepath.Join(home, ".zshrc"), filepath.Join(home, ".bashrc")
		modes := map[string]os.FileMode{zshenv: 0o600, zshrc: 0o640, bashrc: 0o644}
		writeFile(t, zshrc, "alias ll='ls -l'\n")
		writeFile(t, bashrc, "export EDITOR=vi\n")
		for _, p := range []string{zshrc, bashrc} {
			if err := os.Chmod(p, modes[p]); err != nil {
				t.Fatal(err)
			}
		}
		before := profileFiles(t, home)
		// interrupt runs mintrun shim and presses Ctrl-C (a real SIGINT) once the question shows,
		// so mintrun stops there.
		interrupt := func(args ...string) {
			t.Helper()
			inR, inW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer inR.Close()
			defer inW.Close() // ends the read the question left waiting
			origArgs := os.Args
			os.Args = append([]string{"mintrun", "shim"}, args...)
			defer func() { os.Args = origArgs }()
			var timer *time.Timer
			pressCtrlC := func(out string) {
				if timer == nil && strings.Contains(out, "[y/N]: ") {
					p, _ := os.FindProcess(os.Getpid())
					_ = p.Signal(os.Interrupt)
					// A question that misses Ctrl-C reads EOF soon after, a no, so the test fails instead of hanging.
					timer = time.AfterFunc(5*time.Second, func() { inW.Close() })
				}
			}
			r := capture(t, inR, pressCtrlC, main)
			if timer == nil || !timer.Stop() || r.code != 1 || r.err != "interrupted\n" {
				t.Errorf("%v, interrupted: code %d:\n%s%s", args, r.code, r.out, r.err)
			}
		}

		// No answer (EOF) is a no: nothing changes, and the line is shown to add by hand.
		r := runCLI(t, "", nil, "shim", "install", "gh")
		if r.exited || !strings.Contains(r.out, "~/.zshenv, ~/.zshrc, ~/.bashrc:\n  "+line+"\n") || !strings.Contains(r.out, "Left them unchanged.") {
			t.Errorf("install, no answer:\n%s%s", r.out, r.err)
		}
		if got := profileFiles(t, home); !reflect.DeepEqual(got, before) {
			t.Fatalf("install without a yes changed profiles:\n%q\nwant %q", got, before)
		}

		// A yes puts the line last, creating ~/.zshenv with mode 0600, after copying each existing
		// profile to a .bak- backup with its own mode.
		r = runCLI(t, "y\n", nil, "shim", "install", "gh")
		if r.exited || !strings.Contains(r.out, "Added it to ~/.zshenv, ~/.zshrc, ~/.bashrc;") {
			t.Errorf("install, yes:\n%s%s", r.out, r.err)
		}
		got := profileFiles(t, home)
		popBackup(t, got, zshrc, "alias ll='ls -l'\n", 0o640)
		popBackup(t, got, bashrc, "export EDITOR=vi\n", 0o644)
		wired := map[string]string{zshenv: line + "\n", zshrc: "alias ll='ls -l'\n" + line + "\n", bashrc: "export EDITOR=vi\n" + line + "\n"}
		if !reflect.DeepEqual(got, wired) {
			t.Errorf("install, yes:\n%q\nwant %q", got, wired)
		}
		for p, mode := range modes {
			if got := modeOf(t, p); got != mode {
				t.Errorf("%s: mode %v, want %v", p, got, mode)
			}
		}

		// Wired already: nothing to ask, only the line for this shell, whose PATH lacks the shims.
		r = runCLI(t, "", nil, "shim", "install", "gh")
		if r.exited || strings.Contains(r.out, "[y/N]") || !strings.Contains(r.out, "Put "+dir+" first on PATH") {
			t.Errorf("install, wired:\n%s%s", r.out, r.err)
		}

		// remove asks too: no answer keeps the line, and a yes takes it out after a backup.
		r = runCLI(t, "", nil, "shim", "remove")
		if r.exited || !strings.Contains(r.out, "~/.zshenv, ~/.zshrc, ~/.bashrc:\n  "+line+"\n") || !strings.Contains(r.out, "Left them unchanged.") {
			t.Errorf("remove, no answer:\n%s%s", r.out, r.err)
		}
		if got := profileFiles(t, home); !reflect.DeepEqual(got, wired) {
			t.Errorf("remove without a yes changed profiles:\n%q\nwant %q", got, wired)
		}
		interrupt("remove")
		if got := profileFiles(t, home); !reflect.DeepEqual(got, wired) {
			t.Errorf("interrupted remove changed profiles:\n%q\nwant %q", got, wired)
		}
		r = runCLI(t, "y\n", nil, "shim", "remove")
		if r.exited || !strings.Contains(r.out, "Removed it from ~/.zshenv, ~/.zshrc, ~/.bashrc.") {
			t.Errorf("remove, yes:\n%s%s", r.out, r.err)
		}
		got = profileFiles(t, home)
		for p, s := range wired {
			popBackup(t, got, p, s, modes[p])
		}
		if want := map[string]string{zshenv: "", zshrc: "alias ll='ls -l'\n", bashrc: "export EDITOR=vi\n"}; !reflect.DeepEqual(got, want) {
			t.Errorf("remove, yes:\n%q\nwant %q", got, want)
		}

		// A profile edited while the question waits is left alone.
		edits, err := shimProfileEdits(line, true)
		if err != nil || len(edits) != 3 {
			t.Fatalf("edits %v (%v), want three", edits, err)
		}
		writeFile(t, zshenv, "export B=2\n")
		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer inR.Close()
		if _, err := inW.WriteString("y\n"); err != nil {
			t.Fatal(err)
		}
		inW.Close()
		r = capture(t, inR, nil, func() {
			offerShimProfiles(&wizard{ctx: context.Background(), in: bufio.NewReader(os.Stdin)}, line, edits, true)
		})
		if r.code != 1 || !strings.Contains(r.err, "~/.zshenv changed while mintrun waited, so it was left unchanged") {
			t.Errorf("edited while asking: code %d:\n%s%s", r.code, r.out, r.err)
		}
		edited := map[string]string{zshenv: "export B=2\n", zshrc: "alias ll='ls -l'\n", bashrc: "export EDITOR=vi\n"}
		if got := profileFiles(t, home); !reflect.DeepEqual(got, edited) {
			t.Errorf("edited while asking:\n%q\nwant %q", got, edited)
		}
		interrupt("install", "gh")
		if got := profileFiles(t, home); !reflect.DeepEqual(got, edited) {
			t.Errorf("interrupted install changed profiles:\n%q\nwant %q", got, edited)
		}

		// Without HOME there is no profile to offer, only the line.
		t.Setenv("HOME", "")
		r = runCLI(t, "", nil, "shim", "install", "gh")
		if r.exited || strings.Contains(r.out, "[y/N]") || !strings.Contains(r.out, "Put "+dir+" first on PATH") {
			t.Errorf("install, no HOME:\n%s%s", r.out, r.err)
		}
	})

	t.Run("a linked profile changes where it lives and a broken link is left alone", func(t *testing.T) {
		home, _ := setupEnv(t)
		line := "export PATH='" + filepath.Join(home, ".mintrun", "shims") + "':\"$PATH\" # mintrun-shim"
		zshenv, zshrc := filepath.Join(home, ".zshenv"), filepath.Join(home, ".zshrc")
		dotfiles := filepath.Join(home, "dotfiles")
		target := filepath.Join(dotfiles, "zshrc")
		writeFile(t, target, "alias ll='ls -l'\n")
		if err := os.Symlink(filepath.Join("dotfiles", "zshrc"), zshrc); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("missing", zshenv); err != nil {
			t.Fatal(err)
		}

		r := runCLI(t, "y\n", nil, "shim", "install", "gh")
		if r.exited || !strings.Contains(r.out, "Added it to ~/.zshrc;") {
			t.Errorf("install:\n%s%s", r.out, r.err)
		}
		got := profileFiles(t, home)
		popBackup(t, got, target, "alias ll='ls -l'\n", 0o600)
		want := map[string]string{zshenv: "-> missing", zshrc: "-> " + filepath.Join("dotfiles", "zshrc"), dotfiles: "<dir>", target: "alias ll='ls -l'\n" + line + "\n"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("install:\n%q\nwant %q", got, want)
		}

		r = runCLI(t, "y\n", nil, "shim", "remove")
		if r.exited || !strings.Contains(r.out, "Removed it from ~/.zshrc.") {
			t.Errorf("remove:\n%s%s", r.out, r.err)
		}
		got = profileFiles(t, home)
		popBackup(t, got, target, want[target], 0o600)
		want[target] = "alias ll='ls -l'\n"
		if !reflect.DeepEqual(got, want) {
			t.Errorf("remove:\n%q\nwant %q", got, want)
		}

		// A backup that cannot be written stops before the profile changes.
		if os.Geteuid() != 0 { // root writes into a read-only directory anyway
			if err := os.Chmod(dotfiles, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dotfiles, 0o700) }) // so TempDir's cleanup can remove it
			r = runCLI(t, "y\n", nil, "shim", "install", "gh")
			if !r.exited || r.code != 1 || !strings.Contains(r.err, "back up ~/.zshrc") {
				t.Errorf("unwritable backup should fail:\n%s%s", r.out, r.err)
			}
			if got := profileFiles(t, home); !reflect.DeepEqual(got, want) {
				t.Errorf("failed backup changed profiles:\n%q\nwant %q", got, want)
			}
		}
	})

	t.Run("only the exact line mintrun writes moves or goes", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		line := "export PATH='" + dir + "':\"$PATH\" # mintrun-shim"
		zshenv, zshrc, zprofile := filepath.Join(home, ".zshenv"), filepath.Join(home, ".zshrc"), filepath.Join(home, ".zprofile")
		own := "# mintrun-shim: my own note\nexport PATH=\"$HOME/.other/shims:$PATH\" # mintrun-shim\n"
		brew := "eval \"$(brew shellenv)\"" // the last line, with no newline at the end
		writeFile(t, zshrc, own)
		writeFile(t, zprofile, line+"\n"+own+brew)

		// install moves its line below the later PATH change, on a line of its own, and keeps
		// every other line.
		r := runCLI(t, "y\n", nil, "shim", "install", "gh")
		if r.exited {
			t.Fatalf("install:\n%s%s", r.out, r.err)
		}
		got := profileFiles(t, home)
		popBackup(t, got, zshrc, own, 0o600)
		popBackup(t, got, zprofile, line+"\n"+own+brew, 0o600)
		want := map[string]string{zshenv: line + "\n", zshrc: own + line + "\n", zprofile: own + brew + "\n" + line + "\n"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("install:\n%q\nwant %q", got, want)
		}

		r = runCLI(t, "y\n", nil, "shim", "remove")
		if r.exited {
			t.Fatalf("remove:\n%s%s", r.out, r.err)
		}
		got = profileFiles(t, home)
		for p, s := range want {
			popBackup(t, got, p, s, 0o600)
		}
		if want := map[string]string{zshenv: "", zshrc: own, zprofile: own + brew + "\n"}; !reflect.DeepEqual(got, want) {
			t.Errorf("remove:\n%q\nwant %q", got, want)
		}

		// A profile that cannot be read stops install before any shim is linked, and stops remove.
		if err := os.Mkdir(filepath.Join(home, ".bashrc"), 0o700); err != nil {
			t.Fatal(err)
		}
		r = runCLI(t, "", nil, "shim", "install", "gh")
		if !r.exited || r.code != 1 || !strings.Contains(r.err, "update shell profile:") {
			t.Errorf("unreadable profile should fail install:\n%s%s", r.out, r.err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gh")); !os.IsNotExist(err) {
			t.Errorf("install linked gh before it failed: %v", err)
		}
		r = runCLI(t, "", nil, "shim", "remove")
		if !r.exited || r.code != 1 || !strings.Contains(r.err, "clean shell profile:") {
			t.Errorf("unreadable profile should fail remove:\n%s%s", r.out, r.err)
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

	t.Run("auto mode refuses an empty or blank permission list", func(t *testing.T) {
		home, _ := setupEnv(t)
		dir := filepath.Join(home, ".mintrun", "shims")
		bin := filepath.Join(home, "bin")
		policy := filepath.Join(home, ".mintrun", "policy.json")
		for _, tool := range []string{"aws", "vercel", "psql"} {
			writeFile(t, filepath.Join(bin, tool), stubLog+"echo SHOULD_NOT_RUN\n")
			if err := os.Chmod(filepath.Join(bin, tool), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		if r := runCLI(t, "", nil, "shim", "install", "-mode", "auto", "aws", "vercel", "psql"); r.exited {
			t.Fatalf("install: %s%s", r.out, r.err)
		}
		takeCalls(t, home)
		// No real vercel is left on PATH: the refusal comes before the lookup, so it names the
		// config key to set rather than a missing binary.
		if err := os.Remove(filepath.Join(bin, "vercel")); err != nil {
			t.Fatal(err)
		}
		// aws, vercel, and psql have no default permissions, and a wildcard rule names none, so the
		// list is empty, which would mint the provider's widest credential. The shim stops before
		// ExecBlind: nothing is minted or audited, and the real binary never runs.
		writeFile(t, policy, `{"aws":{"allowed_permissions":["ec2:*"]}}`)
		refused := func(tool, provider, got string) {
			t.Helper()
			r := runAsTool(t, filepath.Join(dir, tool), "x")
			want := fmt.Sprintf(`mintrun shim %q in auto mode has no permissions to mint, or a blank one (got %s): set "permissions" for %q in shims/config.json (mintrun shim install -mode auto -perms <p1,p2> %s), or list concrete "allowed_permissions" for provider %q in policy.json`,
				tool, got, tool, tool, provider)
			if !r.exited || r.code != 126 || r.out != "" || r.err != want+"\n" {
				t.Errorf("%s: code=%d exited=%v, want 126 and\n%s\ngot:\n%s%s", tool, r.code, r.exited, want, r.out, r.err)
			}
			if calls := takeCalls(t, home); calls != "" {
				t.Errorf("%s ran with no permissions: %q", tool, calls)
			}
			if _, err := os.Stat(filepath.Join(home, ".mintrun", "audit.jsonl")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s reached ExecBlind with no permissions (audit.jsonl: %v)", tool, err)
			}
		}
		refused("aws", "aws", `[]`)
		refused("vercel", "vercel", `[]`)
		refused("psql", "postgres-jit", `[]`)
		// A blank entry is refused too, from a hand-edited config.json or from policy.json.
		writeFile(t, filepath.Join(dir, "config.json"), `{"aws":{"mode":"auto","permissions":["s3:ListBucket"," "]}}`)
		refused("aws", "aws", `["s3:ListBucket" " "]`)
		writeFile(t, filepath.Join(dir, "config.json"), `{"aws":{"mode":"auto"}}`)
		writeFile(t, policy, `{"aws":{"allowed_permissions":[""]}}`)
		refused("aws", "aws", `[""]`)

		// The positive control: with a permission the shim reaches ExecBlind, which audits the run
		// (a failed one, since no aws secret is stored) with that permission.
		writeFile(t, policy, `{"aws":{"allowed_permissions":["s3:ListBucket"]}}`)
		r := runAsTool(t, filepath.Join(dir, "aws"), "x")
		if !r.exited || r.code != 1 || !strings.Contains(r.err, "run mintrun init aws") {
			t.Errorf("aws with a permission: code=%d exited=%v:\n%s%s", r.code, r.exited, r.out, r.err)
		}
		if e := lastAudit(t, filepath.Join(home, ".mintrun")); e.Outcome != "failed" || !slices.Equal(e.Permissions, []string{"s3:ListBucket"}) {
			t.Errorf("audit entry = %+v, want a failed run with s3:ListBucket", e)
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
		if e := lastAudit(t, filepath.Join(home, ".mintrun")); e.Outcome != "done" || e.Via != "cli" {
			t.Errorf("audit entry = %+v, want a done run via cli", e)
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

	t.Run("provider runs a shim as an account", func(t *testing.T) {
		home, _ := setupEnv(t)
		mintrunHome := filepath.Join(home, ".mintrun")
		dir := filepath.Join(mintrunHome, "shims")
		bin := filepath.Join(home, "bin")
		writeFile(t, filepath.Join(bin, "gh"), stubLog+`printf 'token=%s\n' "$GH_TOKEN"`+"\n")
		if err := os.Chmod(filepath.Join(bin, "gh"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+bin)
		pat := "ghp_work_" + leak
		setSecret(t, "github@work", pat)
		writeFile(t, filepath.Join(mintrunHome, "policy.json"),
			`{"github":{},"github@ci":{},"github@work":{"allowed_scopes":["acme/widgets"],"allow_static":true}}`)
		provider := func() string {
			t.Helper()
			cfg, err := loadShimConfig(mintrunHome)
			if err != nil {
				t.Fatal(err)
			}
			return cfg["gh"].Provider
		}

		// policy.json names GitHub accounts, so install asks which one runs gh; an answer out of
		// range stops it before anything is linked.
		r := runCLI(t, "9\n", nil, "shim", "install", "gh")
		if !r.exited || r.code != 1 || !strings.Contains(r.err, "expected a number from 1 to 3") {
			t.Fatalf("out-of-range answer: code=%d\n%s%s", r.code, r.out, r.err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gh")); !os.IsNotExist(err) {
			t.Errorf("install linked gh after a bad answer: %v", err)
		}
		// Enter (EOF here) picks the default account, which stores no provider.
		if r := runCLI(t, "", nil, "shim", "install", "gh"); r.exited {
			t.Fatalf("install default: %s%s", r.out, r.err)
		}
		if p := provider(); p != "" {
			t.Errorf("default account stored provider %q", p)
		}
		// A number picks the account, and the same reader then answers the profile question.
		r = runCLI(t, "3\ny\n", nil, "shim", "install", "-mode", "auto", "-perms", "static", "gh")
		if r.exited || !strings.Contains(r.out, "  1) github (the default account)\n  2) github@ci\n  3) github@work\n") {
			t.Fatalf("install numbered: %s%s", r.out, r.err)
		}
		if p := provider(); p != "github@work" {
			t.Errorf("provider = %q, want github@work", p)
		}
		if data, _ := os.ReadFile(filepath.Join(home, ".zshrc")); !strings.Contains(string(data), shimProfileMarker) {
			t.Errorf(".zshrc not wired after the numbered answer:\n%s", data)
		}
		if r := runCLI(t, "", nil, "shim", "list"); r.exited || !strings.Contains(r.out, "github@work") {
			t.Errorf("shim list does not show the account:\n%s%s", r.out, r.err)
		}
		takeCalls(t, home)

		// Auto mode runs gh as github@work: that account's secret, and the scope its own rule allows.
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 0 || !strings.Contains(r.out, "token=[MINTRUN:REDACTED]") || strings.Contains(r.out+r.err, pat) {
			t.Fatalf("auto gh as github@work: code=%d\n%s%s", r.code, r.out, r.err)
		}
		if e := lastAudit(t, mintrunHome); e.Provider != "github@work" || e.Scope != "acme/widgets" || e.Outcome != "done" {
			t.Errorf("audit entry = %+v, want a done github@work run on acme/widgets", e)
		}

		// -provider skips the question, and block mode names the account in both hints.
		r = runCLI(t, "", nil, "shim", "install", "-provider", "github@work", "gh")
		if r.exited || strings.Contains(r.out, "Which one") {
			t.Fatalf("install -provider: %s%s", r.out, r.err)
		}
		takeCalls(t, home)
		r = runAsTool(t, filepath.Join(dir, "gh"), "repo", "view")
		if !r.exited || r.code != 126 || !strings.Contains(r.err, `MCP tool (provider="github@work")`) ||
			!strings.Contains(r.err, "mintrun exec -provider github@work -scope acme/widgets -perms contents:read,metadata:read -- gh repo view") {
			t.Errorf("block hint: code=%d\n%s", r.code, r.err)
		}
		if got := takeCalls(t, home); strings.Contains(got, "gh ") {
			t.Errorf("gh ran in block mode: %q", got)
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
			{"provider of another type", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"gh":{"provider":"aws@work"}}`)
			}, `shims/config.json tool "gh" has invalid provider "aws@work"`},
			{"provider with an uppercase account", func(t *testing.T, dir, cfgPath string) {
				writeFile(t, cfgPath, `{"gh":{"provider":"github@Work"}}`)
			}, `shims/config.json tool "gh" has invalid provider "github@Work"`},
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

// profileFiles is snapshot of home without mintrun's own files and the stubs: the shell profiles,
// links, and backups that shim install and remove may change.
func profileFiles(t *testing.T, home string) map[string]string {
	t.Helper()
	m := snapshot(t, home)
	maps.DeleteFunc(m, func(p, _ string) bool {
		return p == home || strings.HasPrefix(p, filepath.Join(home, ".mintrun")) || strings.HasPrefix(p, filepath.Join(home, "bin"))
	})
	return m
}

// popBackup checks that p has exactly one .bak- backup, holding want with mode, then deletes it
// from disk and from m, so the next change starts with none.
func popBackup(t *testing.T, m map[string]string, p, want string, mode os.FileMode) {
	t.Helper()
	baks, err := filepath.Glob(p + ".bak-*")
	if err != nil || len(baks) != 1 {
		t.Errorf("%s: backups %q (%v), want one", p, baks, err)
		return
	}
	if got, gotMode := m[baks[0]], modeOf(t, baks[0]); got != want || gotMode != mode {
		t.Errorf("%s = %q, mode %v; want %q, mode %v", baks[0], got, gotMode, want, mode)
	}
	delete(m, baks[0])
	if err := os.Remove(baks[0]); err != nil {
		t.Fatal(err)
	}
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
