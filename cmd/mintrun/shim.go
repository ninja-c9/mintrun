package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

type shimTarget struct {
	tool     string
	provider string
}

// shimTargets lists the CLIs mintrun can intercept on PATH and the provider each maps to.
var shimTargets = []shimTarget{
	{"gh", "github"},
	{"aws", "aws"},
	{"gcloud", "gcp"},
	{"wrangler", "cloudflare"},
	{"vercel", "vercel"},
	{"psql", "postgres-jit"},
}

// shimEntry is a tool's configuration in <home>/shims/config.json.
type shimEntry struct {
	Mode        string   `json:"mode,omitempty"`        // "block" (default) or "auto"
	Scope       string   `json:"scope,omitempty"`       // Default scope for auto/redirect
	Permissions []string `json:"permissions,omitempty"` // Default permissions for auto/redirect
	Approve     bool     `json:"approve,omitempty"`     // Require human approval in auto mode
	Provider    string   `json:"provider,omitempty"`    // <type>@<account> the shim runs as; empty means the tool's type
}

func shimProvider(tool string) string {
	for _, t := range shimTargets {
		if t.tool == tool {
			return t.provider
		}
	}
	return ""
}

// checkShimProvider returns an error unless p is empty, tool's provider type, or an account of it.
func checkShimProvider(tool, p string) error {
	typ := shimProvider(tool)
	if t, _ := core.SplitProvider(p); p == "" || t == typ && core.ValidProvider(p) {
		return nil
	}
	return fmt.Errorf("tool %q has invalid provider %q (want %s or %s@<account>; a provider is %s)", tool, p, typ, typ, core.ProviderForm)
}

func shimToolNames() []string {
	names := make([]string, len(shimTargets))
	for i, t := range shimTargets {
		names[i] = t.tool
	}
	return names
}

// invokedShimName returns the shimmed CLI name when arg0 is one of shimTargets, or "" when
// invoked as mintrun itself.
func invokedShimName(arg0 string) string {
	base := strings.TrimSuffix(filepath.Base(arg0), ".exe")
	if shimProvider(base) != "" {
		return base
	}
	return ""
}

func shimsDir(homeDir string) string {
	return filepath.Join(homeDir, "shims")
}

func shimConfigPath(homeDir string) string {
	return filepath.Join(shimsDir(homeDir), "config.json")
}

// loadShimConfig reads <home>/shims/config.json fail-closed. Only a missing file (checked via
// Lstat, rule 36) means default settings (block mode for all tools). Any read error, malformed
// JSON, unknown field, unknown tool key, invalid mode, or a provider that is not the tool's type
// or an account of it returns an error quoting only the underlying cause and never a local
// filesystem path.
func loadShimConfig(homeDir string) (map[string]shimEntry, error) {
	p := shimConfigPath(homeDir)
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return map[string]shimEntry{}, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("shims/config.json cannot be read (%v)", err)
	}
	cfg := map[string]shimEntry{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("shims/config.json is malformed (%v)", err)
	}
	if cfg == nil {
		cfg = map[string]shimEntry{}
	}
	for tool, e := range cfg {
		if shimProvider(tool) == "" {
			return nil, fmt.Errorf("shims/config.json has unknown tool %q", tool)
		}
		if e.Mode != "" && e.Mode != "block" && e.Mode != "auto" {
			return nil, fmt.Errorf("shims/config.json tool %q has invalid mode %q (want \"block\" or \"auto\")", tool, e.Mode)
		}
		if err := checkShimProvider(tool, e.Provider); err != nil {
			return nil, fmt.Errorf("shims/config.json %v", err)
		}
	}
	return cfg, nil
}

func writeShimConfig(homeDir string, cfg map[string]shimEntry) error {
	clean := map[string]shimEntry{}
	for k, v := range cfg {
		if v.Mode == "block" {
			v.Mode = ""
		}
		if v.Mode != "" || v.Scope != "" || len(v.Permissions) > 0 || v.Approve || v.Provider != "" {
			clean[k] = v
		}
	}
	if err := os.MkdirAll(shimsDir(homeDir), 0o700); err != nil {
		return err
	}
	out, err := marshalJSON(clean, "  ")
	if err != nil {
		return err
	}
	return builtin.WriteFileAtomic(shimConfigPath(homeDir), append(out, '\n'), 0o600)
}

func sameDir(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if ca == cb {
		return true
	}
	ra, errA := filepath.EvalSymlinks(ca)
	rb, errB := filepath.EvalSymlinks(cb)
	return errA == nil && errB == nil && ra == rb
}

// stripDirFromPath removes skipDir (both raw and symlink-resolved) from a PATH string so
// ExecBlind resolves the real underlying CLI binary instead of re-entering a shim.
func stripDirFromPath(pathEnv, skipDir string) string {
	var kept []string
	for _, d := range filepath.SplitList(pathEnv) {
		if !sameDir(d, skipDir) {
			kept = append(kept, d)
		}
	}
	return strings.Join(kept, string(filepath.ListSeparator))
}

// lookPathSkippingDir finds tool in pathEnv skipping skipDir and any relative PATH entry (rule 14).
func lookPathSkippingDir(tool, pathEnv, skipDir string) (string, error) {
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" || !filepath.IsAbs(d) || sameDir(d, skipDir) {
			continue
		}
		cand := filepath.Join(d, tool)
		fi, err := os.Stat(cand)
		if err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("executable %q not found on PATH outside shims", tool)
}

// shimFirstOnPath reports whether shimsDir appears on pathEnv as an absolute path before any
// other directory holding an executable named tool.
func shimFirstOnPath(tool, pathEnv, dir string) bool {
	for _, d := range filepath.SplitList(pathEnv) {
		if !filepath.IsAbs(d) {
			continue
		}
		if sameDir(d, dir) {
			return true
		}
		if fi, err := os.Stat(filepath.Join(d, tool)); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return false
		}
	}
	return false
}

// atomicSymlink creates or replaces linkPath as a symlink pointing to target, refusing to replace
// a directory.
func atomicSymlink(target, linkPath string) error {
	if fi, err := os.Lstat(linkPath); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", linkPath)
	}
	tmp := filepath.Join(filepath.Dir(linkPath), fmt.Sprintf(".%s-%d.tmp", filepath.Base(linkPath), os.Getpid()))
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// cmdShim manages PATH shims under <home>/shims: list, install, and remove.
func cmdShim(ctx context.Context, rt *core.Runtime, origPath string, args []string) {
	action := "list"
	if len(args) > 0 {
		action = args[0]
		args = args[1:]
	}
	switch action {
	case "list", "ls":
		if len(args) > 0 {
			fatal("usage: mintrun shim list")
		}
		shimList(rt, origPath)
	case "install", "add":
		shimInstall(ctx, rt, origPath, args)
	case "remove", "rm":
		shimRemove(ctx, rt, args)
	default:
		fatal("unknown shim action %q (use list, install, or remove)", action)
	}
}

func shimList(rt *core.Runtime, origPath string) {
	cfg, err := loadShimConfig(rt.HomeDir)
	if err != nil {
		fatal("%v", err)
	}
	dir := shimsDir(rt.HomeDir)
	fmt.Printf("%-10s %-14s %-11s %-7s %s\n", "TOOL", "PROVIDER", "SHIM", "MODE", "TARGET")
	for _, t := range shimTargets {
		link := filepath.Join(dir, t.tool)
		status := "-"
		if fi, err := os.Lstat(link); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			if shimFirstOnPath(t.tool, origPath, dir) {
				status = "active"
			} else {
				status = "installed"
			}
		}
		mode := cfg[t.tool].Mode
		if mode == "" {
			mode = "block"
		}
		target, err := lookPathSkippingDir(t.tool, origPath, dir)
		if err != nil {
			target = "-"
		}
		fmt.Printf("%-10s %-14s %-11s %-7s %s\n", t.tool, cmp.Or(cfg[t.tool].Provider, t.provider), status, mode, target)
	}
}

func shimInstall(ctx context.Context, rt *core.Runtime, origPath string, args []string) {
	fs := flag.NewFlagSet("shim install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "block", "Shim mode: block (reject & redirect agent) or auto (wrap via ExecBlind)")
	scope := fs.String("scope", "", "Default scope for auto/redirect")
	perms := fs.String("perms", "", "Comma-separated default permissions for auto/redirect")
	approve := fs.Bool("approve", false, "Require human approval in auto mode")
	provider := fs.String("provider", "", "Provider the shim runs commands as: the tool's type or <type>@<account>")
	if err := fs.Parse(args); err != nil {
		fatal("usage: mintrun shim install [-mode block|auto] [-scope <scope>] [-perms <p1,p2>] [-approve] [-provider <type>[@<account>]] [tool...]")
	}
	if *mode != "block" && *mode != "auto" {
		fatal("shim mode must be \"block\" or \"auto\", got %q", *mode)
	}
	tools := fs.Args()
	if len(tools) == 0 {
		tools = shimToolNames()
	}
	for _, tool := range tools {
		if shimProvider(tool) == "" {
			fatal("unknown shim tool %q (supported: %s)", tool, strings.Join(shimToolNames(), ", "))
		}
	}
	if len(tools) > 1 && (*scope != "" || *perms != "" || *provider != "") {
		fatal("-scope, -perms, and -provider can only be set when installing a single tool shim")
	}
	if err := checkShimProvider(tools[0], *provider); err != nil {
		fatal("-provider: %v", err)
	}
	self, err := mintrunPath()
	if err != nil {
		fatal("%v", err)
	}
	cfg, err := loadShimConfig(rt.HomeDir)
	if err != nil {
		fatal("%v", err)
	}
	var permList []string
	for _, p := range strings.Split(*perms, ",") {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			permList = append(permList, trimmed)
		}
	}
	dir := shimsDir(rt.HomeDir)
	line := shimProfileLine(dir)
	edits, err := shimProfileEdits(line, true)
	if err != nil {
		fatal("update shell profile: %v", err)
	}
	w := &wizard{ctx: ctx, rt: rt, in: bufio.NewReader(os.Stdin)} // one reader for every question
	if len(tools) == 1 && *provider == "" {
		*provider = shimAccount(w, tools[0])
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatal("%v", err)
	}
	if err := atomicSymlink(self, filepath.Join(dir, "mintrun")); err != nil {
		fatal("link mintrun shim: %v", err)
	}
	for _, tool := range tools {
		if err := atomicSymlink(self, filepath.Join(dir, tool)); err != nil {
			fatal("link %s shim: %v", tool, err)
		}
		entry := cfg[tool]
		entry.Mode = *mode
		if *scope != "" || len(tools) == 1 {
			entry.Scope = *scope
		}
		if len(permList) > 0 || len(tools) == 1 {
			entry.Permissions = permList
		}
		entry.Approve = *approve
		if len(tools) == 1 {
			entry.Provider = *provider
		}
		cfg[tool] = entry
	}
	if err := writeShimConfig(rt.HomeDir, cfg); err != nil {
		fatal("write shim config: %v", err)
	}
	fmt.Printf("Installed %s shim(s) in %s (%s).\n", *mode, dir, strings.Join(tools, ", "))
	if len(edits) > 0 {
		offerShimProfiles(w, line, edits, true)
	} else if !shimFirstOnPath(tools[0], origPath, dir) {
		fmt.Printf("Put %s first on PATH to use the shims:\n  export PATH=%s:\"$PATH\"\n", dir, shellQuote(dir))
	}
}

// shimAccount asks which account tool's shim runs commands as when policy.json has a rule for an
// account of the tool's type: the default account (the answer on Enter) or one of those accounts.
// It returns "" for the default account.
func shimAccount(w *wizard, tool string) string {
	typ := shimProvider(tool)
	rules, _ := w.rt.LoadPolicies() // a policy.json that fails to load offers no choice; exec denies every run anyway
	choices := []string{typ}
	for _, k := range slices.Sorted(maps.Keys(rules)) {
		if t, account := core.SplitProvider(k); t == typ && account != "" {
			choices = append(choices, k)
		}
	}
	if len(choices) == 1 {
		return ""
	}
	fmt.Printf("policy.json has rules for more than one %s account. Which one should the %s shim run commands as?\n", typ, tool)
	for i, c := range choices {
		if i == 0 {
			c += " (the default account)"
		}
		fmt.Printf("  %d) %s\n", i+1, c)
	}
	n, err := strconv.Atoi(cmp.Or(w.ask("Number (Enter for 1)"), "1"))
	if err != nil || n < 1 || n > len(choices) {
		fatal("expected a number from 1 to %d", len(choices))
	}
	if n == 1 {
		return ""
	}
	return choices[n-1]
}

func shimRemove(ctx context.Context, rt *core.Runtime, args []string) {
	tools := args
	if len(tools) == 0 {
		tools = shimToolNames()
	}
	for _, tool := range tools {
		if shimProvider(tool) == "" {
			fatal("unknown shim tool %q (supported: %s)", tool, strings.Join(shimToolNames(), ", "))
		}
	}
	cfg, err := loadShimConfig(rt.HomeDir)
	if err != nil {
		fatal("%v", err)
	}
	dir := shimsDir(rt.HomeDir)
	for _, tool := range tools {
		if err := os.Remove(filepath.Join(dir, tool)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fatal("remove %s shim: %v", tool, err)
		}
		delete(cfg, tool)
	}
	if _, err := os.Lstat(shimConfigPath(rt.HomeDir)); err == nil {
		if err := writeShimConfig(rt.HomeDir, cfg); err != nil {
			fatal("write shim config: %v", err)
		}
	}
	fmt.Printf("Removed shim(s): %s.\n", strings.Join(tools, ", "))
	if !anyShimInstalled(dir) {
		line := shimProfileLine(dir)
		edits, err := shimProfileEdits(line, false)
		if err != nil {
			fatal("clean shell profile: %v", err)
		}
		if len(edits) > 0 {
			offerShimProfiles(&wizard{ctx: ctx, in: bufio.NewReader(os.Stdin)}, line, edits, false)
		}
	}
}

const shimProfileMarker = "# mintrun-shim"

func anyShimInstalled(dir string) bool {
	for _, t := range shimTargets {
		if fi, err := os.Lstat(filepath.Join(dir, t.tool)); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// shimProfileLine is the exact line shim install puts in shell profiles and shim remove takes out.
func shimProfileLine(dir string) string {
	return fmt.Sprintf("export PATH=%s:\"$PATH\" %s", shellQuote(dir), shimProfileMarker)
}

// profileEdit is a change to one shell profile: its name as shown, the file written (a link's
// target), that file's mode, and its contents before (nil when it is new) and after.
type profileEdit struct {
	name, path string
	mode       fs.FileMode
	old        []byte
	out        string
}

// shimProfileEdits returns the shell profiles that shim install (add) or remove (!add) would
// change. Install puts line last in ~/.zshenv and ~/.zshrc, creating them, and in ~/.zprofile and
// ~/.bashrc when they exist; remove takes it out. Only the exact line counts, so a user's own line
// that mentions the marker stays. A linked profile (dotfiles) is changed where it lives, and a
// link that cannot be followed is left alone, never replaced by a file.
func shimProfileEdits(line string, add bool) ([]profileEdit, error) {
	userHome, err := os.UserHomeDir()
	if err != nil || userHome == "" {
		return nil, nil
	}
	var edits []profileEdit
	for _, c := range []struct {
		name   string
		create bool
	}{{".zshenv", true}, {".zshrc", true}, {".zprofile", false}, {".bashrc", false}} {
		p := filepath.Join(userHome, c.name)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		} else if _, err := os.Lstat(p); err == nil {
			continue
		}
		old, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			if !add || !c.create {
				continue
			}
		} else if err != nil {
			return nil, err
		}
		mode := fs.FileMode(0o600)
		if fi, err := os.Stat(p); err == nil {
			mode = fi.Mode().Perm()
		}
		var b strings.Builder
		for ln := range strings.Lines(string(old)) {
			if strings.TrimSuffix(ln, "\n") != line {
				b.WriteString(ln)
			}
		}
		out := b.String()
		if add {
			if out != "" && !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			out += line + "\n"
		}
		if out != string(old) {
			edits = append(edits, profileEdit{"~/" + c.name, p, mode, old, out})
		}
	}
	return edits, nil
}

// offerShimProfiles shows line and the profiles edits change, and changes them only on a yes,
// first copying each existing one to a timestamped .bak- backup with its mode, as init does.
func offerShimProfiles(w *wizard, line string, edits []profileEdit, add bool) {
	var names []string
	for _, e := range edits {
		names = append(names, e.name)
	}
	list := strings.Join(names, ", ")
	verb := "Remove"
	if add {
		verb = "Add"
		fmt.Printf("To put the shims first on PATH in new shells, this line goes last in %s:\n  %s\n", list, line)
	} else {
		fmt.Printf("No shim is left, so this line can come out of %s:\n  %s\n", list, line)
	}
	if !w.confirm(verb + " it (each existing file is backed up first)?") {
		fmt.Println("Left them unchanged.")
		return
	}
	stamp := time.Now().Format("20060102-150405")
	for _, e := range edits {
		// The question may have waited a while: a profile edited since it was read is left alone.
		if cur, _ := os.ReadFile(e.path); !bytes.Equal(cur, e.old) {
			fatal("%s changed while mintrun waited, so it was left unchanged; run the command again", e.name)
		}
		if e.old != nil { // nil: a new file, with nothing to back up
			if err := builtin.WriteFileAtomic(e.path+".bak-"+stamp, e.old, e.mode); err != nil {
				fatal("back up %s: %v", e.name, err)
			}
		}
		if err := builtin.WriteFileAtomic(e.path, []byte(e.out), e.mode); err != nil {
			fatal("update %s: %v", e.name, err)
		}
	}
	if add {
		fmt.Printf("Added it to %s; open a new shell to use the shims.\n", list)
	} else {
		fmt.Printf("Removed it from %s.\n", list)
	}
}

// runShim handles an invocation where argv[0] is a shimmed CLI name (gh, aws, gcloud, wrangler,
// vercel, psql).
func runShim(ctx context.Context, rt *core.Runtime, origPath, tool string, args []string) {
	cfg, err := loadShimConfig(rt.HomeDir)
	if err != nil {
		fatalExit(126, "mintrun shim %q blocked: %v", tool, err)
		return
	}
	entry := cfg[tool]
	provider := cmp.Or(entry.Provider, shimProvider(tool))
	mode := entry.Mode
	// MINTRUN_SHIM_MODE may tighten "auto" to "block", never loosen "block" to "auto": an agent in
	// bash controls its own environment variables (rule 11).
	if mode == "" || os.Getenv("MINTRUN_SHIM_MODE") == "block" {
		mode = "block"
	}
	scope, perms := inferShimScopePerms(rt, tool, provider, entry, args)
	if mode != "auto" {
		hintScope := scope
		if hintScope == "" {
			hintScope = "<scope>"
		}
		hintPerms := strings.Join(perms, ",")
		if hintPerms == "" {
			hintPerms = "<perms>"
		}
		cmdStr := strings.Join(append([]string{tool}, args...), " ")
		fatalExit(126, "direct execution of %q is blocked by mintrun: call the \"mintrun_exec\" MCP tool (provider=%q) or run `mintrun exec -provider %s -scope %s -perms %s -- %s`",
			tool, provider, provider, hintScope, hintPerms, cmdStr)
		return
	}
	// An empty list mints the provider's widest credential, and aws, vercel, and psql have no
	// default to fall back on. A blank entry is refused as the CLI's -perms refuses it (rule 57).
	if len(perms) == 0 || slices.ContainsFunc(perms, func(p string) bool { return strings.TrimSpace(p) == "" }) {
		fatalExit(126, "mintrun shim %q in auto mode has no permissions to mint, or a blank one (got %q): set \"permissions\" for %q in shims/config.json (mintrun shim install -mode auto -perms <p1,p2> %s), or list concrete \"allowed_permissions\" for provider %q in policy.json",
			tool, perms, tool, tool, provider)
		return
	}

	realBin, err := lookPathSkippingDir(tool, origPath, shimsDir(rt.HomeDir))
	if err != nil {
		fatalExit(127, "mintrun shim %q: %v", tool, err)
		return
	}
	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{
			Provider:    provider,
			Scope:       scope,
			Permissions: perms,
		},
		Command: append([]string{realBin}, args...),
		Approve: entry.Approve,
		Via:     "cli",
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "policy denied:") || strings.HasPrefix(err.Error(), "exec requires") {
			fatalExit(126, "%v", err)
			return
		}
		fatal("%v", err)
		return
	}
	if res.Stdout != "" {
		fmt.Print(res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprint(os.Stderr, res.Stderr)
	}
	exitFunc(res.ExitCode)
}

func inferShimScopePerms(rt *core.Runtime, tool, provider string, entry shimEntry, args []string) (string, []string) {
	scope := entry.Scope
	if scope == "" && tool == "gh" {
		scope = ghRepoFromArgsOrGit(args)
	}
	rules, _ := rt.LoadPolicies() // a broken policy.json infers nothing here; ExecBlind denies it
	rule, hasRule := rules[provider]
	if scope == "" && hasRule && len(rule.AllowedScopes) == 1 && !strings.Contains(rule.AllowedScopes[0], "*") {
		scope = rule.AllowedScopes[0]
	}

	perms := slices.Clone(entry.Permissions)
	if len(perms) == 0 && hasRule {
		for _, p := range rule.AllowedPermissions {
			if !strings.Contains(p, "*") {
				perms = append(perms, p)
			}
		}
	}
	if len(perms) == 0 {
		switch tool {
		case "gh":
			perms = []string{"contents:read", "metadata:read"}
		case "gcloud":
			perms = []string{"cloud-platform.read-only"}
		case "wrangler":
			perms = []string{"workers:write"}
		}
	}
	return scope, perms
}

// ghRepoFromArgsOrGit extracts owner/repo from `gh -R/--repo [HOST/]OWNER/REPO` or from
// `git remote get-url origin` without ever printing the remote URL (rule 35).
func ghRepoFromArgsOrGit(args []string) string {
	for i := 0; i < len(args); i++ {
		var val string
		switch {
		case (args[i] == "-R" || args[i] == "--repo") && i+1 < len(args):
			val = args[i+1]
		case strings.HasPrefix(args[i], "-R="):
			val = strings.TrimPrefix(args[i], "-R=")
		case strings.HasPrefix(args[i], "--repo="):
			val = strings.TrimPrefix(args[i], "--repo=")
		}
		if val != "" {
			parts := strings.Split(strings.Trim(val, "/"), "/")
			if len(parts) >= 2 {
				cand := parts[len(parts)-2] + "/" + parts[len(parts)-1]
				if githubScopeRe.MatchString(cand) && !strings.HasSuffix(cand, "/*") {
					return cand
				}
			}
		}
	}
	if out, err := exec.Command("git", "remote", "get-url", "origin").Output(); err == nil {
		if m := githubRemoteRe.FindStringSubmatch(strings.TrimSpace(string(out))); m != nil {
			return m[1]
		}
	}
	return ""
}

// doctorShims checks <home>/shims when the directory exists: config.json, each tool symlink, a
// configured provider's secret (stored holds the keys doctorVault found, nil when it could not
// check), and whether <home>/shims precedes any other copy of the shimmed binary on PATH.
func doctorShims(rt *core.Runtime, self, origPath string, stored map[string]bool, report reportFunc) {
	dir := shimsDir(rt.HomeDir)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return
	}
	cfg, err := loadShimConfig(rt.HomeDir)
	if err != nil {
		report("FAIL", "shims: %v, so every shim denies execution", err)
		return
	}
	for _, t := range shimTargets {
		link := filepath.Join(dir, t.tool)
		fi, err := os.Lstat(link)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			report("FAIL", "shim %s: %s is not a symlink (run mintrun shim install %s)", t.tool, link, t.tool)
			continue
		}
		got, err := filepath.EvalSymlinks(link)
		if err != nil {
			report("FAIL", "shim %s: %s points to a missing binary (run mintrun shim install %s)", t.tool, link, t.tool)
			continue
		}
		if self != "" && got != self {
			report("warn", "shim %s: %s points to %s, not this binary (run mintrun shim install %s)", t.tool, link, got, t.tool)
			continue
		}
		if p := cfg[t.tool].Provider; p != "" && stored != nil && !stored[p] {
			report("warn", "shim %s: runs as %s, which has no master secret", t.tool, p)
		}
		mode := cfg[t.tool].Mode
		if mode == "" {
			mode = "block"
		}
		if !shimFirstOnPath(t.tool, origPath, dir) {
			report("warn", "shim %s (%s): %s is not before %s on PATH (export PATH=%s:\"$PATH\")", t.tool, mode, dir, t.tool, shellQuote(dir))
			continue
		}
		report("ok", "shim %s: %s mode", t.tool, mode)
	}
}
