package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ninja-c9/mintrun/examples/plugins"
	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

// version is stamped at build time with -ldflags "-X main.version=<tag>" (scripts/release.sh).
var version string

// Swapped by tests.
var (
	exitFunc      = os.Exit
	sttyPath      = "/bin/stty"
	osExecutable  = os.Executable
	openPath      = "/usr/bin/open"
	readBuildInfo = debug.ReadBuildInfo
)

// versionString is the -X stamp, else the VCS revision go build embeds from a checkout (12
// characters, +dirty when the tree had changes), else dev (rule 49).
func versionString() string {
	v := version
	if v == "" {
		v = "dev"
		if info, ok := readBuildInfo(); ok {
			var rev, dirty string
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					rev = s.Value[:min(12, len(s.Value))]
				case "vcs.modified":
					if s.Value == "true" {
						dirty = "+dirty"
					}
				}
			}
			if rev != "" {
				v = rev + dirty
			}
		}
	}
	return fmt.Sprintf("mintrun %s (%s, %s/%s)", v, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func defaultHomeDir() string {
	if env := os.Getenv("MINTRUN_HOME"); env != "" {
		return env
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ".mintrun"
	}
	return filepath.Join(h, ".mintrun")
}

// settings is <home>/settings.json, which the macOS app writes. Each field is a pointer, so a key
// that is present must hold a valid value.
type settings struct {
	Vault           *string `json:"vault"`
	ApprovalTimeout *int    `json:"approval_timeout_seconds"`
}

// loadSettings reads <home>/settings.json. Only a missing file means no settings (rule 36), and
// unknown keys are ignored, so a newer app's file still loads. Errors quote the cause, never the path.
func loadSettings(home string) (settings, error) {
	var s settings
	p := filepath.Join(home, "settings.json")
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return s, fmt.Errorf("settings.json cannot be read (%v)", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("settings.json is malformed (%v)", err)
	}
	if s.Vault != nil && !slices.Contains([]string{"keychain", "1password", "file"}, *s.Vault) {
		return s, errors.New(`settings.json: vault must be "keychain", "1password" or "file"`)
	}
	// Telegram and Slack stop at their own 10 minutes.
	if t := s.ApprovalTimeout; t != nil && (*t < 1 || *t > 600) {
		return s, errors.New("settings.json: approval_timeout_seconds must be 1 to 600")
	}
	return s, nil
}

// bootRuntime reads settings.json once, so a change applies from the next mintrun process on (a
// running `mintrun mcp` keeps what it read).
func bootRuntime() (*core.Runtime, error) {
	home := defaultHomeDir()
	s, err := loadSettings(home)
	if err != nil {
		return nil, err
	}
	reg := core.NewRegistry()
	kv := builtin.NewKeychainVault(home)
	vault := os.Getenv("MINTRUN_VAULT")
	// MINTRUN_VAULT and MINTRUN_FILE_VAULT=1 win over the app's choice.
	if s.Vault != nil && vault == "" && os.Getenv("MINTRUN_FILE_VAULT") != "1" {
		switch *s.Vault {
		case "1password":
			vault = "1password"
		case "file":
			kv.ForceFile, kv.SecretTool = true, ""
		}
	}

	// Register built-in core plugins.
	_ = reg.Register(kv)
	_ = reg.Register(builtin.NewOnePasswordVault())
	_ = reg.Register(builtin.NewCloudflareProvider())
	_ = reg.Register(builtin.NewGitHubProvider())
	_ = reg.Register(builtin.NewAWSProvider())
	_ = reg.Register(builtin.NewGCPProvider())
	_ = reg.Register(builtin.NewMCPBridge())

	// Discover and register all externally installed plugins from ~/.mintrun/plugins.
	rt := core.NewRuntime(home, vault, reg)
	// The app answers instead of the dialog when it runs; Telegram and Slack race either one.
	rt.ApprovalFunc = core.FirstApproval(builtin.AppApproval(rt, core.OSApproval), builtin.TelegramApproval(rt), builtin.SlackApproval(rt))
	rt.Track = builtin.AppTrack(rt)
	if s.ApprovalTimeout != nil {
		rt.ApprovalTimeout = time.Duration(*s.ApprovalTimeout) * time.Second
	}
	if err := core.LoadExternalPlugins(rt.PluginsDir(), reg); err != nil {
		return nil, err
	}
	if err := configureRelay(rt, os.Getenv("MINTRUN_RELAY")); err != nil {
		return nil, err
	}
	return rt, nil
}

func main() {
	// SIGHUP too: a blind command runs in its own process group (audit L2), so a terminal hangup
	// no longer reaches it; cancelling the context kills that group, revokes the lease and audits.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	if len(os.Args) > 0 {
		if tool := invokedShimName(os.Args[0]); tool != "" {
			rt, err := bootRuntime()
			if err != nil {
				fatal("boot runtime: %v", err)
			}
			origPath := os.Getenv("PATH")
			defer withoutShimsOnPath(rt.HomeDir)()
			runShim(ctx, rt, origPath, tool, os.Args[1:])
			return
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		exitFunc(1)
		return
	}

	// Before bootRuntime, so nothing that stops every other command hides the version (rule 49).
	if slices.Contains([]string{"version", "-version", "--version"}, os.Args[1]) {
		fmt.Println(versionString())
		return
	}

	rt, err := bootRuntime()
	if err != nil {
		fatal("boot runtime: %v", err)
	}

	switch os.Args[1] {
	case "exec", "run":
		cmdExec(ctx, rt, os.Args[2:])
	case "secret":
		cmdSecret(ctx, rt, os.Args[2:])
	case "plugin":
		cmdPlugin(ctx, rt, os.Args[2:])
	case "mcp":
		cmdMCP(ctx, rt, os.Args[2:])
	case "audit":
		cmdAudit(rt, os.Args[2:])
	case "init":
		cmdInit(ctx, rt, os.Args[2:])
	case "doctor":
		cmdDoctor(ctx, rt, os.Args[2:])
	case "shim":
		cmdShim(ctx, rt, os.Getenv("PATH"), os.Args[2:])
	case "apps":
		cmdApps(ctx, os.Args[2:])
	case "relay":
		cmdRelay(ctx, rt, os.Args[2:])
	case "watch":
		cmdWatch(ctx, rt, os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fatal("unknown subcommand %q (run `mintrun help`)", os.Args[1])
	}
}

func cmdExec(ctx context.Context, rt *core.Runtime, args []string) {
	defer withoutShimsOnPath(rt.HomeDir)()
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	provider := fs.String("provider", "cloudflare", "Provider plugin name (e.g. cloudflare, github)")
	scope := fs.String("scope", "", "Target resource scope (e.g. domain 'example.com' or repo 'owner/repo')")
	perms := fs.String("perms", "dns:write,workers:write", "Comma-separated permissions (or 'static')")
	vault := fs.String("vault", "", "Vault plugin override (default: keychain, or 1password)")
	ttl := fs.Int("ttl", 600, "Ephemeral token TTL in seconds")
	cwd := fs.String("cwd", "", "Working directory for command")
	approve := fs.Bool("approve", false, "Ask a human before minting: the mintrun app (a macOS dialog when it is not running), plus Telegram or Slack when approval-telegram or approval-slack is set")
	cleanEnv := fs.Bool("clean-env", false, "Run the command with only PATH/HOME/TMPDIR/USER/LANG/TERM/SSL_CERT_FILE, policy allowed_env, and the lease env")
	sandbox := fs.Bool("sandbox", false, "Run the command in the OS sandbox (macOS and Linux), away from mintrun's home and the keystore")
	noNetwork := fs.Bool("no-network", false, "Block the command's network egress inside the OS sandbox (implies -sandbox)")
	relayURL := fs.String("relay", "", "Remote relay URL (https://host:port#sha256=<spki-hex>; overrides MINTRUN_RELAY)")

	var cmdArgs []string
	var flagArgs []string
	for i, a := range args {
		if a == "--" {
			flagArgs = args[:i]
			cmdArgs = args[i+1:]
			break
		}
	}
	if cmdArgs == nil {
		_ = fs.Parse(args)
		cmdArgs = fs.Args()
	} else {
		_ = fs.Parse(flagArgs)
	}

	if len(cmdArgs) == 0 {
		fatal("usage: mintrun exec -provider cloudflare -scope example.com -- <command> [args...]")
	}
	if *relayURL != "" {
		if err := configureRelay(rt, *relayURL); err != nil {
			fatal("%v", err)
		}
	}

	var permList []string
	for _, p := range strings.Split(*perms, ",") {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			permList = append(permList, trimmed)
		}
	}

	res, err := rt.ExecBlind(ctx, core.ExecRequest{
		MintRequest: core.MintRequest{
			Provider:    *provider,
			Scope:       *scope,
			Permissions: permList,
			TTLSeconds:  *ttl,
		},
		Vault:      *vault,
		Command:    cmdArgs,
		WorkingDir: *cwd,
		Approve:    *approve,
		CleanEnv:   *cleanEnv,
		Sandbox:    *sandbox,
		NoNetwork:  *noNetwork,
		Via:        "cli",
	})
	if err != nil {
		fatal("%v", err)
	}
	if res.Stdout != "" {
		fmt.Print(res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprint(os.Stderr, res.Stderr)
	}
	exitFunc(res.ExitCode)
}

func cmdSecret(ctx context.Context, rt *core.Runtime, args []string) {
	if len(args) < 2 {
		fatal("usage: mintrun secret <set|delete|check> <provider> [value]")
	}
	action, key := args[0], args[1]
	vault, err := rt.Registry.Vault(rt.DefaultVault)
	if err != nil {
		fatal("%v", err)
	}

	switch action {
	case "set":
		var val string
		if len(args) >= 3 {
			val = args[2]
			fmt.Fprintln(os.Stderr, "mintrun: warning: a secret given as an argument is visible in shell history and `ps`; pipe it on stdin or use the prompt instead")
		} else if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
			// Piped or redirected (`< sa-key.json`): read it whole so multi-line secrets such as a
			// GCP service-account key or a PEM survive intact (and stay off argv, audit M5).
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if err != nil {
				fatal("read secret from stdin: %v", err) // never overwrite a stored secret with a partial read
			}
			val = string(b)
		} else {
			fmt.Fprintf(os.Stderr, "Enter master secret for %q: ", key)
			hidden := setEcho(false)
			sc := bufio.NewScanner(os.Stdin)
			if sc.Scan() {
				val = sc.Text()
			}
			if hidden {
				setEcho(true) // not deferred: fatal exits without running defers
				fmt.Fprintln(os.Stderr)
			}
		}
		if err := vault.SetSecret(ctx, key, val); err != nil {
			fatal("set secret: %v", err)
		}
		fmt.Printf("Stored master secret for %q in vault %q.\n", key, vault.Manifest().Name)

	case "delete", "rm":
		if err := vault.DeleteSecret(ctx, key); err != nil {
			fatal("delete secret: %v", err)
		}
		fmt.Printf("Deleted master secret for %q from vault %q.\n", key, vault.Manifest().Name)

	case "check":
		// Verify existence without ever printing the secret value or anything derived from it, its
		// length included. Only the vault can tell a miss from a failure (a wrong
		// MINTRUN_VAULT_KEY), and its error already names the fix.
		val, err := vault.GetSecret(ctx, key)
		switch {
		case errors.Is(err, builtin.ErrSecretNotFound):
			fatal("secret %q is NOT configured in vault %q: %v", key, vault.Manifest().Name, err)
		case err != nil:
			fatal("could not read vault %q to check secret %q: %v", vault.Manifest().Name, key, err)
		case val == "":
			fatal("secret %q is NOT configured in vault %q", key, vault.Manifest().Name)
		}
		fmt.Printf("Secret %q is configured in vault %q (value hidden).\n", key, vault.Manifest().Name)

	default:
		fatal("unknown secret action %q (use set, delete, or check)", action)
	}
}

func cmdPlugin(ctx context.Context, rt *core.Runtime, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		manifests := rt.Registry.Manifests()
		fmt.Printf("%-14s %-10s %-8s %-9s %s\n", "NAME", "KIND", "VERSION", "SOURCE", "DESCRIPTION")
		for _, m := range manifests {
			src := "external"
			if m.Builtin {
				src = "builtin"
			}
			fmt.Printf("%-14s %-10s %-8s %-9s %s\n", m.Name, m.Kind, m.Version, src, m.Description)
		}

	case "install", "add":
		if len(args) < 2 {
			names, _ := fs.Glob(plugins.Catalog, "*")
			fatal("usage: mintrun plugin install <name|dir|https-url> (bundled: %s)", strings.Join(names, ", "))
		}
		m, err := installPlugin(ctx, rt.PluginsDir(), args[1])
		if err != nil {
			fatal("install plugin: %v", err)
		}
		fmt.Printf("Installed plugin %q (%s v%s) into %s\n", m.Name, m.Kind, m.Version, rt.PluginsDir())

	case "remove", "rm":
		if len(args) < 2 {
			fatal("usage: mintrun plugin remove <name>")
		}
		if err := core.RemovePlugin(rt.PluginsDir(), args[1]); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("Removed external plugin %q.\n", args[1])

	default:
		fatal("unknown plugin action %q (use list, install, or remove)", args[0])
	}
}

// installPlugin installs the plugin bundled under the name src, else the directory or URL src
// names. A bundled name wins over a directory of the same name in the working directory, so a
// planted ./bitwarden is never installed by accident; "./bitwarden" installs that directory.
func installPlugin(ctx context.Context, pluginsDir, src string) (core.Manifest, error) {
	if _, err := fs.Stat(plugins.Catalog, src+"/plugin.json"); err != nil {
		return core.InstallPlugin(ctx, pluginsDir, src)
	}
	sub, _ := fs.Sub(plugins.Catalog, src) // src is a valid path: Stat found a file under it
	tmp, err := os.MkdirTemp("", "mintrun-plugin-")
	if err != nil {
		return core.Manifest{}, err
	}
	defer os.RemoveAll(tmp)
	if err := os.CopyFS(tmp, sub); err != nil {
		return core.Manifest{}, err
	}
	return core.InstallPlugin(ctx, pluginsDir, tmp)
}

func cmdMCP(ctx context.Context, rt *core.Runtime, args []string) {
	defer withoutShimsOnPath(rt.HomeDir)()
	bridgeName := "mcp"
	if len(args) > 0 {
		bridgeName = args[0]
	}
	bridge, err := rt.Registry.Bridge(bridgeName)
	if err != nil {
		fatal("%v", err)
	}
	if err := bridge.Serve(ctx, rt, os.Stdin, os.Stdout); err != nil {
		fatal("mcp bridge: %v", err)
	}
}

func cmdAudit(rt *core.Runtime, args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	provider := fs.String("provider", "", "Filter audit entries by provider name")
	failedOnly := fs.Bool("failed", false, "Show only failed executions (exit_code != 0 or error != '')")
	limit := fs.Int("limit", 0, "Show only the last N matching entries")
	_ = fs.Parse(args)

	f, err := os.Open(filepath.Join(rt.HomeDir, "audit.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No audit entries yet.")
			return
		}
		fatal("read audit log: %v", err)
	}
	defer f.Close()
	if *provider == "" && !*failedOnly && *limit <= 0 {
		_, err = io.Copy(os.Stdout, f)
	} else {
		err = core.TailAudit(f, *provider, *failedOnly, *limit, func(line string, _ core.AuditEntry) { fmt.Println(line) })
	}
	if err != nil {
		fatal("read audit log: %v", err)
	}
}

func printUsage() {
	fmt.Println(`mintrun — Zero-knowledge JIT credential minter & blind CLI runner for AI Agents

Usage:
  mintrun init [step]                                         Set up secrets, approval, policy and IDEs step by step
  mintrun doctor                                              Check the setup without changing anything
  mintrun shim [list|install|remove] [tool...]                Intercept bare CLI calls (gh, aws, gcloud, wrangler, vercel, psql)
  mintrun apps status|connect|disconnect [-app <list>]        Add mintrun to Claude Code, Claude Desktop or Cursor (JSON output)
  mintrun watch [-http 127.0.0.1:0]                           Listen on app.sock for approvals, running tasks, Stop and Pause
  mintrun relay serve|device ...                              Serve the team relay over TLS 1.3 or manage enrolled devices
  mintrun secret set <provider> [secret]                      Store master secret in OS Keychain vault
  mintrun secret check <provider>                             Verify secret exists without exposing value
  mintrun secret delete <provider>                            Delete master secret from vault
  mintrun exec -provider <name> -scope <zone> -- <cmd...>     Mint JIT token, run command blindly, scrub & revoke
  mintrun plugin list                                         List built-in and installed plugins
  mintrun plugin install <name|path|url>                      Install a bundled plugin by name, or one from a directory or URL
  mintrun plugin remove <name>                                Remove an installed external plugin
  mintrun mcp                                                 Start MCP JSON-RPC 2.0 server over stdio
  mintrun audit                                               View zero-secret execution audit trail
  mintrun version                                             Print the version, Go version and platform`)
}

func withoutShimsOnPath(homeDir string) func() {
	orig := os.Getenv("PATH")
	_ = os.Setenv("PATH", stripDirFromPath(orig, shimsDir(homeDir)))
	return func() { _ = os.Setenv("PATH", orig) }
}

// setEcho turns terminal echo on or off so a typed secret is not shown (the stdlib has no termios
// API). It reports whether stty succeeded, which it does not when stdin is not a terminal.
func setEcho(on bool) bool {
	mode := "-echo"
	if on {
		mode = "echo"
	}
	cmd := exec.Command(sttyPath, mode)
	cmd.Stdin = os.Stdin
	return cmd.Run() == nil
}

func fatal(format string, a ...any) {
	fatalExit(1, format, a...)
}

func fatalExit(code int, format string, a ...any) {
	out, _ := json.Marshal(map[string]string{"error": fmt.Sprintf(format, a...)})
	fmt.Fprintf(os.Stderr, "%s\n", out)
	exitFunc(code)
}
