package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

var exitFunc = os.Exit

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

func bootRuntime() (*core.Runtime, error) {
	home := defaultHomeDir()
	reg := core.NewRegistry()

	// Register built-in core plugins.
	_ = reg.Register(builtin.NewKeychainVault(home))
	_ = reg.Register(builtin.NewOnePasswordVault())
	_ = reg.Register(builtin.NewCloudflareProvider())
	_ = reg.Register(builtin.NewGitHubProvider())
	_ = reg.Register(builtin.NewAWSProvider())
	_ = reg.Register(builtin.NewGCPProvider())
	_ = reg.Register(builtin.NewMCPBridge())

	// Discover and register all externally installed plugins from ~/.mintrun/plugins.
	rt := core.NewRuntime(home, os.Getenv("MINTRUN_VAULT"), reg)
	if err := core.LoadExternalPlugins(rt.PluginsDir(), reg); err != nil {
		return nil, err
	}
	return rt, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if len(os.Args) < 2 {
		printUsage()
		exitFunc(1)
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
	case "-h", "--help", "help":
		printUsage()
	default:
		fatal("unknown subcommand %q (run `mintrun help`)", os.Args[1])
	}
}

func cmdExec(ctx context.Context, rt *core.Runtime, args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	provider := fs.String("provider", "cloudflare", "Provider plugin name (e.g. cloudflare, github)")
	scope := fs.String("scope", "", "Target resource scope (e.g. domain 'example.com' or repo 'owner/repo')")
	perms := fs.String("perms", "dns:write,workers:write", "Comma-separated permissions (or 'static')")
	vault := fs.String("vault", "", "Vault plugin override (default: keychain, or 1password)")
	ttl := fs.Int("ttl", 600, "Ephemeral token TTL in seconds")
	cwd := fs.String("cwd", "", "Working directory for command")
	approve := fs.Bool("approve", false, "Prompt for interactive macOS HITL approval before minting")
	cleanEnv := fs.Bool("clean-env", false, "Run the command with only PATH/HOME/TMPDIR/USER/LANG/TERM/SSL_CERT_FILE, policy allowed_env, and the lease env")

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
			sc := bufio.NewScanner(os.Stdin)
			if sc.Scan() {
				val = sc.Text()
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
		// Verify existence without ever printing the secret value.
		val, err := vault.GetSecret(ctx, key)
		if err != nil || val == "" {
			fatal("secret %q is NOT configured in vault %q", key, vault.Manifest().Name)
		}
		fmt.Printf("Secret %q is configured in vault %q (length=%d chars, value hidden).\n", key, vault.Manifest().Name, len(val))

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
			fatal("usage: mintrun plugin install <dir-or-https-url>")
		}
		m, err := core.InstallPlugin(ctx, rt.PluginsDir(), args[1])
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

func cmdMCP(ctx context.Context, rt *core.Runtime, args []string) {
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

	p := filepath.Join(rt.HomeDir, "audit.jsonl")
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No audit entries yet.")
			return
		}
		fatal("read audit log: %v", err)
	}
	if *provider == "" && !*failedOnly && *limit <= 0 {
		fmt.Print(string(raw))
		return
	}
	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e core.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if *provider != "" && !strings.EqualFold(e.Provider, *provider) {
			continue
		}
		if *failedOnly && e.ExitCode == 0 && e.Error == "" {
			continue
		}
		matched = append(matched, line)
	}
	if *limit > 0 && len(matched) > *limit {
		matched = matched[len(matched)-*limit:]
	}
	for _, line := range matched {
		fmt.Println(line)
	}
}

func printUsage() {
	fmt.Println(`mintrun — Zero-knowledge JIT credential minter & blind CLI runner for AI Agents

Usage:
  mintrun secret set <provider> [secret]                      Store master secret in OS Keychain vault
  mintrun secret check <provider>                             Verify secret exists without exposing value
  mintrun secret delete <provider>                            Delete master secret from vault
  mintrun exec -provider <name> -scope <zone> -- <cmd...>     Mint JIT token, run command blindly, scrub & revoke
  mintrun plugin list                                         List built-in and installed plugins
  mintrun plugin install <path-or-url>                        Install an external Vault/Provider plugin
  mintrun plugin remove <name>                                Remove an installed external plugin
  mintrun mcp                                                 Start MCP JSON-RPC 2.0 server over stdio
  mintrun audit                                               View zero-secret execution audit trail`)
}

func fatal(format string, a ...any) {
	out, _ := json.Marshal(map[string]string{"error": fmt.Sprintf(format, a...)})
	fmt.Fprintf(os.Stderr, "%s\n", out)
	exitFunc(1)
}
