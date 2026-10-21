package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/ninja-c9/mintrun/internal/builtin"
	"github.com/ninja-c9/mintrun/internal/core"
)

const scanUsage = "usage: mintrun scan, or mintrun scan -add <id> [-account <name>]"

// scanMaxBytes caps each file scan reads; a credentials file is a few KiB.
const scanMaxBytes = 1 << 20

// scanProviders is the row order: the order the macOS app's scan screen lists them in.
var scanProviders = []string{"github", "aws", "gcp", "cloudflare"}

var scanLabelRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)

// scanRow is one sign-in scan found, or one file it could not read. Nothing in it is a value from
// the file or derived from one (rule 38): Label is a name the user chose (an AWS profile) or a
// service account's client_email, and Temporary says a session token field is present. vals and
// raw, which hold secrets, are filled only for -add and never marshalled.
type scanRow struct {
	ID        string            `json:"id,omitempty"`
	Provider  string            `json:"provider"`
	Kind      string            `json:"kind,omitempty"` // key: mintrun can copy it; signin: a personal sign-in it cannot mint from
	Where     string            `json:"where"`
	Label     string            `json:"label,omitempty"`
	Temporary bool              `json:"temporary,omitempty"`
	Error     string            `json:"error,omitempty"`
	vals      map[string]string // an AWS profile's keys
	raw       string            // a GCP key file
}

// cmdScan lists the sign-ins gh, the AWS CLI, gcloud and wrangler keep on this machine as JSON rows,
// for the macOS app, by reading their files only: it runs no helper and opens no connection. -add
// copies one key row's secret into the vault through mintrun init's checks, and never the original.
func cmdScan(ctx context.Context, rt *core.Runtime, args []string) {
	fset := flag.NewFlagSet("scan", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	add := fset.String("add", "", "")
	account := fset.String("account", "", "")
	if err := fset.Parse(args); err != nil || fset.NArg() > 0 || *add == "" && *account != "" {
		fatal(scanUsage)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatal("cannot find the home directory")
	}
	rows := scanHome(home, runtime.GOOS, *add != "")
	if *add != "" {
		scanAdd(ctx, rt, rows, *add, *account)
		return
	}
	out, _ := marshalJSON(rows, "  ")
	fmt.Println(string(out))
	if slices.ContainsFunc(rows, func(r scanRow) bool { return r.Error != "" }) {
		exitFunc(1)
	}
}

// scanAdd stores the secret behind the key row id under <provider>[@<account>]. The id must be one
// scan found, so a caller never names a path, and a key the vault holds is never replaced.
func scanAdd(ctx context.Context, rt *core.Runtime, rows []scanRow, id, account string) {
	if rt.Relay != nil {
		fatal("a relay holds this machine's master secrets, so scan -add stores nothing here: store it on the relay server")
	}
	i := slices.IndexFunc(rows, func(r scanRow) bool { return r.ID == id })
	if i < 0 {
		fatal("unknown id %q: run mintrun scan to list them", id)
	}
	r := rows[i]
	if r.Kind != "key" {
		fatal("%s is a sign-in, not a key mintrun can copy: run mintrun init %s", id, r.Provider)
	}
	key, initCmd := r.Provider, "mintrun init "+r.Provider
	if account != "" {
		key, initCmd = key+"@"+account, initCmd+" -account "+account
	}
	if !core.ValidProvider(key) {
		fatal("account %q is not valid: a provider is %s", account, core.ProviderForm)
	}
	vault, err := rt.Registry.Vault(rt.DefaultVault)
	if err != nil {
		fatal("%v", err)
	}
	if kv, ok := vault.(*builtin.KeychainVault); ok && fileVaultOnly(kv) && os.Getenv("MINTRUN_VAULT_KEY") == "" {
		fatal("the encrypted file vault needs a passphrase: export MINTRUN_VAULT_KEY in this shell, then run mintrun scan -add again")
	}
	master, err := r.master()
	if err != nil {
		fatal("%s: %v", id, err)
	}
	// Only a miss lets the store go ahead: a lookup that failed (a wrong MINTRUN_VAULT_KEY) says
	// nothing about whether the key is held, and SetSecret would replace it.
	switch _, err := vault.GetSecret(ctx, key); {
	case err == nil:
		fatal("%s is already stored: add this one under another name with -account <name>, or replace it with %s", key, initCmd)
	case !errors.Is(err, builtin.ErrSecretNotFound):
		fatal("could not read vault %q to check whether %s is stored: %v", vault.Manifest().Name, key, err)
	}
	if err := vault.SetSecret(ctx, key, master); err != nil {
		fatal("store %s: %v", key, err)
	}
	out, _ := marshalJSON(map[string]string{"id": id, "key": key, "vault": vault.Manifest().Name}, "")
	fmt.Println(string(out))
}

// master checks a key row's secret the way mintrun init does (rule 35) and returns it as init stores it.
func (r scanRow) master() (string, error) {
	if r.Provider == "aws" {
		return awsMaster(r.vals["aws_access_key_id"], r.vals["aws_secret_access_key"], r.vals["aws_session_token"])
	}
	return r.raw, checkGCPKey(r.raw)
}

// scanHome finds the sign-ins under home as GOOS goos lays them out. A variable moves a tool's
// config only where the tool honours it, and an empty one counts as unset. Only -add sets values.
func scanHome(home, goos string, values bool) []scanRow {
	s := &scanner{home: home, values: values, rows: []scanRow{}}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	gh := filepath.Join(home, ".config", "gh")
	if xdg != "" {
		gh = filepath.Join(xdg, "gh")
	}
	s.github(filepath.Join(cmp.Or(os.Getenv("GH_CONFIG_DIR"), gh), "hosts.yml"))
	s.aws(cmp.Or(os.Getenv("AWS_CONFIG_FILE"), filepath.Join(home, ".aws", "config")),
		cmp.Or(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), filepath.Join(home, ".aws", "credentials")))
	s.gcp(cmp.Or(os.Getenv("CLOUDSDK_CONFIG"), filepath.Join(home, ".config", "gcloud")))
	s.wrangler(wranglerFiles(home, goos, xdg))
	slices.SortStableFunc(s.rows, func(a, b scanRow) int {
		return cmp.Or(cmp.Compare(slices.Index(scanProviders, a.Provider), slices.Index(scanProviders, b.Provider)),
			strings.Compare(a.ID, b.ID), strings.Compare(a.Where, b.Where))
	})
	return s.rows
}

// wranglerFiles lists where wrangler keeps its login, in the order it looks: the legacy ~/.wrangler,
// then its per-OS config folder.
func wranglerFiles(home, goos, xdg string) []string {
	dirs := []string{filepath.Join(home, ".wrangler")}
	switch goos {
	case "darwin":
		dirs = append(dirs, filepath.Join(home, "Library", "Preferences", ".wrangler"))
	case "linux":
		dirs = append(dirs, filepath.Join(cmp.Or(xdg, filepath.Join(home, ".config")), ".wrangler"))
	}
	for i, d := range dirs {
		dirs[i] = filepath.Join(d, "config", "default.toml")
	}
	return dirs
}

type scanner struct {
	home   string
	values bool
	rows   []scanRow
}

// add appends r, shown at p.
func (s *scanner) add(r scanRow, p string) {
	r.Where = p
	if rel, err := filepath.Rel(s.home, p); err == nil && filepath.IsLocal(rel) {
		r.Where = "~/" + filepath.ToSlash(rel)
	}
	s.rows = append(s.rows, r)
}

// read returns p's bytes, or false when p is missing or cannot be read, adding an error row shown at
// where for the latter. Only a missing p means none (rule 36). It follows a link only to a regular
// file, reads at most scanMaxBytes, and its errors are fixed texts, never an error that could quote
// a path or a byte.
func (s *scanner) read(provider, p, where string) ([]byte, bool) {
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	msg := "cannot read this file"
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if fi, err = os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			msg = "a link to a missing file"
		}
	}
	if err == nil && !fi.Mode().IsRegular() {
		err, msg = errors.New(""), "not a regular file"
	}
	var b []byte
	if err == nil {
		var f *os.File
		if f, err = os.Open(p); err == nil {
			b, err = io.ReadAll(io.LimitReader(f, scanMaxBytes+1))
			f.Close()
		}
	}
	if err == nil && len(b) > scanMaxBytes {
		err, msg = errors.New(""), "larger than 1 MiB"
	}
	if err != nil {
		s.add(scanRow{Provider: provider, Error: msg}, where)
		return nil, false
	}
	return b, true
}

// github finds gh's github.com sign-in by the top-level key of hosts.yml, never its token or user.
func (s *scanner) github(p string) {
	b, ok := s.read("github", p, p)
	if !ok {
		return
	}
	for line := range strings.Lines(string(b)) {
		if strings.TrimRight(line, " \t\r\n") == "github.com:" {
			s.add(scanRow{ID: "github:gh", Provider: "github", Kind: "signin"}, p)
			return
		}
	}
}

// aws finds each profile with an access key (key) or an SSO sign-in (signin) in the AWS CLI's
// config and credentials files, merged by profile; a role or process profile holds no key of its own.
func (s *scanner) aws(config, creds string) {
	type profile struct{ val, src map[string]string }
	profiles := map[string]*profile{}
	for _, f := range []struct {
		p      string
		config bool
	}{{config, true}, {creds, false}} { // credentials last: its values win, as in the AWS CLI
		b, ok := s.read("aws", f.p, f.p)
		if !ok {
			continue
		}
		sections, msg := parseAWSINI(b, f.config, s.values)
		if msg != "" {
			s.add(scanRow{Provider: "aws", Error: msg}, f.p)
			continue
		}
		for name, keys := range sections {
			pr := profiles[name]
			if pr == nil {
				pr = &profile{map[string]string{}, map[string]string{}}
				profiles[name] = pr
			}
			for k, v := range keys {
				pr.val[k], pr.src[k] = v, f.p
			}
		}
	}
	for name, pr := range profiles {
		r := scanRow{ID: "aws:" + name, Provider: "aws", Label: name}
		src := pr.src["aws_access_key_id"]
		switch {
		case src != "":
			r.Kind = "key"
			_, r.Temporary = pr.val["aws_session_token"]
		case cmp.Or(pr.src["sso_session"], pr.src["sso_start_url"]) != "":
			r.Kind, src = "signin", cmp.Or(pr.src["sso_session"], pr.src["sso_start_url"])
		default:
			continue
		}
		if !scanLabelRe.MatchString(name) {
			s.add(scanRow{Provider: "aws", Error: "a profile name is not letters, digits, . _ @ + or -"}, src)
			continue
		}
		if s.values {
			r.vals = pr.val
		}
		s.add(r, src)
	}
}

// parseAWSINI returns the keys of each profile in an AWS credentials file, or a config file's
// [default] and [profile <name>] sections, lowercased as the AWS CLI reads them. A value is kept only
// when values is set. Its error is a fixed text naming a line, never quoting one.
func parseAWSINI(b []byte, config, values bool) (map[string]map[string]string, string) {
	profiles := map[string]map[string]string{}
	var cur map[string]string
	inSection := false
	for n, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || t[0] == '#' || t[0] == ';':
		case t[0] == '[' && t[len(t)-1] == ']':
			name := strings.TrimSpace(t[1 : len(t)-1])
			if config {
				if rest, ok := strings.CutPrefix(name, "profile "); ok {
					name = strings.TrimSpace(rest)
				} else if name != "default" {
					name = "" // [sso-session …], [services …]: not a profile
				}
			}
			cur, inSection = nil, true
			if name != "" {
				if profiles[name] == nil {
					profiles[name] = map[string]string{}
				}
				cur = profiles[name]
			}
		case line[0] == ' ' || line[0] == '\t':
			// A nested setting (s3 =, then indented lines) or a continued value: not a profile key.
		default:
			i := strings.IndexAny(t, "=:")
			if !inSection || i <= 0 {
				return nil, fmt.Sprintf("line %d is not a [section] or key = value", n+1)
			}
			if cur != nil {
				v := ""
				if values {
					v = strings.TrimSpace(t[i+1:])
				}
				cur[strings.ToLower(strings.TrimSpace(t[:i]))] = v
			}
		}
	}
	return profiles, ""
}

type gcpCred struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	raw         string
}

// gcp finds gcloud's application default credentials and the logins gcloud keeps per account under
// legacy_credentials, whose folder names are accounts: a row from there is shown at that folder,
// and one row stands for every user login, so no user's address is printed.
func (s *scanner) gcp(dir string) {
	adc := filepath.Join(dir, "application_default_credentials.json")
	if c, ok := s.gcpFile(adc, adc); ok {
		s.gcpRow("gcp:adc", c, adc)
	}
	legacy := filepath.Join(dir, "legacy_credentials")
	ents, err := os.ReadDir(legacy)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.add(scanRow{Provider: "gcp", Error: "cannot list this folder"}, legacy)
	}
	ents = slices.DeleteFunc(ents, func(e fs.DirEntry) bool { return !e.IsDir() }) // .DS_Store
	login := false
	for _, e := range ents[:min(len(ents), 20)] {
		c, ok := s.gcpFile(filepath.Join(legacy, e.Name(), "adc.json"), legacy)
		switch {
		case !ok || c.Type == "authorized_user" && login:
		case c.Type == "authorized_user":
			login = true
			s.add(scanRow{ID: "gcp:gcloud-login", Provider: "gcp", Kind: "signin"}, legacy)
		default:
			s.gcpRow("gcp:gcloud:"+c.ClientEmail, c, legacy)
		}
	}
}

func (s *scanner) gcpFile(p, where string) (gcpCred, bool) {
	var c gcpCred
	b, ok := s.read("gcp", p, where)
	if !ok {
		return c, false
	}
	if json.Unmarshal(b, &c) != nil {
		s.add(scanRow{Provider: "gcp", Error: "not valid JSON"}, where)
		return c, false
	}
	if s.values {
		c.raw = string(b)
	}
	return c, true
}

// gcpRow adds a service account's key, or the sign-in of a user's ADC, and skips any other type.
func (s *scanner) gcpRow(id string, c gcpCred, where string) {
	switch {
	case c.Type == "authorized_user":
		s.add(scanRow{ID: id, Provider: "gcp", Kind: "signin"}, where)
	case c.Type != "service_account":
	case !scanLabelRe.MatchString(c.ClientEmail):
		s.add(scanRow{Provider: "gcp", Error: "client_email is not an address mintrun can show"}, where)
	default:
		s.add(scanRow{ID: id, Provider: "gcp", Kind: "key", Label: c.ClientEmail, raw: c.raw}, where)
	}
}

// wrangler finds wrangler's OAuth sign-in in the first config file that exists.
func (s *scanner) wrangler(files []string) {
	for _, p := range files {
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		b, _ := s.read("cloudflare", p, p)
		for line := range strings.Lines(string(b)) {
			if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "oauth_token" {
				s.add(scanRow{ID: "cloudflare:wrangler", Provider: "cloudflare", Kind: "signin"}, p)
				break
			}
		}
		return
	}
}
