package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ninja-c9/mintrun/internal/core"
)

// scanEnv is setupEnv with the tools' location variables cleared and a logging stub, first on
// PATH, for every tool whose files scan reads, plus security and sqlite3.
func scanEnv(t *testing.T) string {
	t.Helper()
	home, _ := setupEnv(t)
	for _, k := range []string{"GH_CONFIG_DIR", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "CLOUDSDK_CONFIG"} {
		t.Setenv(k, "")
	}
	for _, name := range []string{"gh", "aws", "gcloud", "wrangler", "security", "sqlite3"} {
		p := filepath.Join(home, "bin", name)
		writeFile(t, p, stubLog+"exit 0\n")
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// leakForm names the first form of leak that s holds: raw, base64 with or without padding, hex,
// or URL-escaped.
func leakForm(s string) string {
	b := []byte(leak)
	for _, f := range [][2]string{{"raw", leak}, {"base64", base64.StdEncoding.EncodeToString(b)},
		{"raw base64", base64.RawStdEncoding.EncodeToString(b)}, {"hex", hex.EncodeToString(b)},
		{"HEX", strings.ToUpper(hex.EncodeToString(b))}, {"URL", url.QueryEscape(leak)}} {
		if strings.Contains(s, f[1]) {
			return f[0]
		}
	}
	return ""
}

// runScan runs mintrun with args, checks it ran no tool and printed no form of leak, and returns
// its result.
func runScan(t *testing.T, home string, args ...string) cliResult {
	t.Helper()
	r := runCLI(t, "", nil, args...)
	if calls := takeCalls(t, home); calls != "" {
		t.Errorf("scan ran %q", calls)
	}
	if f := leakForm(r.out + r.err); f != "" {
		t.Errorf("output holds the %s canary:\n%s%s", f, r.out, r.err)
	}
	return r
}

// scanRows runs mintrun scan and checks its rows: an error row exits 1, and none exits normally.
func scanRows(t *testing.T, home string, want ...scanRow) {
	t.Helper()
	r := runScan(t, home, "scan")
	var got []scanRow
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatalf("stdout is not rows: %v\n%s%s", err, r.out, r.err)
	}
	if want == nil {
		want = []scanRow{} // printed as [], never null
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows:\ngot  %+v\nwant %+v", got, want)
	}
	bad := slices.ContainsFunc(want, func(r scanRow) bool { return r.Error != "" })
	if r.exited != bad || bad && r.code != 1 {
		t.Errorf("exited %v with %d, want an exit only for an error row", r.exited, r.code)
	}
}

func TestScanEmptyHome(t *testing.T) {
	home := scanEnv(t)
	r := runScan(t, home, "scan")
	if strings.TrimSpace(r.out) != "[]" || r.err != "" || r.exited {
		t.Errorf("got %q %q exited %v, want [] and no exit", r.out, r.err, r.exited)
	}

	// Positive controls: a stub run is logged, and each form of leak is caught.
	if err := exec.Command(filepath.Join(home, "bin", "gh"), "auth", "token").Run(); err != nil {
		t.Fatal(err)
	}
	if calls := takeCalls(t, home); calls != "gh auth token\n" {
		t.Errorf("stub log = %q", calls)
	}
	b := []byte(leak)
	for _, s := range []string{leak, base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)), url.QueryEscape("/" + leak)} {
		if leakForm("x"+s+"y") == "" {
			t.Errorf("leakForm misses %q", s)
		}
	}
}

func TestScanFindsEachSource(t *testing.T) {
	home := scanEnv(t)
	writeFile(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: gho_"+leak+"\n    user: octo-user\n")
	writeFile(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = AKIA"+leak+"\naws_secret_access_key = "+leak+"\n")
	writeFile(t, filepath.Join(home, ".aws", "config"), "[profile corp]\nsso_session = corp\n")
	writeJSON(t, filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"),
		obj{"type": "service_account", "client_email": "ci@proj.iam.gserviceaccount.com", "private_key": leak})
	writeFile(t, filepath.Join(home, ".wrangler", "config", "default.toml"), "oauth_token = \""+leak+"\"\nrefresh_token = \""+leak+"\"\n")
	scanRows(t, home,
		scanRow{ID: "github:gh", Provider: "github", Kind: "signin", Where: "~/.config/gh/hosts.yml"},
		scanRow{ID: "aws:corp", Provider: "aws", Kind: "signin", Where: "~/.aws/config", Label: "corp"},
		scanRow{ID: "aws:default", Provider: "aws", Kind: "key", Where: "~/.aws/credentials", Label: "default"},
		scanRow{ID: "gcp:adc", Provider: "gcp", Kind: "key", Where: "~/.config/gcloud/application_default_credentials.json", Label: "ci@proj.iam.gserviceaccount.com"},
		scanRow{ID: "cloudflare:wrangler", Provider: "cloudflare", Kind: "signin", Where: "~/.wrangler/config/default.toml"},
	)
	if r := runScan(t, home, "scan"); strings.Contains(r.out, "octo-user") {
		t.Errorf("scan printed the gh user:\n%s", r.out)
	}

	// Only -add reads values; the positive control shows the fields hold them when it does.
	for _, values := range []bool{false, true} {
		for _, r := range scanHome(home, runtime.GOOS, values) {
			held := strings.Contains(fmt.Sprint(r.vals)+r.raw, leak)
			if want := values && r.Kind == "key"; held != want {
				t.Errorf("values=%v: %s holds values %v, want %v", values, r.ID, held, want)
			}
		}
	}
}

// scanSources is one file per source: good gives row, and bad, where the source parses, puts leak
// where a value or key should be and gives badErr.
var scanSources = []struct {
	rel, good   string
	row         scanRow
	bad, badErr string
}{
	{".config/gh/hosts.yml", "github.com:\n    oauth_token: " + leak + "\n",
		scanRow{ID: "github:gh", Provider: "github", Kind: "signin"}, "", ""},
	{".aws/credentials", "[default]\naws_access_key_id = " + leak + "\n",
		scanRow{ID: "aws:default", Provider: "aws", Kind: "key", Label: "default"},
		"[default]\n" + leak + "\n", "line 2 is not a [section] or key = value"},
	{".aws/config", "[default]\nsso_start_url = " + leak + "\n",
		scanRow{ID: "aws:default", Provider: "aws", Kind: "signin", Label: "default"},
		leak + " = 1\n", "line 1 is not a [section] or key = value"},
	{".config/gcloud/application_default_credentials.json", `{"type": "authorized_user", "refresh_token": "` + leak + `"}`,
		scanRow{ID: "gcp:adc", Provider: "gcp", Kind: "signin"},
		`{"type": "authorized_user", "refresh_token": ` + leak + `}`, "not valid JSON"},
	{".wrangler/config/default.toml", "oauth_token = \"" + leak + "\"\n",
		scanRow{ID: "cloudflare:wrangler", Provider: "cloudflare", Kind: "signin"}, "", ""},
}

// scanErr is the error row for the file at rel.
func scanErr(provider, rel, msg string) scanRow {
	return scanRow{Provider: provider, Where: "~/" + rel, Error: msg}
}

func TestScanFileErrors(t *testing.T) {
	for _, src := range scanSources {
		good := src.row
		good.Where = "~/" + src.rel
		atMax := src.good + "\n" + strings.Repeat(" ", scanMaxBytes-len(src.good)-1)
		cases := []struct {
			name  string
			setup func(t *testing.T, p string)
			want  scanRow
		}{
			{"file", func(t *testing.T, p string) { writeFile(t, p, src.good) }, good},
			{"link to a file", func(t *testing.T, p string) {
				target := filepath.Join(filepath.Dir(p), "stored")
				writeFile(t, target, src.good)
				symlink(t, target, p)
			}, good},
			{"dangling link", func(t *testing.T, p string) { symlink(t, filepath.Join(filepath.Dir(p), "gone"), p) },
				scanErr(src.row.Provider, src.rel, "a link to a missing file")},
			{"directory", func(t *testing.T, p string) { mkdir(t, p) },
				scanErr(src.row.Provider, src.rel, "not a regular file")},
			{"1 MiB", func(t *testing.T, p string) { writeFile(t, p, atMax) }, good},
			{"over 1 MiB", func(t *testing.T, p string) { writeFile(t, p, atMax[:len(atMax)-len(leak)]+leak+" ") },
				scanErr(src.row.Provider, src.rel, "larger than 1 MiB")},
			{"unreadable", func(t *testing.T, p string) {
				if os.Geteuid() == 0 {
					t.Skip("root reads a mode-000 file")
				}
				writeFile(t, p, src.good)
				if err := os.Chmod(p, 0); err != nil {
					t.Fatal(err)
				}
			}, scanErr(src.row.Provider, src.rel, "cannot read this file")},
		}
		if src.bad != "" {
			cases = append(cases, struct {
				name  string
				setup func(t *testing.T, p string)
				want  scanRow
			}{"malformed", func(t *testing.T, p string) { writeFile(t, p, src.bad) }, scanErr(src.row.Provider, src.rel, src.badErr)})
		}
		for _, tc := range cases {
			t.Run(src.rel+"/"+tc.name, func(t *testing.T) {
				home := scanEnv(t)
				tc.setup(t, filepath.Join(home, src.rel))
				scanRows(t, home, tc.want)
			})
		}
	}
}

func symlink(t *testing.T, target, p string) {
	t.Helper()
	mkdir(t, filepath.Dir(p))
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestScanAWS(t *testing.T) {
	key := "aws_access_key_id = AKIA" + leak + "\naws_secret_access_key = " + leak + "\n"
	creds, config := ".aws/credentials", ".aws/config"
	row := func(id, kind, where string) scanRow {
		return scanRow{ID: "aws:" + id, Provider: "aws", Kind: kind, Where: "~/" + where, Label: id}
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		env   map[string]string // a variable and the path under home it names
		want  []scanRow
	}{
		{"credentials win the merge", map[string]string{
			config: "[default]\nregion = us-east-1\n[profile both]\n" + key + "[profile work]\nregion = eu-west-1\n",
			creds:  "[work]\n" + key + "[both]\n" + key,
		}, nil, []scanRow{row("both", "key", creds), row("work", "key", creds)}},
		{"a config key", map[string]string{config: "[profile solo]\n" + key}, nil, []scanRow{row("solo", "key", config)}},
		{"sso", map[string]string{
			config: "[profile a]\nsso_session = corp\n[profile b]\nsso_start_url = https://corp.awsapps.com/start\n[sso-session corp]\nsso_start_url = https://corp.awsapps.com/start\n",
		}, nil, []scanRow{row("a", "signin", config), row("b", "signin", config)}},
		{"no key of its own", map[string]string{
			config: "[profile r]\nrole_arn = arn:aws:iam::123456789012:role/x\nsource_profile = default\n[profile p]\ncredential_process = /opt/bin/creds\n[profile w]\nweb_identity_token_file = /var/token\n",
		}, nil, nil},
		{"temporary", map[string]string{creds: "[t]\n" + key + "aws_session_token = " + leak + "\n"}, nil,
			[]scanRow{{ID: "aws:t", Provider: "aws", Kind: "key", Where: "~/" + creds, Label: "t", Temporary: true}}},
		{"bad name", map[string]string{creds: "[my profile!]\n" + key}, nil,
			[]scanRow{scanErr("aws", creds, "a profile name is not letters, digits, . _ @ + or -")}},
		{"comments, case, and nesting", map[string]string{
			config: "# note\n; note\n[profile n]\nAWS_ACCESS_KEY_ID = AKIA" + leak + "\naws_secret_access_key: " + leak +
				"\ns3 =\n  max_concurrent_requests = 10\n[services s]\ndynamodb =\n  endpoint_url = http://localhost:8000\n" +
				"[profile nest]\nregion = eu-west-1\ns3 =\n  aws_access_key_id = AKIA" + leak + "\n\t" + leak + "\n",
		}, nil, []scanRow{row("n", "key", config)}},
		{"variables", map[string]string{
			creds: "[decoy]\n" + key, config: "[profile decoy2]\n" + key,
			"alt/creds": "[moved]\n" + key, "alt/config": "[profile sso]\nsso_session = corp\n",
		}, map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "alt/creds", "AWS_CONFIG_FILE": "alt/config"},
			[]scanRow{row("moved", "key", "alt/creds"), row("sso", "signin", "alt/config")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := scanEnv(t)
			for rel, s := range tc.files {
				writeFile(t, filepath.Join(home, rel), s)
			}
			for k, rel := range tc.env {
				t.Setenv(k, filepath.Join(home, rel))
			}
			scanRows(t, home, tc.want...)
			if r := runScan(t, home, "scan"); strings.Contains(r.out, "my profile") {
				t.Errorf("scan printed a refused profile name:\n%s", r.out)
			}
		})
	}

	t.Run("outside home", func(t *testing.T) {
		home := scanEnv(t)
		p := filepath.Join(t.TempDir(), "credentials")
		writeFile(t, p, "[ci]\n"+key)
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", p)
		scanRows(t, home, scanRow{ID: "aws:ci", Provider: "aws", Kind: "key", Where: p, Label: "ci"})
	})
}

func TestScanGCP(t *testing.T) {
	sa := func(email string) obj {
		return obj{"type": "service_account", "client_email": email, "private_key": leak}
	}
	user := obj{"type": "authorized_user", "client_id": "x.apps.googleusercontent.com", "refresh_token": leak}
	adc := ".config/gcloud/application_default_credentials.json"
	legacy := ".config/gcloud/legacy_credentials"

	t.Run("types and legacy logins", func(t *testing.T) {
		home := scanEnv(t)
		writeJSON(t, filepath.Join(home, adc), user)
		dir := filepath.Join(home, legacy)
		writeJSON(t, filepath.Join(dir, "ci@p.iam.gserviceaccount.com", "adc.json"), sa("ci@p.iam.gserviceaccount.com"))
		writeJSON(t, filepath.Join(dir, "ana@example.com", "adc.json"), user)
		writeJSON(t, filepath.Join(dir, "bao@example.com", "adc.json"), user)
		writeJSON(t, filepath.Join(dir, "pool@p", "adc.json"), obj{"type": "external_account"})
		mkdir(t, filepath.Join(dir, "empty"))
		writeFile(t, filepath.Join(dir, ".DS_Store"), leak)
		scanRows(t, home,
			scanRow{ID: "gcp:adc", Provider: "gcp", Kind: "signin", Where: "~/" + adc},
			scanRow{ID: "gcp:gcloud-login", Provider: "gcp", Kind: "signin", Where: "~/" + legacy},
			scanRow{ID: "gcp:gcloud:ci@p.iam.gserviceaccount.com", Provider: "gcp", Kind: "key", Where: "~/" + legacy, Label: "ci@p.iam.gserviceaccount.com"},
		)
		if r := runScan(t, home, "scan"); strings.Contains(r.out, "example.com") {
			t.Errorf("scan printed a user's address:\n%s", r.out)
		}
	})

	t.Run("at most 20 legacy folders, in name order", func(t *testing.T) {
		home := scanEnv(t)
		var want []scanRow
		for i := range 25 {
			email := fmt.Sprintf("sa%02d@p.iam.gserviceaccount.com", i)
			writeJSON(t, filepath.Join(home, legacy, email, "adc.json"), sa(email))
			if i < 20 {
				want = append(want, scanRow{ID: "gcp:gcloud:" + email, Provider: "gcp", Kind: "key", Where: "~/" + legacy, Label: email})
			}
		}
		scanRows(t, home, want...)
	})

	t.Run("variable", func(t *testing.T) {
		home := scanEnv(t)
		writeJSON(t, filepath.Join(home, adc), sa("decoy@p.iam.gserviceaccount.com"))
		writeJSON(t, filepath.Join(home, "alt", "application_default_credentials.json"), sa("ci@p.iam.gserviceaccount.com"))
		t.Setenv("CLOUDSDK_CONFIG", filepath.Join(home, "alt"))
		scanRows(t, home, scanRow{ID: "gcp:adc", Provider: "gcp", Kind: "key",
			Where: "~/alt/application_default_credentials.json", Label: "ci@p.iam.gserviceaccount.com"})
	})

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, home string)
		want  scanRow
	}{
		{"an address it cannot show", func(t *testing.T, home string) { writeJSON(t, filepath.Join(home, adc), sa(leak+" <x@y>")) },
			scanErr("gcp", adc, "client_email is not an address mintrun can show")},
		{"legacy folder is a file", func(t *testing.T, home string) { writeFile(t, filepath.Join(home, legacy), leak) },
			scanErr("gcp", legacy, "cannot list this folder")},
		{"legacy file malformed", func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, legacy, "ana@example.com", "adc.json"), "{"+leak)
		}, scanErr("gcp", legacy, "not valid JSON")},
		{"legacy file is a folder", func(t *testing.T, home string) { mkdir(t, filepath.Join(home, legacy, "ana@example.com", "adc.json")) },
			scanErr("gcp", legacy, "not a regular file")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := scanEnv(t)
			tc.setup(t, home)
			scanRows(t, home, tc.want)
		})
	}
}

func TestScanGitHub(t *testing.T) {
	signin := func(where string) scanRow {
		return scanRow{ID: "github:gh", Provider: "github", Kind: "signin", Where: "~/" + where}
	}
	t.Run("GH_CONFIG_DIR, then XDG_CONFIG_HOME, then ~/.config", func(t *testing.T) {
		home := scanEnv(t)
		for _, d := range []string{"ghdir", "xdg/gh", ".config/gh"} {
			writeFile(t, filepath.Join(home, d, "hosts.yml"), "github.com:\n    user: x\n")
		}
		t.Setenv("GH_CONFIG_DIR", filepath.Join(home, "ghdir"))
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
		scanRows(t, home, signin("ghdir/hosts.yml"))
		t.Setenv("GH_CONFIG_DIR", "")
		scanRows(t, home, signin("xdg/gh/hosts.yml"))
		t.Setenv("XDG_CONFIG_HOME", "")
		scanRows(t, home, signin(".config/gh/hosts.yml"))
	})
	t.Run("GitHub Enterprise only", func(t *testing.T) {
		home := scanEnv(t)
		writeFile(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "ghe.corp.example:\n    github.com:\n    oauth_token: "+leak+"\n")
		scanRows(t, home)
	})
	t.Run("CRLF and trailing spaces", func(t *testing.T) {
		home := scanEnv(t)
		writeFile(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "ghe.corp.example:\r\n    user: x\r\ngithub.com:  \r\n")
		scanRows(t, home, signin(".config/gh/hosts.yml"))
	})
}

func TestScanWrangler(t *testing.T) {
	home := filepath.Join(string(filepath.Separator)+"h", "u")
	legacy := filepath.Join(home, ".wrangler", "config", "default.toml")
	for _, tc := range []struct {
		goos, xdg string
		want      []string
	}{
		{"darwin", "", []string{legacy, filepath.Join(home, "Library", "Preferences", ".wrangler", "config", "default.toml")}},
		{"linux", "", []string{legacy, filepath.Join(home, ".config", ".wrangler", "config", "default.toml")}},
		{"linux", filepath.Join(home, "xdg"), []string{legacy, filepath.Join(home, "xdg", ".wrangler", "config", "default.toml")}},
		{"windows", "", []string{legacy}},
	} {
		if got := wranglerFiles(home, tc.goos, tc.xdg); !slices.Equal(got, tc.want) {
			t.Errorf("wranglerFiles(%s, %q) = %q, want %q", tc.goos, tc.xdg, got, tc.want)
		}
	}

	signin := func(where string) []scanRow {
		return []scanRow{{ID: "cloudflare:wrangler", Provider: "cloudflare", Kind: "signin", Where: "~/" + where}}
	}
	darwinFile := "Library/Preferences/.wrangler/config/default.toml"
	t.Run("macOS folder", func(t *testing.T) {
		home := scanEnv(t)
		writeFile(t, filepath.Join(home, darwinFile), "oauth_token = \""+leak+"\"\n")
		if got := scanHome(home, "darwin", false); !reflect.DeepEqual(got, signin(darwinFile)) {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("the legacy file wins, even logged out", func(t *testing.T) {
		home := scanEnv(t)
		writeFile(t, filepath.Join(home, darwinFile), "oauth_token = \""+leak+"\"\n")
		writeFile(t, filepath.Join(home, ".wrangler", "config", "default.toml"), "# logged out\n")
		if got := scanHome(home, "darwin", false); len(got) != 0 {
			t.Errorf("got %+v, want no row", got)
		}
	})
	t.Run("linux folder", func(t *testing.T) {
		home := scanEnv(t)
		writeFile(t, filepath.Join(home, ".config", ".wrangler", "config", "default.toml"), "oauth_token=\""+leak+"\"\n")
		if got := scanHome(home, "linux", false); !reflect.DeepEqual(got, signin(".config/.wrangler/config/default.toml")) {
			t.Errorf("got %+v", got)
		}
	})
}

func TestScanUsage(t *testing.T) {
	home := scanEnv(t)
	for _, args := range [][]string{{"extra"}, {"-account", "work"}, {"-bogus"}, {"-add"}} {
		r := runScan(t, home, append([]string{"scan"}, args...)...)
		if r.out != "" || strings.TrimSpace(r.err) != scanUsage || r.code != 1 {
			t.Errorf("scan %q: got %q %q exit %d, want the usage", args, r.out, r.err, r.code)
		}
	}
}

// TestScanImports pins that scan only reads files: it cannot run a helper or open a connection.
func TestScanImports(t *testing.T) {
	banned := func(file string) []string {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		var bad []string
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "os/exec" || p == "net" || strings.HasPrefix(p, "net/") {
				bad = append(bad, p)
			}
		}
		return bad
	}
	if bad := banned("scan.go"); len(bad) > 0 {
		t.Errorf("scan.go imports %q", bad)
	}
	// Positive control: setup.go runs helpers and builds URLs.
	if bad := banned("setup.go"); !slices.Contains(bad, "os/exec") || !slices.Contains(bad, "net/url") {
		t.Errorf("setup.go: got %q, want os/exec and net/url", bad)
	}
}

// fileState is p's SHA-256 and modification time, to show -add leaves the original alone.
func fileState(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x %d", sha256.Sum256(b), fi.ModTime().UnixNano())
}

// scanAdded checks that scan -add printed its one row and stored master under key, leaving the
// file at p as it was.
func scanAdded(t *testing.T, home, p, key, master string, args ...string) {
	t.Helper()
	before := fileState(t, p)
	r := runScan(t, home, append([]string{"scan"}, args...)...)
	want := fmt.Sprintf(`{"id":%q,"key":%q,"vault":"keychain"}`+"\n", args[1], key)
	if r.out != want || r.err != "" || r.exited {
		t.Errorf("got %q %q exited %v, want %q", r.out, r.err, r.exited, want)
	}
	if got := getSecret(t, key); got != master {
		t.Errorf("stored %q under %s, want %q", got, key, master)
	}
	if fileState(t, p) != before {
		t.Errorf("scan -add changed %s", p)
	}
}

func TestScanAddAWS(t *testing.T) {
	id, tempID, secret, token := "AKIA"+leak+"000000", "ASIA"+leak+"000000", leak+strings.Repeat("s", 30), leak+"/+="
	creds := "[work]\naws_access_key_id = " + id + "\naws_secret_access_key = " + secret + "\n" +
		"[temp]\naws_access_key_id = " + tempID + "\naws_secret_access_key = " + secret + "\naws_session_token = " + token + "\n"
	for _, tc := range []struct {
		args        []string
		key, master string
	}{
		{[]string{"-add", "aws:work"}, "aws", id + ":" + secret},
		{[]string{"-add", "aws:work", "-account", "ci"}, "aws@ci", id + ":" + secret},
		{[]string{"-add", "aws:temp"}, "aws", tempID + ":" + secret + ":" + token},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			home := scanEnv(t)
			p := filepath.Join(home, ".aws", "credentials")
			writeFile(t, p, creds)
			scanAdded(t, home, p, tc.key, tc.master, tc.args...)
		})
	}
}

func TestScanAddGCP(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// Encoded at run time, so no private key block sits in this file.
	pk, err := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	file := `{"type": "service_account", "client_email": "ci@p.iam.gserviceaccount.com", "private_key_id": "` + leak + `", "private_key": ` + string(pk) + "}\n"
	t.Run("adc", func(t *testing.T) {
		home := scanEnv(t)
		p := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		writeFile(t, p, file)
		scanAdded(t, home, p, "gcp", strings.TrimSpace(file), "-add", "gcp:adc") // the vault trims, as for init
	})
	t.Run("legacy, under an account", func(t *testing.T) {
		home := scanEnv(t)
		p := filepath.Join(home, ".config", "gcloud", "legacy_credentials", "ci@p.iam.gserviceaccount.com", "adc.json")
		writeFile(t, p, file)
		scanAdded(t, home, p, "gcp@legacy", strings.TrimSpace(file), "-add", "gcp:gcloud:ci@p.iam.gserviceaccount.com", "-account", "legacy")
	})
}

// TestScanAddRefusals pins each refusal: it exits 1 with one message, quotes no value, and leaves
// the vault as it was.
func TestScanAddRefusals(t *testing.T) {
	secret := leak + strings.Repeat("s", 30)
	creds := "[work]\naws_access_key_id = AKIA" + leak + "000000\naws_secret_access_key = " + secret + "\n" +
		"[short]\naws_access_key_id = AKIA" + leak + "000000\naws_secret_access_key = " + secret[1:] + "\n" +
		"[temp]\naws_access_key_id = ASIA" + leak + "000000\naws_secret_access_key = " + secret + "\n"
	for _, tc := range []struct {
		name       string
		setup      func(t *testing.T)
		args       []string
		key, prior string // the key -add would store under, and what it holds before
		want       string
	}{
		{"a sign-in", nil, []string{"-add", "github:gh"}, "github", "",
			"github:gh is a sign-in, not a key mintrun can copy: run mintrun init github"},
		{"an unknown id", nil, []string{"-add", "aws:nope"}, "aws", "", `unknown id "aws:nope": run mintrun scan to list them`},
		{"a bad account", nil, []string{"-add", "aws:work", "-account", "Work!"}, "aws", "",
			`account "Work!" is not valid: a provider is ` + core.ProviderForm},
		{"a short secret", nil, []string{"-add", "aws:short"}, "aws", "", "aws:short: a secret access key is 40 letters, digits, / or +"},
		{"a temporary key without a token", nil, []string{"-add", "aws:temp"}, "aws", "", "aws:temp: a session token is letters, digits, /, + or ="},
		{"a GCP file without a key", nil, []string{"-add", "gcp:adc"}, "gcp", "",
			"gcp:adc: not a service-account key file: it needs client_email and private_key"},
		{"a stored key", func(t *testing.T) { setSecret(t, "aws", "old") }, []string{"-add", "aws:work"}, "aws", "old",
			"aws is already stored: add this one under another name with -account <name>, or replace it with mintrun init aws"},
		{"a stored account", func(t *testing.T) { setSecret(t, "aws@ci", "old") }, []string{"-add", "aws:work", "-account", "ci"}, "aws@ci", "old",
			"aws@ci is already stored: add this one under another name with -account <name>, or replace it with mintrun init aws -account ci"},
		{"a relay", func(t *testing.T) { t.Setenv("MINTRUN_RELAY", "https://relay.invalid#sha256="+strings.Repeat("0", 64)) },
			[]string{"-add", "aws:work"}, "aws", "",
			"a relay holds this machine's master secrets, so scan -add stores nothing here: store it on the relay server"},
		{"a vault it cannot read", func(t *testing.T) { setSecret(t, "aws", "old"); t.Setenv("MINTRUN_VAULT_KEY", "wrong-"+leak) },
			[]string{"-add", "aws:work"}, "aws", "old",
			`could not read vault "keychain" to check whether aws is stored: decrypt vault (wrong MINTRUN_VAULT_KEY?): cipher: message authentication failed`},
		{"no passphrase", func(t *testing.T) { t.Setenv("MINTRUN_VAULT_KEY", "") }, []string{"-add", "aws:work"}, "aws", "",
			"the encrypted file vault needs a passphrase: export MINTRUN_VAULT_KEY in this shell, then run mintrun scan -add again"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := scanEnv(t)
			writeFile(t, filepath.Join(home, ".aws", "credentials"), creds)
			writeFile(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: "+leak+"\n")
			writeJSON(t, filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"),
				obj{"type": "service_account", "client_email": "ci@p.iam.gserviceaccount.com", "private_key_id": leak})
			if tc.setup != nil {
				tc.setup(t)
			}
			r := runScan(t, home, append([]string{"scan"}, tc.args...)...)
			if r.out != "" || r.err != tc.want+"\n" || r.code != 1 {
				t.Errorf("got %q %q exit %d, want %q", r.out, r.err, r.code, tc.want)
			}
			t.Setenv("MINTRUN_VAULT_KEY", "vault-"+leak)
			t.Setenv("MINTRUN_RELAY", "")
			if got := getSecret(t, tc.key); got != tc.prior {
				t.Errorf("%s holds %q, want %q", tc.key, got, tc.prior)
			}
		})
	}
}
