package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ninja-c9/mintrun/internal/core"
)

// stubBW stands in for the Bitwarden CLI: it keeps items in bw.json and logs its argv to bw.log.
const stubBW = `#!/usr/bin/env python3
import base64, json, os, sys, uuid
here = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
with open(os.path.join(here, "bw.log"), "a") as f:
    f.write(json.dumps(args) + "\n")
if args[:1] != ["--nointeraction"] or not os.environ.get("BW_SESSION"):
    sys.exit("stub bw: needs --nointeraction and BW_SESSION")
args, stdin = args[1:], sys.stdin.read()
db_path = os.path.join(here, "bw.json")
db = json.load(open(db_path)) if os.path.exists(db_path) else []
if os.environ.get("BW_STUB_FAIL") == args[0]:
    # A real bw can echo what it was given, so the plugin must scrub all of it.
    notes = json.loads(base64.b64decode(stdin))["notes"]
    sys.exit("notes=%s session=%s stdin=%s" % (notes, os.environ["BW_SESSION"], stdin))
if args[:3] == ["list", "items", "--search"]:
    print(json.dumps([i for i in db if args[3] in i["name"]]))
elif args[:2] == ["create", "item"]:
    item = dict(json.loads(base64.b64decode(stdin)), id=str(uuid.uuid4()))
    db.append(item)
    print(json.dumps(item))
elif args[:2] == ["edit", "item"]:
    item = dict(json.loads(base64.b64decode(stdin)), id=args[2])
    db = [item if i["id"] == args[2] else i for i in db]
    print(json.dumps(item))
elif args[:2] == ["delete", "item"]:
    for i in db:
        if i["id"] == args[2]:
            i["deletedDate"] = "2026-01-01T00:00:00.000Z"
else:
    sys.exit("stub bw: unexpected command")
with open(db_path, "w") as f:
    json.dump(db, f)
`

// stubPSQL stands in for psql: it logs its argv, PGPASSWORD, and the SQL on stdin to psql.log.
const stubPSQL = `#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
sql = sys.stdin.read()
with open(os.path.join(here, "psql.log"), "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "pgpassword": os.environ.get("PGPASSWORD"), "sql": sql}) + "\n")
if os.environ.get("PSQL_STUB_FAIL"):
    # A real error can quote the statement, so the plugin must scrub the verifier and the password.
    sys.exit("ERROR: %s password=%s" % (sql, os.environ.get("PGPASSWORD")))
`

// TestExamplePlugins installs each plugin under examples/plugins the way a user would after a clone,
// then drives it through the runtime against stand-ins: no Bitwarden account, Vercel API, or database.
func TestExamplePlugins(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("the example plugins need python3")
	}
	t.Setenv("MINTRUN_HOME", t.TempDir())
	t.Setenv("MINTRUN_FILE_VAULT", "1")
	t.Setenv("MINTRUN_VAULT", "keychain")
	const session = "bw-test-session-7f3a9c"
	t.Setenv("BW_SESSION", session)
	bin := t.TempDir()
	for name, src := range map[string]string{"bw": stubBW, "psql": stubPSQL} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(src), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, name := range []string{"bitwarden", "vercel", "postgres-jit"} {
		if code, exited := runMainWithArgs(t, "", "plugin", "install", filepath.Join("..", "..", "examples", "plugins", name)); exited {
			t.Fatalf("plugin install %s exited %d", name, code)
		}
	}
	rt, err := bootRuntime()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	readLog := func(name string) []string {
		b, _ := os.ReadFile(filepath.Join(bin, name))
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}

	t.Run("bitwarden", func(t *testing.T) {
		bwv, err := rt.Registry.Vault("bitwarden")
		if err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(bin, "bw.json")
		readDB := func() (db []map[string]any) {
			b, err := os.ReadFile(dbPath)
			if err == nil {
				err = json.Unmarshal(b, &db)
			}
			if err != nil {
				t.Fatal(err)
			}
			return db
		}
		writeDB := func(db []map[string]any) {
			b, _ := json.Marshal(db)
			if err := os.WriteFile(dbPath, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// The search also returns these, and none may be read or edited: an organization's note,
		// one in the trash, a login rather than a secure note, and a longer name.
		writeDB([]map[string]any{
			{"id": "11111111-1111-4111-8111-111111111111", "type": 2, "name": "mintrun/vercel", "notes": "ORG-PLANTED", "organizationId": "org-1"},
			{"id": "22222222-2222-4222-8222-222222222222", "type": 2, "name": "mintrun/vercel", "notes": "TRASHED", "organizationId": nil, "deletedDate": "2026-01-01T00:00:00.000Z"},
			{"id": "33333333-3333-4333-8333-333333333333", "type": 1, "name": "mintrun/vercel", "notes": "LOGIN", "organizationId": nil},
			{"id": "44444444-4444-4444-8444-444444444444", "type": 2, "name": "mintrun/vercel-old", "notes": "OLD", "organizationId": nil},
		})

		t.Setenv("BW_SESSION", "")
		if _, err := bwv.GetSecret(ctx, "vercel"); err == nil || !strings.Contains(err.Error(), "bw unlock --raw") {
			t.Fatalf("locked: got %v, want the unlock hint", err)
		}
		t.Setenv("BW_SESSION", session)
		if _, err := bwv.GetSecret(ctx, "vercel"); err == nil || !strings.Contains(err.Error(), "no Bitwarden secure note named mintrun/vercel") {
			t.Fatalf("only decoys: got %v, want a miss", err)
		}

		const v1, v2, v3 = "first-secret-value-1", "second-secret\nline two", "third-secret-value-3"
		if err := bwv.SetSecret(ctx, "vercel", v1); err != nil {
			t.Fatal(err)
		}
		db := readDB()
		if len(db) != 5 || db[4]["name"] != "mintrun/vercel" || db[4]["type"] != 2.0 || db[4]["notes"] != v1 || db[4]["organizationId"] != nil {
			t.Fatalf("first set: store %v, want one new personal secure note", db)
		}
		id := db[4]["id"]
		if err := bwv.SetSecret(ctx, "vercel", v2); err != nil {
			t.Fatal(err)
		}
		if db = readDB(); len(db) != 5 || db[4]["id"] != id || db[4]["notes"] != v2 || db[0]["notes"] != "ORG-PLANTED" {
			t.Fatalf("second set: store %v, want the same note edited and the decoys untouched", db)
		}
		if got, err := bwv.GetSecret(ctx, "vercel"); err != nil || got != v2 {
			t.Fatalf("get: %q, %v", got, err)
		}

		t.Setenv("BW_STUB_FAIL", "edit")
		r := core.RedactedPlaceholder
		if err := bwv.SetSecret(ctx, "vercel", v3); err == nil || !strings.Contains(err.Error(), "bw edit failed: notes="+r+" session="+r+" stdin="+r) {
			t.Fatalf("failed edit: got %v, want the secret, session, and payload scrubbed", err)
		}
		t.Setenv("BW_STUB_FAIL", "")
		if got, err := bwv.GetSecret(ctx, "vercel"); err != nil || got != v2 {
			t.Fatalf("after a failed edit: %q, %v, want the old secret", got, err)
		}

		writeDB(append(slices.Clone(db), maps.Clone(db[4])))
		if _, err := bwv.GetSecret(ctx, "vercel"); err == nil || !strings.Contains(err.Error(), "2 Bitwarden secure notes are named mintrun/vercel") {
			t.Fatalf("duplicate: got %v, want an error, never a guess", err)
		}
		writeDB(db)

		if err := bwv.DeleteSecret(ctx, "vercel"); err != nil {
			t.Fatal(err)
		}
		if _, err := bwv.GetSecret(ctx, "vercel"); err == nil || !strings.Contains(err.Error(), "no Bitwarden secure note") || readDB()[4]["deletedDate"] == nil {
			t.Fatalf("after delete: got %v, want a miss and the note in the trash", err)
		}

		// 13 calls in all, and the secrets and session travel on stdin and in the environment only.
		calls := readLog("bw.log")
		for _, c := range calls {
			if !strings.HasPrefix(c, `["--nointeraction", `) || strings.Contains(c, session) || slices.ContainsFunc([]string{v1, "second-secret", v3}, func(s string) bool { return strings.Contains(c, s) }) {
				t.Errorf("bw argv %s", c)
			}
		}
		if len(calls) != 13 {
			t.Errorf("bw ran %d times, want 13: %q", len(calls), calls)
		}
	})

	t.Run("vercel", func(t *testing.T) {
		const master, minted = "vercel-master-token-abc123", "vcp_minted_secret_123"
		bwv, err := rt.Registry.Vault("bitwarden")
		if err != nil {
			t.Fatal(err)
		}
		if err := bwv.SetSecret(ctx, "vercel", master); err != nil {
			t.Fatal(err)
		}
		var (
			mu    sync.Mutex
			calls []string
			body  struct {
				Name      string  `json:"name"`
				ExpiresAt float64 `json:"expiresAt"`
				ProjectID string  `json:"projectId"`
			}
		)
		// A redirect is never followed: urllib would carry the Authorization header to wherever it points.
		elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("redirect followed: %s %s", r.Method, r.URL)
		}))
		defer elsewhere.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			if auth := r.Header.Get("Authorization"); auth != "Bearer "+master {
				w.WriteHeader(http.StatusForbidden) // and echoes what it was sent, as a careless API might
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": "invalid token " + auth}})
				return
			}
			switch r.Method + " " + r.URL.Path {
			case "POST /v3/user/tokens":
				if r.URL.Query().Get("teamId") == "team_redirect" {
					http.Redirect(w, r, elsewhere.URL+"/v3/user/tokens", http.StatusFound)
					return
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				_ = json.NewEncoder(w).Encode(map[string]any{"token": map[string]string{"id": "tok_1"}, "bearerToken": minted})
			case "DELETE /v3/user/tokens/tok_1":
				_ = json.NewEncoder(w).Encode(map[string]string{"tokenId": "tok_1"})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		t.Setenv("VERCEL_API_BASE", srv.URL)
		snapshot := func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(calls)
		}

		before := time.Now().Unix()
		res, err := rt.ExecBlind(ctx, core.ExecRequest{
			MintRequest: core.MintRequest{Provider: "vercel", Scope: "team_abc/prj_def", TTLSeconds: 300},
			Vault:       "bitwarden",
			Command:     []string{"sh", "-c", `printf 'token=%s\n' "$VERCEL_TOKEN"`},
		})
		after := time.Now().Unix()
		if err != nil || res.ExitCode != 0 || res.Stdout != "token="+core.RedactedPlaceholder+"\n" || res.LeaseID != "tok_1" || !res.Revoked {
			t.Fatalf("exec: %+v, %v", res, err)
		}
		if got, want := snapshot(), []string{"POST /v3/user/tokens?teamId=team_abc", "DELETE /v3/user/tokens/tok_1"}; !slices.Equal(got, want) {
			t.Fatalf("requests %q, want %q", got, want)
		}
		mu.Lock()
		if exp := int64(body.ExpiresAt) / 1000; !strings.HasPrefix(body.Name, "mintrun-") || body.ProjectID != "prj_def" || exp < before+300 || exp > after+300 {
			t.Errorf("token request %+v, want a mintrun- token for prj_def that expires in 300s", body)
		}
		mu.Unlock()

		p, err := rt.Registry.Provider("vercel")
		if err != nil {
			t.Fatal(err)
		}
		const wrong = "wrong-master-token-xyz"
		if _, err := p.Mint(ctx, wrong, core.MintRequest{Provider: "vercel", Scope: "prj_def"}); err == nil || !strings.Contains(err.Error(), "HTTP 403 invalid token Bearer "+core.RedactedPlaceholder) || strings.Contains(err.Error(), wrong) {
			t.Errorf("wrong master: got %v, want a 403 that quotes no token", err)
		}
		if _, err := p.Mint(ctx, master, core.MintRequest{Provider: "vercel", Scope: "team_redirect/prj_def"}); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
			t.Errorf("redirect: got %v, want the 302 as an error", err)
		}
		n := len(snapshot())
		if err := p.Revoke(ctx, master, &core.Lease{ID: "current", Provider: "vercel", Ephemeral: true}); err == nil || !strings.Contains(err.Error(), "refusing to revoke") {
			t.Errorf(`revoke "current": got %v, want a refusal, since it would delete the master`, err)
		}
		if _, err := p.Mint(ctx, master, core.MintRequest{Provider: "vercel", Scope: "a/b/c"}); err == nil || !strings.Contains(err.Error(), "-scope must be") {
			t.Errorf("bad scope: got %v", err)
		}
		t.Setenv("VERCEL_API_BASE", "https://evil.example")
		if _, err := p.Mint(ctx, master, core.MintRequest{Provider: "vercel", Scope: "prj_def"}); err == nil || !strings.Contains(err.Error(), "VERCEL_API_BASE must be unset") {
			t.Errorf("foreign API base: got %v, want a refusal", err)
		}
		if got := len(snapshot()); n != 4 || got != n {
			t.Errorf("%d requests before the refusals (want 4) and %d after", n, got)
		}
	})

	t.Run("postgres-jit", func(t *testing.T) {
		const master = "postgres://admin:s3cr%40t-PW@db.example:6543/appdb?sslmode=require&application_name=x"
		kv, err := rt.Registry.Vault("keychain")
		if err != nil {
			t.Fatal(err)
		}
		if err := kv.SetSecret(ctx, "postgres-jit", master); err != nil {
			t.Fatal(err)
		}
		type psqlCall struct {
			Argv       []string `json:"argv"`
			PGPassword string   `json:"pgpassword"`
			SQL        string   `json:"sql"`
		}
		psqlCalls := func() (calls []psqlCall) {
			for _, l := range readLog("psql.log") {
				var c psqlCall
				if err := json.Unmarshal([]byte(l), &c); err != nil {
					t.Fatalf("psql.log line %q: %v", l, err)
				}
				calls = append(calls, c)
			}
			return calls
		}
		// The child writes the URL to a file, since mintrun redacts it from the output, and prints the host,
		// port, and database, which only a PG* variable would get redacted.
		out := filepath.Join(t.TempDir(), "child-env")
		t.Setenv("CHILD_ENV", out)

		before := time.Now().Unix()
		res, err := rt.ExecBlind(ctx, core.ExecRequest{
			MintRequest: core.MintRequest{Provider: "postgres-jit", Scope: "app_readonly", TTLSeconds: 120},
			Vault:       "keychain",
			Command:     []string{"sh", "-c", `printf '%s\n' "$DATABASE_URL" > "$CHILD_ENV"; echo db.example:6543/appdb`},
		})
		after := time.Now().Unix()
		if err != nil || res.ExitCode != 0 || !res.Revoked || res.Stdout != "db.example:6543/appdb\n" {
			t.Fatalf("exec: %+v, %v", res, err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		env := regexp.MustCompile(`^postgres://(mintrun_[0-9]+_[0-9a-f]{8}):([0-9a-f]{48})@db\.example:6543/appdb\?sslmode=require&application_name=x\n$`).FindStringSubmatch(string(b))
		if env == nil || env[1] != res.LeaseID {
			t.Fatalf("DATABASE_URL %q, lease %q", b, res.LeaseID)
		}
		user, pw := env[1], env[2]

		calls := psqlCalls()
		if len(calls) != 2 {
			t.Fatalf("psql ran %d times, want mint and revoke", len(calls))
		}
		argv := []string{"-X", "-q", "-v", "ON_ERROR_STOP=1", "-At", "-d", "postgres://admin@db.example:6543/appdb?sslmode=require&application_name=x"}
		for _, c := range calls {
			if !slices.Equal(c.Argv, argv) || c.PGPassword != "s3cr@t-PW" || strings.Contains(c.SQL, pw) {
				t.Errorf("psql got argv %q and PGPASSWORD %q, want the password in the environment only", c.Argv, c.PGPassword)
			}
		}
		m := regexp.MustCompile(`^DO \$\$ BEGIN IF \(SELECT rolsuper FROM pg_roles WHERE rolname = current_user\) THEN RAISE EXCEPTION '[^']+'; END IF; ` +
			`IF 'app_readonly' = current_user OR NOT pg_has_role\(current_user, 'app_readonly', 'MEMBER WITH ADMIN OPTION'\) THEN RAISE EXCEPTION '[^']+'; END IF; END \$\$;\n` +
			`CREATE ROLE "(mintrun_[0-9]+_[0-9a-f]{8})" LOGIN PASSWORD 'SCRAM-SHA-256\$4096:([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)' ` +
			`VALID UNTIL '([0-9-]{10} [0-9:]{8}\+00)' IN ROLE "app_readonly";\n$`).FindStringSubmatch(calls[0].SQL)
		if m == nil || m[1] != user {
			t.Fatalf("mint SQL %q", calls[0].SQL)
		}
		// The verifier must be the one PostgreSQL derives from the password the child got.
		mac := func(key []byte, msg string) []byte {
			h := hmac.New(sha256.New, key)
			h.Write([]byte(msg))
			return h.Sum(nil)
		}
		salt, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil {
			t.Fatal(err)
		}
		salted, err := pbkdf2.Key(sha256.New, pw, salt, 4096, 32)
		if err != nil {
			t.Fatal(err)
		}
		stored := sha256.Sum256(mac(salted, "Client Key"))
		if len(salt) != 16 || m[3] != base64.StdEncoding.EncodeToString(stored[:]) || m[4] != base64.StdEncoding.EncodeToString(mac(salted, "Server Key")) {
			t.Errorf("the SCRAM verifier does not match the password")
		}
		if until, err := time.Parse("2006-01-02 15:04:05-07", m[5]); err != nil || until.Unix() < before+120 || until.Unix() > after+120 {
			t.Errorf("VALID UNTIL %q (%v), want 120s from now", m[5], err)
		}
		revoke := strings.ReplaceAll(`ALTER ROLE "{r}" NOLOGIN;
GRANT "{r}" TO CURRENT_USER;
SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity WHERE usename = '{r}';
REASSIGN OWNED BY "{r}" TO CURRENT_USER;
DROP OWNED BY "{r}";
DROP ROLE "{r}";
`, "{r}", user)
		if calls[1].SQL != revoke {
			t.Errorf("revoke SQL %q, want %q", calls[1].SQL, revoke)
		}

		// None of these reaches psql.
		p, err := rt.Registry.Provider("postgres-jit")
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, master, scope, want string }{
			{"no scope", master, "", "-scope must name the group role"},
			{"quote in scope", master, `app"; DROP ROLE admin; --`, "-scope must name the group role"},
			{"built-in role", master, "pg_read_all_data", "-scope must name the group role"},
			{"dollar quote in scope", master, "app$$", "-scope must name the group role"},
			{"uppercase scope", master, "App_ReadOnly", "-scope must name the group role"},
			{"not a URL", "hunter2-not-a-url", "app_readonly", "the master secret must be a URL"},
			{"two hosts", "postgres://admin:hunter2@h1:5432,h2:5432/appdb", "app_readonly", "one host and a numeric port"},
			{"password in query", "postgres://admin@db.example/appdb?password=hunter2", "app_readonly", "has a password in its query"},
		} {
			if _, err := p.Mint(ctx, tc.master, core.MintRequest{Provider: "postgres-jit", Scope: tc.scope, TTLSeconds: 60}); err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "hunter2") {
				t.Errorf("%s: got %v, want %q quoting no secret", tc.name, err, tc.want)
			}
		}
		if err := p.Revoke(ctx, master, &core.Lease{ID: "app_owner", Provider: "postgres-jit", Ephemeral: true}); err == nil || !strings.Contains(err.Error(), "refusing to revoke") {
			t.Errorf("revoke of a role the plugin did not create: got %v", err)
		}
		if n := len(psqlCalls()); n != 2 {
			t.Errorf("psql ran %d times, want no more than mint and revoke", n)
		}

		t.Setenv("PSQL_STUB_FAIL", "1")
		_, err = p.Mint(ctx, master, core.MintRequest{Provider: "postgres-jit", Scope: "app_readonly", TTLSeconds: 60})
		if err == nil || !strings.Contains(err.Error(), "psql failed: ERROR: DO $$") || !strings.Contains(err.Error(), "LOGIN PASSWORD '"+core.RedactedPlaceholder+"'") ||
			!strings.HasSuffix(err.Error(), "password="+core.RedactedPlaceholder) || strings.Contains(err.Error(), "s3cr") || strings.Contains(err.Error(), "SCRAM-SHA-256") {
			t.Errorf("psql failure: got %v, want the statement with the verifier and password scrubbed", err)
		}
	})
}

// TestPluginInstallCatalog installs every example plugin by its bare name from the copy built into
// the binary. The bundled copy wins over a directory of the same name in the working directory,
// which installs only by its path, and the temporary copy is removed.
func TestPluginInstallCatalog(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "examples", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	home, tmp := t.TempDir(), t.TempDir()
	t.Setenv("MINTRUN_HOME", home)
	t.Setenv("TMPDIR", tmp)
	t.Chdir(t.TempDir())
	if err := os.Mkdir("bitwarden", 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join("bitwarden", "plugin.json"), []byte(`{"name":"bitwarden","version":"6.6.6","kind":"vault"}`), 0o600)
	_ = os.WriteFile(filepath.Join("bitwarden", "run"), []byte("#!/bin/sh\n"), 0o700)

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n++
		if code, exited := runMainWithArgs(t, "", "plugin", "install", e.Name()); exited {
			t.Fatalf("plugin install %s exited %d", e.Name(), code)
		}
		for _, f := range []string{"plugin.json", "run"} {
			want, _ := os.ReadFile(filepath.Join(src, e.Name(), f))
			got, err := os.ReadFile(filepath.Join(home, "plugins", e.Name(), f))
			if err != nil || len(want) == 0 || !bytes.Equal(got, want) {
				t.Errorf("%s/%s: the installed copy differs from examples/plugins (err %v)", e.Name(), f, err)
			}
		}
		if info, err := os.Stat(filepath.Join(home, "plugins", e.Name(), "run")); err != nil || info.Mode().Perm() != 0o700 {
			t.Errorf("%s/run: want mode 0700, got %v (err %v)", e.Name(), info, err)
		}
	}
	if n == 0 {
		t.Fatal("no example plugins found")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temporary copies left behind: %v", left)
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "install", "./bitwarden"); exited {
		t.Fatalf("plugin install ./bitwarden exited %d", code)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "plugins", "bitwarden", "run")); string(got) != "#!/bin/sh\n" {
		t.Errorf("./bitwarden: got %q, want the local directory's run", got)
	}
	if code, exited := runMainWithArgs(t, "", "plugin", "install", "no-such-plugin"); !exited || code != 1 {
		t.Errorf("unknown bare name: got exit %d (exited %v), want 1", code, exited)
	}
}
