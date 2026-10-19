# Example Plugins

Three plugins built into the `mintrun` binary: `mintrun plugin install <name>` installs one with no clone or download. Each is one Python script (Python 3.9 or later, standard library only) that speaks the protocol in the main README's [Polyglot Plugin SDK](../../README.md#polyglot-plugin-sdk) section: one JSON request on `stdin`, one JSON reply on `stdout`.

| Plugin | Kind | Needs | What it does |
|---|---|---|---|
| [`bitwarden`](bitwarden/run) | vault | `bw` (Bitwarden CLI), unlocked | Keeps master secrets as Bitwarden secure notes |
| [`vercel`](vercel/run) | provider | a Vercel access token | Mints a Vercel token that expires with the lease and deletes it on exit |
| [`postgres-jit`](postgres-jit/run) | provider | `psql`, PostgreSQL 14 or later | Creates a login role for each command and drops it on exit |

```bash
mintrun plugin install postgres-jit
mintrun plugin list
```

`plugin install` copies the plugin into `~/.mintrun/plugins/<name>/`, and `mintrun plugin remove <name>` deletes that copy. A bare name always installs the copy built into the binary, never a directory of that name in the current directory. To run your own edits, install the directory by its path, and again after each edit: `mintrun plugin install ./examples/plugins/postgres-jit`.

**What has been tested:** `go test ./cmd/mintrun` (`TestExamplePlugins`) installs all three through the CLI and runs them against stand-ins: a stub `bw`, a stub `psql`, and a local Vercel API. `TestPluginInstallCatalog` installs each by name and checks that the installed files match this directory byte for byte. `postgres-jit` has also run against real PostgreSQL 15 and 16 servers. `bitwarden` and `vercel` have not run against a real Bitwarden account or the real Vercel API.

Each plugin passes secrets to its helper on `stdin` or in its environment, never on its command line, where `ps` shows them. It never quotes a helper's `stdout`, which can hold the secret, and it removes every secret it knows from its error messages before returning them.

## `bitwarden` (vault)

Stores each master secret as a secure note named `mintrun/<key>` in your personal vault.

```bash
export BW_SESSION="$(bw unlock --raw)"     # after bw login
MINTRUN_VAULT=bitwarden mintrun secret set cloudflare
mintrun exec -vault bitwarden -provider cloudflare -scope example.com -perms dns:write,workers:write -clean-env -- npx wrangler deploy
```

- `MINTRUN_VAULT=bitwarden` makes it the default vault for `secret` and `exec`; `-vault bitwarden` picks it for one `exec`.
- `BW_SESSION` unlocks your whole vault, and the command `mintrun` runs inherits it unless you pass `-clean-env` or set `clean_env` in the policy. Even then, a command running as you can read it from `mintrun`'s environment ([What the Vault Protects](../../README.md#5-what-the-vault-protects-and-what-it-does-not)).
- Only notes in your personal vault count: a note an organization shares is ignored, since another member could have planted it. Two notes with the same name are an error.
- `bw` reads its local copy of the vault: run `bw sync` after adding a note on another device.
- `mintrun secret delete` moves the note to the trash.

## `vercel` (provider)

The master secret is a Vercel access token. Each `exec` creates a token that expires when the lease does and deletes it when the command exits. The command gets it as `VERCEL_TOKEN`, which the Vercel CLI reads.

```bash
mintrun secret set vercel
mintrun exec -provider vercel -scope team_abc/prj_def -perms deploy -ttl 900 -- npx vercel deploy --prod
```

- `-scope` is empty, `<project_id>`, or `<team_id>/<project_id>`. A project ID limits the new token to that project; a team ID creates it in that team.
- The plugin ignores permissions, but `mintrun exec` requires `-perms`: name what the command does (`deploy`), and pin it with `allowed_permissions` in `policy.json`.
- The lease ID is the new token's ID. Revoke refuses the ID `current`, which would delete the master token.
- `VERCEL_API_BASE` exists for the tests and accepts only `http://127.0.0.1:<port>`.

## `postgres-jit` (provider)

Creates a login role for each `exec` and drops it when the command exits. The role joins the group role named by `-scope` and inherits its privileges. Its password stops working when the lease expires.

One-time setup, as a superuser:

```sql
CREATE ROLE app_readonly NOLOGIN;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
CREATE ROLE mintrun_minter LOGIN CREATEROLE PASSWORD 'choose-a-password';
GRANT app_readonly TO mintrun_minter WITH ADMIN OPTION;
```

Store the minting role's URL, `postgres://mintrun_minter:<password>@<host>:5432/<db>?sslmode=require`, then run commands with `DATABASE_URL`:

```bash
mintrun secret set postgres-jit
mintrun exec -provider postgres-jit -scope app_readonly -perms login -ttl 300 -- sh -c 'psql "$DATABASE_URL" -c "select count(*) from orders"'
```

Pin the groups in `~/.mintrun/policy.json`, because an agent picks `-scope` over MCP:

```json
{ "postgres-jit": { "allowed_scopes": ["app_readonly"], "max_ttl_seconds": 900 } }
```

- **The minting role:** it needs `CREATEROLE` and `ADMIN OPTION` on each group agents may join. The plugin refuses a superuser, and any group the minting role holds no `ADMIN OPTION` on. PostgreSQL 15 and older let a `CREATEROLE` role grant any role but a superuser, so there this check is the only limit besides the policy.
- **Group names** are lowercase, cannot start with `pg_`, and cannot hold `$`.
- **Permissions:** the plugin ignores them, but `mintrun exec` requires `-perms`: `login` names what the role does, and `allowed_permissions` in `policy.json` can pin it.
- **The command gets only `DATABASE_URL`.** `mintrun` removes every lease env value and the lease ID from the command's output. A separate `PGPORT=5432` would turn every `5432` in query results into `[MINTRUN:REDACTED]`. The role name is the lease ID: the audit log and the MCP result show it, and the command's output shows `[MINTRUN:REDACTED]` in its place.
- **The password** reaches the server only as a SCRAM-SHA-256 verifier, so no statement log holds it.
- **Revoke** stops the role from logging in, ends its open sessions, gives what it created to the minting role, and drops it. `VALID UNTIL` alone would only block new logins. Objects the role created in another database stay, so `DROP ROLE` fails and the role remains, unable to log in; the lease then reports `revoked: false`.
- **The master URL** must name one host, with `@`, `:`, `/`, and `%` in the password percent-encoded. The command's URL keeps its query options, such as `sslmode`.
