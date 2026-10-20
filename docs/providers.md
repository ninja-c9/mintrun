# Cloud Providers

`mintrun` wraps your unmodified native binaries and injects standard environment variables into the blind child process. Each section shows the master secret a provider takes and one command; `mintrun init <provider>` stores and checks it.

## Cloudflare (`wrangler`)
Create a Cloudflare API Token with **`User -> API Tokens -> Edit`** so `mintrun` can mint and revoke disposable child tokens on your behalf:

```bash
## Mint a sub-token locked ONLY to `example.com` with DNS + Workers write access,
## run Wrangler, scrub stdout/stderr, and DELETE the sub-token when Wrangler exits:
./mintrun exec \
  -provider cloudflare \
  -scope example.com \
  -perms dns:write,workers:write \
  -ttl 300 \
  -- npx wrangler deploy
```

## GitHub CLI (`gh` & `git`)
Store a GitHub App credential formatted as `<app_id>:<installation_id>:<private_key_pem>` (or `<app_id>::<private_key_pem>` when MCP agents select an installation via `params.installation_id`):

```bash
## Enroll your GitHub App credential via stdin:
printf '%s:%s:%s' "123456" "87654321" "$(cat app-private-key.pem)" | ./mintrun secret set github

## Mint a repository-scoped installation token, run `gh`, and revoke it on exit:
./mintrun exec \
  -provider github \
  -scope ninja-c9/mintrun \
  -perms contents:write,pull_requests:write \
  -- gh pr create --fill
```

## AWS CLI (`aws` & `terraform`)
Store IAM credentials formatted as `<access_key_id>:<secret_access_key>[:<session_token>]`. `mintrun` signs an `STS AssumeRole` request with 100% stdlib SigV4 and narrows the session with an inline IAM policy:

```bash
./mintrun exec \
  -provider aws \
  -scope arn:aws:iam::123456789012:role/DeployRole \
  -perms s3:GetObject,s3:PutObject \
  -ttl 900 \
  -- aws s3 ls s3://my-Bucket
```

## Google Cloud SDK (`gcloud` & `gsutil`)
Permissions map to OAuth2 scopes (short names expand under `https://www.googleapis.com/auth/`). Add `-clean-env` so the child only sees `PATH`, `HOME`, `TMPDIR`, `USER`, `LANG`, `TERM`, `SSL_CERT_FILE`, your policy's `allowed_env`, and the lease credential:

```bash
./mintrun exec \
  -provider gcp \
  -perms cloud-platform.read-only \
  -clean-env \
  -- gcloud storage ls gs://my-bucket
```

> **Explicit Static Wrapper Mode:** Already have a pre-scoped token (such as a Cloudflare scoped token, a GitHub PAT, stored AWS IAM keys, or a GCP OAuth2 access token) and only want zero-knowledge injection + 5-encoding output scrubbing? Request static mode explicitly with `-perms static` (MCP: `"permissions": ["static"]`). Because static mode hands the stored secret directly to the child without minting a disposable token, the provider must also opt in with `"allow_static": true` in `policy.json`:
> ```bash
> ./mintrun exec -provider github -perms static -- gh issue list -R ninja-c9/mintrun
> ```
> ```json
> { "github": { "allow_static": true } }
> ```
> Static mode never wraps a private key the provider signs with: `github` refuses a GitHub App private key and `gcp` refuses a service-account JSON or PEM key.
>
> **Migration (breaking change):** `github` used to fall back to static mode for a PAT, and `aws` for any scope that is not an `arn:aws:` role ARN, which skipped the `allow_static` gate. Both now fail with an error that names the opt-in. To keep injecting a GitHub PAT or stored IAM keys, add `-perms static` and `"allow_static": true` for `github` or `aws`. GitHub App credentials and AWS role-ARN scopes mint JIT credentials as before.
