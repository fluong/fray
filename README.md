# Fray

Public client, GitHub Action, and scan API wire contract for Fray.

Parse a Terraform plan into a data-flow diagram (DFD), send it to the hosted
scan API, and get STRIDE findings plus a merge gate back. Rule evaluation and
the hosted service live in a private companion repository — this repo never
ships rules.

Latest release: **v0.5.0**. `v0.1.0` is retracted (non-public fixtures leaked
into the module zip; see `go.mod`).

Related:

- Hosted API / rules — private companion repository
- [fluong/fray-demo-aws](https://github.com/fluong/fray-demo-aws) — AWS demo wired to the Action
- [Trust and data handling](docs/trust.md) — what is sent, where it lives, retention, subprocessors; [Dashboard](docs/trust.md#dashboard)
- [Privacy policy](docs/privacy.md) — draft GDPR-shaped privacy notice; [Dashboard](docs/privacy.md#dashboard)
- [Terms of service](docs/terms.md) — draft terms (beta / as-is)

## Install

### 1. Install the GitHub App

Install **Fray (getfray.dev)** on your GitHub account or organization and
**select repositories** (do not grant all-repos access unless you intend to).

The free plan covers **3 repositories per installation**. If an installation
selects more than 3 repositories, scans for **all** of its repositories are
skipped (`installation_over_cap`) until you narrow the selection.

The App has **metadata read** only. It does not get code access. Fray never
clones repositories. Scans authenticate with **GitHub Actions OIDC** from your
CI.

### 2. Add a redaction key

```bash
openssl rand -hex 32 | gh secret set FRAY_REDACTION_KEY
```

### 3. Add the workflow

Pin third-party actions by commit SHA (same shape as the post-install setup
page). Look up the current `fluong/fray` release tag and pin that commit:

```yaml
name: fray

on:
  pull_request:
  push:
    branches: [main]

permissions:
  id-token: write        # OIDC token with audience "fray"
  contents: read
  pull-requests: write   # create/update the Fray PR comment
  security-events: write # upload SARIF to the Security tab

jobs:
  fray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - uses: fluong/fray@23947633d771e9bb74f9262809a424673886651d # v0.5.5
        with:
          api-url: https://api.getfray.dev
          working-directory: infra   # Terraform root; omit if plans live at repo root
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
```

See [GitHub Action](#github-action) for every input.

### When a repo is not enrolled

If the App install does not cover the repository (inactive install, repo not
selected, or over the free-tier cap), the Action **skips the scan** by default:
warning annotation + job summary, exit 0. Set `fail-on-unenrolled: true` to
fail the job instead.

| API code | Default | `fail-on-unenrolled: true` |
|---|---|---|
| `installation_inactive` | Skip + warning | Fail |
| `repo_not_enrolled` | Skip + warning | Fail |
| `installation_over_cap` | Skip + warning | Fail |

### Limits

On the free plan the hosted API allows **30 scans per repository per hour** and
**100 scans per organization per day**. When a run is rate-limited (HTTP 429
`rate_limited`), the Action **skips the scan** by default: warning annotation
(with retry-after), job summary, exit 0. Set `fail-on-rate-limit: true` to fail
the job instead. This is independent of `fail-on-unenrolled`.

### Uninstall

Uninstalling the App (or removing a repository from it) soft-disables access
immediately. After **30 days**, Fray hard-deletes that organization’s (or
repository’s) scan data and archive objects. Details:
[docs/trust.md](docs/trust.md).

## Layout

| Path | Purpose |
|------|---------|
| `client/` | Terraform plan → DFD parser (default-on HMAC redaction) |
| `render/` | Threat-model, PR-comment, and SARIF renderers |
| `api/v1/` | Request/response types for `POST /v1/scans` |
| `schema/` | DFD / finding / config / mitigations JSON Schemas and validation |
| `cmd/fray/` | CLI that parses a plan and calls the hosted API (`-remote`) |
| `action.yml` + `action/` | Composite Action — OIDC-authenticated scan from GitHub Actions |
| `testdata/` | Public AWS fixture, synthetic DFDs, PR-comment goldens |
| `scripts/` | Internal-identifier denylist + `install-hooks.sh` |
| `.githooks/` | Pre-push (actionlint, gitleaks, denylist, pins, docs); install via `scripts/install-hooks.sh` |

## What leaves your CI

Redaction is **on by default**. Before Fray receives a scan, the client replaces
resource names, Terraform addresses, signal names, declared keys/paths, and the
`source.repo` string with HMAC-SHA256 digests under a key that only you hold
(`FRAY_REDACTION_KEY`). Element and flow ids are re-derived from those digests.
The key never leaves CI. Optional element `purpose` values (a closed enum such as
`customer_uploads` or `backups`) are sent in the clear — they are not names.

Fray still knows **which GitHub repository and ref** sent a scan: that identity
comes from the Actions OIDC token used to authenticate. Redaction does not hide
the repository from Fray. What Fray does **not** receive are resource names,
addresses, module names, file contents, or source code.

`redaction: off` in `fray.yaml` is client-side only and prints a loud warning.
The hosted API rejects unredacted payloads unless the org explicitly allows
them.

If the redaction key rotates, the server may report an incomparable baseline;
the PR comment surfaces that note so a key change cannot silently loosen the
gate.

Example of a redacted DFD fragment (scheme `hmac-sha256-v1`):

```json
{
  "schema_version": "dfd/v1",
  "redaction": {
    "scheme": "hmac-sha256-v1",
    "key_fingerprint": "0123456789abcdef"
  },
  "source": {
    "repo": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "commit": "abcdef1",
    "iac_tool": "terraform",
    "fidelity": "plan"
  },
  "elements": [
    {
      "id": "e0123456789abcdef",
      "type": "datastore",
      "kind": "object_storage",
      "provider": "aws",
      "provenance": "iac",
      "evidence": {
        "addresses": [
          "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        ]
      },
      "attributes": {
        "public": false,
        "public_access_blocked": true
      }
    }
  ]
}
```

Audit the exact POST body with `-dry-run -show-payload`, or set Action input
`show-payload: true` to upload it as the `fray-payload` workflow artifact.

Generate a key once and store it as a repository secret:

```bash
openssl rand -hex 32 | gh secret set FRAY_REDACTION_KEY
```

## GitHub Action

```yaml
name: fray

on:
  pull_request:
  push:
    branches: [main]

permissions:
  id-token: write        # OIDC token with audience "fray"
  contents: read
  pull-requests: write   # create/update the Fray PR comment
  security-events: write # upload SARIF to the Security tab

jobs:
  fray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - uses: fluong/fray@v0.4.0
        with:
          api-url: https://api.getfray.dev
          working-directory: infra
          config: fray.yaml
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
          show-payload: true   # optional: upload the sent JSON as fray-payload
```

| Input | Default | Notes |
|-------|---------|-------|
| `api-url` | — | Required. Hosted API: `https://api.getfray.dev` (never a `*.run.app` URL). |
| `working-directory` | `.` | Terraform root (contains `.tf` sources). |
| `config` | `fray.yaml` | Path relative to the workspace. |
| `redaction-key` | `""` | Required unless `fray.yaml` sets `redaction: off`. |
| `show-payload` | `false` | Upload `payload.json` as the `fray-payload` artifact. |
| `fail-on-unenrolled` | `false` | Fail the job when the GitHub App install does not cover this repo (see below). |
| `fail-on-rate-limit` | `false` | Fail the job when the API returns HTTP 429 `rate_limited` (see [Limits](#limits)). |

Auth is GitHub Actions OIDC with audience `fray` — there is no API-key input.
Fork pull requests cannot mint that token: the Action emits a warning annotation
and a job-summary line stating Fray did not run (never a silent pass).

When the API returns **403** with an enrollment code (only once App enrollment
is required server-side), the Action handles three outcomes:

| Code | Default (`fail-on-unenrolled: false`) | `fail-on-unenrolled: true` |
|------|----------------------------------------|------------------------------|
| `installation_inactive` | Warning + summary; skip scan (exit 0) | Error annotation; exit 1 |
| `repo_not_enrolled` | Warning + summary; skip scan (exit 0) | Error annotation; exit 1 |
| `installation_over_cap` | Warning + summary; skip scan (exit 0) | Error annotation; exit 1 |

Skipped enrollment runs set `steps.scan.outputs.skipped=true` and
`skip_reason` to the enrollment code, and do not upload SARIF, update the PR
comment, or upload the payload artifact. Any other auth failure (401,
plain-text 403, unknown JSON `error`) still fails the job.

On each run the Action:

1. `terraform init` + `plan` + `show -json` in `working-directory`
2. Scans via OIDC (`aud=fray`)
3. Updates a single PR comment in place (hidden `<!-- fray -->` marker)
4. Uploads SARIF via `github/codeql-action/upload-sarif` (category `fray`,
   tool name `Fray`). Results include `properties.security-severity` (high 7.5,
   medium 5.0, low 3.0) so GitHub Code Scanning’s “check run failure” threshold
   (default High or higher) agrees with Fray’s high-severity gate.
5. Exits non-zero when the merge gate blocks

`mitigations.yaml` at the repo root is used when present; otherwise the Action
writes an empty dispositions file for the CLI.

## CLI

```bash
go install github.com/fluong/fray/cmd/fray@v0.4.0

export FRAY_REDACTION_KEY="$(openssl rand -hex 32)"
export FRAY_API_URL=https://api.getfray.dev

fray \
  -plan plan.json \
  -source infra \
  -config fray.yaml \
  -mitigations mitigations.yaml \
  -remote "$FRAY_API_URL" \
  -default-branch main \
  -repo org/repo \
  -commit "$SHA" \
  -branch feature/x \
  -oidc-token "$FRAY_OIDC_TOKEN"

# Inspect the exact JSON that would be POSTed (no network call):
fray ... -dry-run -show-payload

# Or write it to a file:
fray ... -dry-run -payload-out payload.json
```

| Flag / env | Role |
|------------|------|
| `-remote` | API base URL (required; `https://api.getfray.dev`) |
| `-oidc-token` / `FRAY_OIDC_TOKEN` | Actions OIDC JWT (preferred in CI) |
| `-api-key` / `FRAY_API_KEY` | Org API key (local smoke only; cannot write default-branch baseline) |
| `-fail-on-unenrolled` | Exit 1 on enrollment rejection codes (default: warn + exit 0) |
| `-default-branch` / `-branch` | Local only — POST body carries `is_default_branch`, not names |
| `-base-commit` / `-base-source` | PR base sha + sources for module-arg attribution |
| `-out` | Writes `findings.json`, `findings.sarif`, `threat-model.md`, `pr-comment.md` |

Exit `1` when the gate blocks; exit `2` on usage or transport errors.

## Config

Minimal `fray.yaml` (redaction on by default — omit `redaction`):

```yaml
schema_version: fray-config/v1
```

**Breaking (v0.5.0):** purpose is no longer inferred from resource names. It is set
from resource type, plan relations (CloudTrail / S3 access-log / GCS sink targets),
or declared in `fray.yaml` — declare `purpose: audit_archive` etc. for buckets you
want FR-027 to cover:

```yaml
schema_version: fray-config/v1
annotations:
  elements:
    - address: cloudflare_r2_bucket.archive
      purpose: audit_archive
    - address: module.uploads.aws_s3_bucket.this[0]
      purpose: customer_uploads
```

Minimal `mitigations.yaml`:

```yaml
schema_version: mitigation/v1
entries: []
```

Schemas live under `schema/` (`fray-config.schema.json`, `mitigations.schema.json`,
`dfd.schema.json`, `finding.schema.json`). Use `fray.yaml` to declare extra
elements/flows/boundaries and annotate inferred ones; use mitigations to accept
`(rule_id, target)` pairs that should not gate.

## Development

```bash
./scripts/install-hooks.sh   # once per clone; pre-push = actionlint + gitleaks + denylist + pins + docs
go test ./...
```

CI (`.github/workflows/guardrails.yml`) and the pre-push hook both run actionlint,
gitleaks, `scripts/check-internal-identifiers.sh` (whole tree, including
`*_test.go`), `scripts/check-action-pins.sh` (every `action.yml` `uses:` must be
a 40-char SHA), and `scripts/check-public-docs.sh` (CHANGELOG/README must not
name the private companion repository; README/`docs/`/`action.yml` must not
contain a Cloud Run `*.run.app` hostname). Patterns come from the `FRAY_DENYLIST`
secret (CI) or `FRAY_DENYLIST` / `~/.config/fray/denylist` locally — never from
the committed tree; missing list fails closed. See [docs/release.md](docs/release.md).

## Contributing

Copy paths from the private companion into this repo with an **explicit
allowlist only** — never a bulk `cp -R`. Public docs and Action examples use
`https://api.getfray.dev`; never publish a Cloud Run `*.run.app` hostname
(`scripts/check-public-docs.sh` fails the build if one appears in README,
`docs/`, or `action.yml`). Do not land private-companion fixtures, plans, or
goldens here. The guardrails denylist job fails on pull requests from forks
(secrets are not exposed to them); a maintainer re-runs the check from a
trusted context.

## License

Apache-2.0. See [LICENSE](LICENSE) and `testdata/aws-web-app/NOTICE` for the
demo Terraform fixture’s third-party module attributions.
