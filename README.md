# Fray

Public client, GitHub Action, and scan API wire contract for Fray.

Parse a Terraform plan into a data-flow diagram (DFD), send it to the hosted
scan API, and get STRIDE findings plus a merge gate back. Rule evaluation and
the hosted service live in a private companion repository — this repo never
ships rules.

**New here?** → [Getting started](docs/getting-started.md) (shortest path to a
first green scan). Stuck? → [Troubleshooting](#troubleshooting).

Latest release: **v0.9.0**. `v0.1.0` is retracted (non-public fixtures leaked
into the module zip; see `go.mod`).

Related:

- Hosted API / rules — private companion repository
- [fluong/fray-demo-aws](https://github.com/fluong/fray-demo-aws) — AWS demo wired to the Action
- [Trust and data handling](docs/trust.md) — what is sent, where it lives, retention, subprocessors; [Dashboard](docs/trust.md#dashboard)
- [Privacy policy](docs/privacy.md) — draft GDPR-shaped privacy notice; [Dashboard](docs/privacy.md#dashboard)
- [Terms of service](docs/terms.md) — draft terms (beta / as-is)

## Install

Prefer the checklist in [Getting started](docs/getting-started.md). Summary:

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
| `schema/` | DFD / finding / config / waivers JSON Schemas and validation |
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
| `fail-on-rate-limit` | `false` | Fail the job when the API returns HTTP 429 `rate_limited` (see [Limits](#limits)). Also covered by `fail-on-skip`. |
| `fail-on-skip` | `false` | Fail the job on **any** soft-skip (enrollment or rate limit). Default: warn + exit 0. Supersedes soft-skip for rate limit when true (`fail-on-rate-limit` still works alone). |
| `upload-sarif` | `true` | Upload `findings.sarif` to Code Scanning. Requires `security-events: write`. Set `false` to keep the file without uploading. |

| Output | Notes |
|--------|-------|
| `has-sarif` | `true` when `findings.sarif` was written. |
| `sarif-file` | Absolute path to `findings.sarif` when present; empty otherwise. |

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
   tool name `Fray`) when `upload-sarif` is true (default). The workflow must
   grant **`security-events: write`**; private repos also need Code Scanning
   enabled. Upload failures are non-fatal (`continue-on-error`) and emit a
   warning. Results include `properties.security-severity` (high 7.5, medium
   5.0, low 3.0) so Code Scanning’s “check run failure” threshold (default High
   or higher) agrees with Fray’s high-severity gate. **Waived** and **mitigated**
   findings are not uploaded to Code Scanning (GitHub ignores SARIF
   `suppressions`), so their alerts close as fixed there. The accepted-risk
   record is `.fray/waivers.yml`, the PR comment’s Waivers section, and the Fray
   dashboard — not the Security tab.
5. Exits non-zero when the merge gate blocks

Optional waivers live at `.fray/waivers.yml` (Action input `waivers-file`). See
[Waivers](#waivers).

## CLI

```bash
go install github.com/fluong/fray/cmd/fray@v0.9.0

export FRAY_REDACTION_KEY="$(openssl rand -hex 32)"
export FRAY_API_URL=https://api.getfray.dev

fray \
  -plan plan.json \
  -source infra \
  -config fray.yaml \
  -waivers .fray/waivers.yml \
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
| `-waivers` | Path to `.fray/waivers.yml` (missing file = no waivers) |
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

Schemas live under `schema/` (`fray-config.schema.json`, `waivers.schema.json`,
`dfd.schema.json`, `finding.schema.json`). Use `fray.yaml` to declare extra
elements/flows/boundaries and annotate inferred ones; use
[Waivers](#waivers) to accept exact `(rule, address)` pairs that should not gate.

## Waivers

Accepted risks are recorded in **`.fray/waivers.yml`** (schema
`schema/waivers.schema.json`). The Action reads this file by default (`waivers-file`
input). A missing file means no waivers.

```yaml
version: 1
waivers:
  - id: public-assets-s3
    rule: FR-001
    address: aws_s3_bucket.assets
    reason: "CDN origin; WAF and bucket policy reviewed 2026-10."
    owner: "@security-eng"
    expires: "2027-01-15"
```

| Rule | Detail |
|------|--------|
| `id` | `^[a-z0-9][a-z0-9-]{0,63}$`, unique in the file. **Must not contain personal data** (no names, emails, logins). |
| `rule` | `^FR-[0-9]{3}$` |
| `address` | Terraform / flow address (1–512 chars; no `://`, no `=`), same language as the old mitigations file |
| `reason` | Required (≥10 chars); **stays in the repo** — never sent to Fray |
| `owner` | Required (team or handle as text); **stays in the repo** — never sent |
| `expires` | `YYYY-MM-DD`. Server rejects `expires` beyond **365 days** from today (UTC), or beyond **90 days** when the matched finding is high severity. Expired entries leave the finding `open` again (not an error). Unused in-date entries are **stale** warnings. |

Limits: **200** entries, file ≤ **64 KiB**. The client validates the JSON Schema
and the 365-day horizon locally; the server is authoritative (show its HTTP 400
message verbatim).

On the wire Fray receives only `{id, rule_id, target_id, expires}` inside the
existing `accepted_mitigations` field (address is resolved to a DFD id, then
redacted like today). The PR comment and job summary list applied / new-in-PR /
expiring-soon / expired / stale outcomes from the response.

Recommend protecting `.fray/` with **CODEOWNERS** so waiver changes get review
(Fray cannot enforce GitHub review rules).

### Migrating from `mitigations.yaml`

`mitigations.yaml` is **deprecated**. Action **v0.7.0** rejects a non-empty
`mitigations.yaml` (and rejects having both files non-empty). Copy each entry to
`.fray/waivers.yml`: add `id`, `owner`, and `expires`; rename `rule_id` → `rule`;
drop `status: accepted`. Empty or missing `mitigations.yaml` is ignored. The
`-mitigations` CLI flag remains for one release only and errors with the same
migration message when the file has entries.

## Troubleshooting

Symptom → typical cause → fix. Full setup path: [Getting started](docs/getting-started.md).

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Missing Actions ID token endpoints` / empty OIDC token | Workflow lacks `id-token: write`, or fork PR | Add `permissions: id-token: write`. Open PRs from a branch in this repo, not a fork. |
| App not installed / suspended (`installation_inactive`) | GitHub App missing or suspended | Install [Fray (getfray.dev)](https://github.com/apps/fray-getfray-dev). |
| `repo_not_enrolled` | Repo not selected in the App | Add the repo under [installation Repository access](https://github.com/settings/installations). |
| `installation_over_cap` | More than 3 repos selected (free plan) | Narrow Repository access to ≤3 repos you want scanned. |
| Rate limited (`rate_limited`, retry-after) | Free-plan scan quota | Wait for retry-after. Free plan: **30 scans/repo/hour**, **100/org/day**. Or set `fail-on-rate-limit` / `fail-on-skip` if you want the job red. |
| `FRAY_REDACTION_KEY is required` / must be 64 hex chars | Missing or bad redaction secret | `openssl rand -hex 32 \| gh secret set FRAY_REDACTION_KEY` and pass `redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}`. |
| `working-directory not found` / no `.tf` files | Wrong Terraform root | Set `working-directory` to the directory that contains your `.tf` files. |
| `fray.yaml not found` | Config file missing | Add `schema_version: fray-config/v1` (see [Config](#config)). |
| `terraform init/plan failed` | Provider/backend credentials or TF error | Give the job the same credentials as your normal plan workflow. Fray runs `terraform init` + `plan` in CI (bring-your-own-plan coming later). |
| `Fray API request failed` / 5xx | Network or API error | Confirm `api-url: https://api.getfray.dev`, retry. If it persists, open an issue on `fluong/fray`. |
| Waivers / `mitigations.yaml` errors | Invalid `.fray/waivers.yml` or legacy file | Fix schema/expires; migrate mitigations → [Waivers](#waivers). |
| Fork PR: Fray did not run | Forks cannot mint OIDC `aud=fray` | Open the PR from a branch in this repository. |
| SARIF upload warning | Missing `security-events: write` or Code Scanning off | Grant `security-events: write`; enable Code Scanning on private repos — or set `upload-sarif: false`. |
| Gate blocked | New high-severity findings vs baseline | Read the Fray PR comment / `findings.sarif`. Waive via `.fray/waivers.yml` if accepting the risk. Push/merge to the default branch to set the baseline. |
| Soft-skip exit 0 (enrollment / rate limit) | Default soft-skip | Check the **warning** on the checks page and the job summary. Set `fail-on-skip: true` (or `fail-on-unenrolled` / `fail-on-rate-limit`) to fail instead. |
| No “new vs baseline” on first PR | No default-branch scan yet | Expected: comment still posts in absolute mode with a “No baseline yet” line. Scan the default branch once. |

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
