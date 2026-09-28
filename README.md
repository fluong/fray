# Fray

Public client, GitHub Action, and scan API wire contract for Fray.

Parse a Terraform plan into a data-flow diagram (DFD), send it to the hosted
scan API, and get STRIDE findings plus a merge gate back. Rule evaluation and
the hosted service live in a private companion repository — this repo never
ships rules.

Latest release: **v0.3.1**. `v0.1.0` is retracted (non-public fixtures leaked
into the module zip; see `go.mod`).

Related:

- Hosted API / rules — private companion (`fray-server`)
- [fluong/fray-demo-aws](https://github.com/fluong/fray-demo-aws) — AWS demo wired to the Action

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
| `scripts/` | Internal-identifier denylist for the public tree |
| `.githooks/` | Optional pre-push (gitleaks + denylist) |

## What leaves your CI

Redaction is **on by default**. Before Fray receives a scan, the client replaces
resource names, Terraform addresses, signal names, declared keys/paths, and the
`source.repo` string with HMAC-SHA256 digests under a key that only you hold
(`FRAY_REDACTION_KEY`). Element and flow ids are re-derived from those digests.
The key never leaves CI.

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
    "key_fingerprint": "a1b2c3d4e5f60718"
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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: fluong/fray@v0.3.1
        with:
          api-url: ${{ vars.FRAY_API_URL }}   # required; do not hardcode in this repo
          working-directory: infra
          config: fray.yaml
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
          show-payload: true   # optional: upload the sent JSON as fray-payload
```

| Input | Default | Notes |
|-------|---------|-------|
| `api-url` | — | Required. Pass via `vars.FRAY_API_URL` in consumers. |
| `working-directory` | `.` | Terraform root (contains `.tf` sources). |
| `config` | `fray.yaml` | Path relative to the workspace. |
| `redaction-key` | `""` | Required unless `fray.yaml` sets `redaction: off`. |
| `show-payload` | `false` | Upload `payload.json` as the `fray-payload` artifact. |

Auth is GitHub Actions OIDC with audience `fray` — there is no API-key input.
Fork pull requests cannot mint that token: the Action emits a warning annotation
and a job-summary line stating Fray did not run (never a silent pass).

On each run the Action:

1. `terraform init` + `plan` + `show -json` in `working-directory`
2. Scans via OIDC (`aud=fray`)
3. Updates a single PR comment in place (hidden `<!-- fray -->` marker)
4. Uploads SARIF via `github/codeql-action/upload-sarif` (category `fray`)
5. Exits non-zero when the merge gate blocks

`mitigations.yaml` at the repo root is used when present; otherwise the Action
writes an empty dispositions file for the CLI.

## CLI

```bash
go install github.com/fluong/fray/cmd/fray@v0.3.1

export FRAY_REDACTION_KEY="$(openssl rand -hex 32)"

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
| `-remote` | API base URL (required) |
| `-oidc-token` / `FRAY_OIDC_TOKEN` | Actions OIDC JWT (preferred in CI) |
| `-api-key` / `FRAY_API_KEY` | Org API key (local smoke only; cannot write default-branch baseline) |
| `-default-branch` / `-branch` | Local only — POST body carries `is_default_branch`, not names |
| `-base-commit` / `-base-source` | PR base sha + sources for module-arg attribution |
| `-out` | Writes `findings.json`, `findings.sarif`, `threat-model.md`, `pr-comment.md` |

Exit `1` when the gate blocks; exit `2` on usage or transport errors.

## Config

Minimal `fray.yaml` (redaction on by default — omit `redaction`):

```yaml
schema_version: fray-config/v1
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
go test ./...
```

CI (`.github/workflows/guardrails.yml`) and the optional pre-push hook
(`git config core.hooksPath .githooks`) run gitleaks plus
`scripts/check-internal-identifiers.sh`.

## Contributing

Copy paths from the private companion into this repo with an **explicit
allowlist only** — never a bulk `cp -R`. Do not commit a hosted API URL into
this repository; pass it as the Action `api-url` input (or `vars.FRAY_API_URL`
in consumers). Do not land fray-server fixtures, plans, or goldens here.

## License

Apache-2.0. See [LICENSE](LICENSE) and `testdata/aws-web-app/NOTICE` for the
demo Terraform fixture’s third-party module attributions.
