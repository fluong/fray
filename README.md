# Fray

Public client, GitHub Action, and scan API wire contract for Fray.

This repository ships:

- `client` — Terraform plan → DFD parser (with default-on HMAC redaction)
- `render` — threat-model, PR-comment, and SARIF renderers
- `api/v1` — request/response types for `POST /v1/scans`
- `schema` — DFD / finding / config JSON Schemas and semantic validation
- `cmd/fray` — CLI that parses a plan and calls the hosted API (`-remote`)
- Composite Action (`action.yml`) — OIDC-authenticated scan from GitHub Actions

Rule evaluation and the hosted service live in a private companion repository.
The public CLI never ships rules; build with `-remote` against a Fray API.

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

      - uses: fluong/fray@v0.2.3
        with:
          api-url: ${{ vars.FRAY_API_URL }}   # required; do not hardcode in the Action repo
          working-directory: infra
          config: fray.yaml
          redaction-key: ${{ secrets.FRAY_REDACTION_KEY }}
          show-payload: true   # optional: upload the sent JSON as fray-payload
```

Auth is GitHub Actions OIDC with audience `fray` — there is no API-key input.
Fork pull requests cannot mint that token: the Action emits a warning annotation
and a job-summary line stating Fray did not run (never a silent pass).

The Action updates a single PR comment in place (hidden `<!-- fray -->` marker),
uploads SARIF via `github/codeql-action/upload-sarif`, and exits non-zero when
the merge gate blocks.

## CLI

```bash
go install github.com/fluong/fray/cmd/fray@v0.2.3

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
```

`-branch` and `-default-branch` are local only: the POST body carries
`is_default_branch`, not branch names. Exit `1` when the gate blocks; exit `2`
on usage or transport errors.

## Contributing

Copy paths from the private companion into this repo with an **explicit
allowlist only** — never a bulk `cp -R`. CI and the optional pre-push hook
(`git config core.hooksPath .githooks`) run gitleaks plus a denylist for
internal identifiers. Do not commit a hosted API URL into this repository;
pass it as the Action `api-url` input (or `vars.FRAY_API_URL` in consumers).

## License

Apache-2.0. See [LICENSE](LICENSE) and `testdata/aws-web-app/NOTICE` for the
demo Terraform fixture’s third-party module attributions.
