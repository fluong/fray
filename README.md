# Fray

Public client, GitHub Action, and scan API wire contract for Fray.

This repository ships:

- `client` — Terraform plan → DFD parser
- `render` — threat-model, PR-comment, and SARIF renderers
- `api/v1` — request/response types for `POST /v1/scans`
- `schema` — DFD / finding / config JSON Schemas and semantic validation
- `cmd/fray` — CLI that parses a plan and calls the hosted API (`-remote`)
- Composite Action (`action.yml`) — OIDC-authenticated scan from GitHub Actions

Rule evaluation and the hosted service live in a private companion repository.
The public CLI never ships rules; build with `-remote` against a Fray API.

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

      - uses: fluong/fray@v0.2.1
        with:
          api-url: ${{ vars.FRAY_API_URL }}   # required; do not hardcode in the Action repo
          working-directory: infra
          config: fray.yaml
```

Auth is GitHub Actions OIDC with audience `fray` — there is no API-key input.
Fork pull requests cannot mint that token: the Action emits a warning annotation
and a job-summary line stating Fray did not run (never a silent pass).

The Action updates a single PR comment in place (hidden `<!-- fray -->` marker),
uploads SARIF via `github/codeql-action/upload-sarif`, and exits non-zero when
the merge gate blocks.

## CLI

```bash
go install github.com/fluong/fray/cmd/fray@v0.2.1

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
```

Exit `1` when the gate blocks; exit `2` on usage or transport errors.

## Contributing

Copy paths from the private companion into this repo with an **explicit
allowlist only** — never a bulk `cp -R`. CI and the optional pre-push hook
(`git config core.hooksPath .githooks`) run gitleaks plus a denylist for
internal identifiers. Do not commit a hosted API URL into this repository;
pass it as the Action `api-url` input (or `vars.FRAY_API_URL` in consumers).

## License

Apache-2.0. See [LICENSE](LICENSE) and `testdata/aws-web-app/NOTICE` for the
demo Terraform fixture’s third-party module attributions.
