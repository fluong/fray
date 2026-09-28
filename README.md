# Fray

Public client and scan API wire contract for [Fray](https://github.com/fluong/fray).

This repository ships:

- `client` — Terraform plan → DFD parser
- `render` — threat-model and PR-comment renderers
- `api/v1` — request/response types for `POST /v1/scans`
- `schema` — DFD / finding / config JSON Schemas and semantic validation
- `cmd/fray` — CLI that parses a plan and calls the hosted API (`-remote`)

Rule evaluation and the hosted service live in a private companion repository.
The public CLI never ships rules; build with `-remote` against a Fray API.

## Contributing

Copy paths from the private companion into this repo with an **explicit
allowlist only** — never a bulk `cp -R`. CI and the optional pre-push hook
(`git config core.hooksPath .githooks`) run gitleaks plus a denylist for
internal identifiers.

## License

Apache-2.0. See [LICENSE](LICENSE) and `testdata/aws-web-app/NOTICE` for the
demo Terraform fixture’s third-party module attributions.
