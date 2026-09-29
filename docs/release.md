# Release checklist (public `fray`)

## Before every push to a shared branch

1. Install the local guardrails hook once per clone:

   ```bash
   ./scripts/install-hooks.sh
   ```

   This sets `core.hooksPath=.githooks`. The pre-push hook runs **gitleaks** and
   `scripts/check-internal-identifiers.sh` (same script as CI) and **refuses the
   push** on a hit. The denylist scans the whole tree, including `*_test.go`.

2. Or run the checks yourself:

   ```bash
   gitleaks detect --source . --log-opts='--all' --verbose --no-banner
   ./scripts/check-internal-identifiers.sh
   go test ./...
   ```

## Tagging a release

1. Date the `[x.y.z]` section in `CHANGELOG.md`; drop any “(pending tag)” wording
   in `README.md`.
2. Push `main`; wait for the **guardrails** workflow to pass.
3. Annotated tag and push:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. In fray-server, bump every `github.com/fluong/fray` require to the new tag and
   `go mod tidy` (see CHANGELOG notes).

## Copying from fray-server

Use an **explicit allowlist only** — never a bulk copy. Do not land private
fixtures, plans, or goldens here. The denylist exists because of
fray-server/docs/incidents/2026-09-28-public-fixtures.md (T28).
