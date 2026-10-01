# Release checklist (public `fray`)

## Before every push to a shared branch

1. Install the local guardrails hook once per clone:

   ```bash
   ./scripts/install-hooks.sh
   ```

   This sets `core.hooksPath=.githooks`. The pre-push hook runs **actionlint**,
   **gitleaks**, `scripts/check-internal-identifiers.sh`,
   `scripts/check-action-pins.sh`, and `scripts/check-public-docs.sh` (same as CI)
   and **refuses the push** on a hit. The denylist scans the whole tree, including
   `*_test.go`.

2. Provide the denylist patterns (not stored in this public repo). Locally:
   `FRAY_DENYLIST` env, else `~/.config/fray/denylist` (one ERE pattern per
   line). CI reads the repository secret `FRAY_DENYLIST` only and **fails
   closed** if it is missing or empty.

3. Or run the checks yourself:

   ```bash
   actionlint
   gitleaks detect --source . --log-opts='--all' --verbose --no-banner
   ./scripts/check-internal-identifiers.sh
   ./scripts/check-action-pins.sh
   ./scripts/check-public-docs.sh
   go test ./...
   ```

## Tagging a release

1. Date the `[x.y.z]` section in `CHANGELOG.md`; drop any “(pending tag)” wording
   in `README.md`.
2. Push `main`; wait for both the **guardrails** and **test** workflows to pass
   on that commit.
3. Annotated tag and push:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. In the private companion, bump every `github.com/fluong/fray` require to the new
   tag and `go mod tidy` (see that repo’s `docs/release.md`).

## Copying from the private companion

Use an **explicit allowlist only** — never a bulk copy. Do not land private
fixtures, plans, or goldens here. The denylist exists because of a prior public
fixture leak (T28 / companion `docs/incidents/`).
