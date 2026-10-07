# Changelog

## [Unreleased]

### Added
- Action input **`fail-on-rate-limit`** (default `false`): when the hosted API
  returns HTTP 429 with `error: rate_limited`, the CLI writes `enrollment.json`
  (`status: rate_limited`, message, `retry_after`), exits like an enrollment
  soft-skip, and the Action emits a warning (or error when the input is true),
  a short job-summary note, and sets `skipped=true` / `skip_reason=rate_limited`.
  Independent of `fail-on-unenrolled`. No automatic retries.
- README **Limits** note: 30 scans per repository per hour and 100 per
  organization per day on the free plan.

## [0.5.5] — pending tag

### Added
- Action input **`fail-on-unenrolled`** (default `false`): when the hosted API
  rejects a scan because the GitHub App is not installed, this repository is
  not selected, or the installation is over the free-plan repo cap
  (`installation_inactive` / `repo_not_enrolled` / `installation_over_cap`),
  the Action emits a warning, writes the job summary, writes
  `enrollment.json`, sets `skipped=true` / `skip_reason=<code>` on the scan
  step, and skips SARIF / PR comment / payload artifact with exit 0.
  Set `fail-on-unenrolled: true` to fail the job instead.

### Changed
- Public docs and Action examples use **`https://api.getfray.dev`** as the hosted
  API URL. Guardrail (`scripts/check-public-docs.sh`) fails if a `*.run.app` URL
  appears in `README.md`, `docs/`, or `action.yml`.
- Composite Action `setup-go` pin: **v7.0.0** (was v6.5.0). CI workflows run on
  `ubuntu-26.04`; action pin-check covers workflows as well as `action.yml`.

## [0.5.4] — pending tag

### Changed
- Go language version in `go.mod` is **1.26** (was 1.22). Composite Action reads
  it via `setup-go` `go-version-file` and builds with `GOTOOLCHAIN=local` (no
  toolchain download at Action runtime).
- CI: `.github/workflows/test.yml` runs `go vet` + `go test` on push/PR
  (`workflow_dispatch` `runner` input for ubuntu-26.04 soak). Tag only when both
  **guardrails** and **test** are green.

## [0.5.3] — pending tag

### Fixed
- Composite Action: `setup-go` with `cache: false`. A `cache-dependency-path` under
  the Action checkout (outside `GITHUB_WORKSPACE`) is ignored, so the module cache
  never ran; dropping the go.sum staging step is not a speed regression.

## [0.5.2] — pending tag

### Fixed
- Module-input findings (the `·` attribute list) locate on the HCL attribute lines
  in both the PR comment and SARIF (span + relatedLocations), not the module header —
  so Code Scanning “new alerts in this PR” agrees with the gate.
- SARIF rules include `properties.tags: ["security"]` so `security-severity` counts.
- Composite Action: stage `go.sum` under `${{ runner.temp }}` before `setup-go` cache
  (Action path is outside `GITHUB_WORKSPACE`).

## [0.5.1] — 2026-09-30

### Security
- Fail-closed internal-identifier denylist (missing tool or search error fails CI/hook;
  never reports clean on error). CI hit output is masked to file:line + entry index
  only (no pattern or matched text).
- Pre-push hook runs gitleaks, denylist, and `action.yml` SHA-pin check (same as CI).

### Changed
- FR-025 PR prose: when rule context (`acls_disabled`) applies, the base explanation
  drops “or ACL” — ACLs are already covered by `why_here`.
- FR-007 `fix_here`: customer wording (“gives {process} access to {secret}”) instead of
  “authorizes this flow”.
- SARIF keeps tool `Fray` / upload category `fray`; open findings set
  `properties.security-severity` (high 7.5, medium 5.0, low 3.0) so Code Scanning’s
  default “check run failure” threshold (High or higher) matches the gate.
- Action third-party `uses:` pinned to full commit SHAs (Node 24 majors); CI fails
  if any `action.yml` `uses:` is unpinned.

## [0.5.0] — 2026-09-29

### Added
- Rule FR-027 companion support: element `purpose=audit_archive`, flow `authz_actions`
  (closed enum including DeleteObject, PutObject, BypassGovernanceRetention,
  DeleteObjectVersion, PutBucketVersioning, PutObjectLockConfiguration,
  PutObjectRetention, PutBucketPolicy, PutLifecycleConfiguration), and optional
  finding `evidence` strings for inbound writers.
- `authz_actions` case-insensitive glob matching (`*` / `?` anywhere); `*`, `s3:*`
  expand to the full enum. Absent when NotAction / Condition / bucket-policy-sourced
  (parser warning). Not part of flow ids.
- Rule schema `covers.attributes` and `inbound_writer` field for restates matching /
  audit-archive selection.
- Rule-authored `fix_here` / `why_here` / `context_when` on the wire (`api/v1`).
- `.gitleaks.toml` allowlist for the README example `key_fingerprint` only.

### Changed
- LLM advisory contract is observations-only (`m4-v5`); enrichments are rule-authored
  only. `FindingEnrichment.FixHere` replaces the generic Fix line when present.
- `object_lock` parser truth table: AWS `COMPLIANCE` → true; `GOVERNANCE` → absent
  (evidence `s3:BypassGovernanceRetention`); AWS enabled without default retention →
  absent; GCS `is_locked=true` → true; unlocked retention → absent; GCS no retention
  policy → `false`. Cloudflare R2 omits `object_lock` until lock/retention is parsed
  (FR-027 stays unverified on R2 archives).
- **Breaking:** purpose is no longer inferred from resource names. It is set from
  resource type (secret managers → `secrets`), plan relations (CloudTrail
  `s3_bucket_name` → `audit_archive`; S3 server-access-logging `target_bucket` /
  GCS logging sink destination → `logs`), or declared in `fray.yaml` — declare
  `purpose: audit_archive` (etc.) for buckets you want FR-027 to cover. Evidence
  records `purpose_source` as `type` | `relation` | `declared`.
- Authz grants remain multi-valued (`authz_grants`); effective scope stays on `authz_scope`.
- R2 service→bucket authz is derived from `cloudflare_api_token` /
  `cloudflare_account_token` policies in the plan: bucket resource keys
  (`com.cloudflare.edge.r2.bucket.…`) → `resource`; account keys
  (`com.cloudflare.api.account.…`) → `account`. When no token is in the plan,
  `authz_scope` is omitted and the parser warns (no blanket `resource` guess).
