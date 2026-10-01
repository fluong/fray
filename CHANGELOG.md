# Changelog

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
