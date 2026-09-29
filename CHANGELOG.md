# Changelog

## [0.5.0] — unreleased

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
- Purpose inference no longer maps bare `"api"` → `internal_api` (avoids labeling
  external control planes like "GitHub API").
- Authz grants remain multi-valued (`authz_grants`); effective scope stays on `authz_scope`.
- R2 service→bucket mechanical flows record `authz_scope=resource` when R2 key envs
  are present (so inbound_writer / FR-027 can see the writer).

### Notes for fray-server
After this tag is published, bump every `github.com/fluong/fray` require to `v0.5.0`
(`server/go.mod`, `schema/eval/go.mod`, `schema/check/go.mod`, `client/go.mod`) and
`go mod tidy`. Image builds copy `server/go.mod` only (no `go.work`); do not commit a
`replace` for the public module.
