# Changelog

## [Unreleased]

## [0.29.1] — 2026-10-15

### Fixed
- Client: plain S3 buckets without an SSE configuration now report
  `customer_managed_key=false` instead of omitting it (AWS provider v4+
  marks the legacy inline attribute Optional+Computed).

## [0.29.0] — 2026-10-15

### Added
- Client: emit `customer_managed_key` for object storage (enables FR-036).
  FR-035 also evaluates on this Action version.

## [0.28.2] — 2026-10-15

### Added
- Schema: rule fields `from.`/`to.internet_reachable`,
  `to.attributes.tls_enforced`, `attributes.customer_managed_key`; rule
  operator `any_prefer_false`; DFD attribute `customer_managed_key`
  (emitted from a later release).
  Docs: FR-035, FR-036 rule pages.

## [0.28.1] — 2026-10-15

### Added
- Client: documented `tls_enforced` engine defaults for Aurora PostgreSQL /
  MySQL, MariaDB, and MySQL when the effective parameter group is the engine
  default (B-03). Databases on RDS MySQL, RDS MariaDB 11.4 and earlier, and
  Aurora PostgreSQL 16 and earlier that use the engine's default parameter
  group now report TLS as not enforced (previously unverified); expect these
  as new open findings after upgrading.

### Docs
- FR-014: note that Cloudflare R2 has no object versioning, so the rule is
  always unverified for R2 buckets.

## [0.28.0] — 2026-10-15

### Added
- Client: emit `provider_deletion_protection` for RDS/Aurora and Cloud SQL
  (enables FR-038).

## [0.27.2] — 2026-10-15

### Added
- Schema: new DFD attribute `provider_deletion_protection` (emitted from a
  later release). Docs: FR-038 rule page.

## [0.27.1] — 2026-10-14

### Changed
- Rule schema: accept `min_action` and remediation `catalog_text` / `catalog_explanation`.

## [0.27.0] — 2026-10-14

### Added
- Optional `stack` Action input / `-stack` CLI flag / `FRAY_STACK` for several
  Terraform roots in one repository. Each named stack gets its own PR comment,
  merge baseline, SARIF category (`fray/<stack>`), and artifact names. Empty
  `stack` keeps today’s behaviour.
- Requires the hosted service from 2026-10-14 or later for `stack` (older servers ignore it; without `stack` nothing changes).

### Changed
- `rule.schema.json`: `introduced` is a date (YYYY-MM-DD), matching the published rule catalog.

## [0.26.1] — 2026-10-14

### Fixed
- IAM policies attached with `aws_iam_policy_attachment` or the `*_exclusive`
  resources now count toward a role's permissions.
- A role named by a literal string in an IAM attachment (for example
  `role = "app-task"`) was ignored, which could understate its permissions.
  Such attachments now count; if the role's name is only known after apply,
  the scope is reported as unverified.

## [0.26.0] — 2026-10-14

### Added
- `findings.json` lists the Terraform addresses behind each finding.

### Fixed
- Subnets, launch templates, launch configurations and EKS clusters read through
  data sources now count (from the plan's prior state when resolved during planning).

## [0.25.1] — 2026-10-14

### Fixed
- Secrets in a root-module ECS task definition are now detected when the task definition is created in the same plan as the secret (read from the Terraform configuration).

## [0.25.0] — 2026-10-14

### Fixed
- S3 flows are now inferred for each ECS task definition (previously only when the plan had exactly one).
- `container_definitions` on root-module ECS task definitions are now read for secrets.

## [0.24.1] — 2026-10-13

### Fixed
- IAM policy documents that Terraform resolves during planning (`data.aws_iam_policy_document`
  with only literal values) are now read. Previously the grant could be shown as unverified or
  the finding left out (FR-004, FR-007, FR-032).
- Scans of Terraform that grants Bedrock access were rejected by the hosted service between
  v0.20.0 and v0.24.0; fixed on the service side, no upgrade required.

## [0.24.0] — 2026-10-13

### Added
- EKS managed node groups now appear in the diagram. FR-034 flags node groups with a
  public IP whose SSH/RDP is open to the internet — including remote access configured
  without source security groups, where AWS opens the port to 0.0.0.0/0.

## [0.23.0] — 2026-10-13

### Added
- Auto Scaling groups now appear in the diagram. FR-034 checks them using their launch
  template or launch configuration (public IP and security groups). When Fray can't tell
  which template version a group uses, the result is unverified.

### Fixed
- When Fray can't find where a finding comes from in your Terraform, the PR comment no
  longer repeats the resource address in place of the file and line.

## [0.22.1] — 2026-10-13

### Fixed
- EC2 instances that get their public IP or security groups from a launch template are now
  evaluated with those settings. Previously such an instance could be reported as having no
  public IP, so FR-034 could miss SSH or RDP open to the internet. When Fray can't tell which
  template version an instance uses, the result is unverified.

## [0.22.0] — 2026-10-13

### Added
- IAM permissions in inline role policies (`aws_iam_role_policy`, `inline_policy`) and in
  policies written as JSON (`jsonencode`) are now read for Secrets Manager, S3 and Bedrock.

### Fixed
- When an attached IAM policy can't be read from the plan, Fray no longer reports the role's
  access as narrower than it may be — the scope is shown as unverified.
- Secrets Manager and S3 grants that name a concrete secret or bucket with a trailing
  wildcard (`secret:name-*`, `arn:aws:s3:::bucket/*`) are now treated as resource-scoped,
  not account-wide. Exact ARNs that match a secret or bucket in the plan are also reported
  as resource-scoped (they were previously left without a scope).

## [0.21.0] — 2026-10-13

### Added
- Standalone EC2 instances (`aws_instance`) now appear in the diagram.
- FR-034 flags instances that have a public IP and a security group allowing SSH (22)
  or RDP (3389) from the internet. If Fray can't tell whether the instance has a
  public IP or what its security groups allow, the result is unverified.
- Limits: launch templates, Auto Scaling groups, route tables and network ACLs are not
  read yet.
- FR-034 needs this version or later; older versions list it as not evaluated.

## [0.20.0] — 2026-10-13

### Added
- AWS Bedrock: IAM grants that let an ECS task role or Lambda role invoke Bedrock models are shown as a model API in the diagram. FR-004 (model access scope) and FR-017 (processing region) now apply on AWS.
- The region is read from the model ARNs in the grant. A `global.` inference profile is reported as not pinned. When the region can't be determined, FR-017 is unverified.
- Limits: inline role policies, managed policies other than AmazonBedrockFullAccess, and EC2 instance roles are not read yet.
- FR-017 on AWS needs the current Fray service (already live).

### Fixed
- IAM policies attached in the root Terraform module are now read. Secrets Manager and S3 findings can change on plans that keep IAM in the root module.

## [0.19.0] — 2026-10-13

### Added
- The Action reports its version to the Fray service, which skips rules that need a newer Action instead of reporting them as unverified. Skipped rules are listed in the PR comment and job summary.

## [0.18.0] — 2026-10-13

### Added
- Google Cloud SQL instances are modelled as relational databases, so FR-029 (internet exposure), FR-030 (encryption at rest), FR-031 (TLS) and FR-033 (destroy protection) apply on Google Cloud. A public IP with no authorized networks counts as restricted (only the Cloud SQL connectors, which require IAM, can connect). Fray does not assume a default ssl_mode. FR-033 counts the Terraform deletion_protection argument, settings.deletion_protection_enabled or lifecycle.prevent_destroy.
- Cloud Run services attached to a Cloud SQL instance (cloud_sql_instance volume or the cloudsql-instances annotation) are connected to it over TLS.

## [0.17.0] — 2026-10-13

### Added
- AWS API Gateway (REST and HTTP/WebSocket) and Lambda function URLs are modelled as internet entry points, so FR-001 and FR-026 apply to them. An API is treated as anonymous if any method or route allows unauthenticated access; APIs that use custom (Lambda) authorizers, are defined by an OpenAPI body, have a resource policy, have no stage, or use private endpoints are not assumed to be public or authenticated.
- Lambda integrations behind API Gateway are shown as backend flows over TLS.

### Changed
- Load balancer listeners that require Cognito or OIDC authentication on every forwarding path now count as authenticated for FR-001 (mitigated instead of unverified). A listener rule that forwards without authentication makes the entry anonymous; rules that cannot be attributed to a listener leave the result unverified. Requires a Fray service that accepts the authenticated scope (the current service does).

## [0.16.1] — 2026-10-12

### Fixed
- PR comments and SARIF name the specific attribute for rules with any/all
  conditions (for example FR-029). Requires a Fray service that sends nested
  conditions; with older services the attribute is omitted.

## [0.16.0] — 2026-10-12

### Added
- Database TLS enforcement is read from RDS and Aurora parameter groups
  (rds.force_ssl, require_secure_transport), including groups created by
  modules. When no custom value is set, RDS for PostgreSQL 15 and later is
  treated as enforcing TLS and 14 and earlier as not; other engines are
  reported only when the parameter is set. Used by a new rule on the Fray
  service.
- Security groups passed through module outputs are resolved for load balancer
  and database exposure.

### Changed
- Cloudflare R2 audit logging is reported as unverified instead of open, since
  R2 Data Access Logs are enabled in the dashboard and are not visible in
  Terraform.

## [0.15.1] — 2026-10-12

Upgrading may change results on existing repositories; see "Changed".

### Changed
- On Google Cloud, Data Access audit configurations are recognised for the
  specific service, for allServices, and at folder and organization level when
  present in the plan.
- Audit configurations present in the plan always count. When none covers a
  Secret Manager secret, Cloud Storage bucket or S3 bucket, the result is open
  only if `audit_config: owned_by_this_root` is set; otherwise it is
  unverified. On Google Cloud, FR-006 and FR-023 may move from open to
  unverified.
- S3 server access logging and CloudTrail data-event coverage present in the
  plan now count even without `audit_config: owned_by_this_root`, so some
  FR-023 findings may move from unverified to mitigated.

## [0.15.0] — 2026-10-12

Upgrading may change results on existing repositories; see "Changed".

### Added
- Cloud Run secrets mounted as files are recognised as file delivery, so
  FR-003 can be mitigated. A secret that is also exposed as an environment
  variable is still reported as environment delivery.
- R2 bucket locks are read from Terraform: an enabled retention rule covering
  the whole bucket satisfies FR-027. Locks managed outside Terraform are
  reported as unverified.
- R2 buckets are reported as encrypted at rest.

### Changed
- Load balancer exposure uses the same security-group analysis as databases.
  Load balancers opened to the internet through aws_security_group_rule,
  security groups defined in another module, or prefix lists are now
  detected, so FR-001 may report new findings.
- S3 audit logging is credited only when a trail or logging configuration
  covers that specific bucket. Previously any trail with S3 data events
  counted for every bucket, so some FR-023 findings may move from mitigated
  to open or unverified.
- Databases behind for_each-style ingress rules open to the internet are now
  reported (FR-029 open instead of unverified).

### Fixed
- Load balancers whose exposure cannot be determined are no longer reported
  as private.
- Security-group ingress sources that are unknown at plan time are treated as
  unknown and are never outweighed by a resolved peer group. Direct
  references to security groups created in the same plan are still
  recognised as restricted.

## [0.14.0] — 2026-10-11

### Added
- SARIF `helpUri` and PR-comment rule ids link to the public rule catalog under
  [`docs/rules/`](docs/rules/README.md).

## [0.13.0] — 2026-10-11

### Added
- RDS/Aurora instances now report whether their security groups admit the internet
  (`network_restricted`); only the boolean leaves the runner.
- Rule schema operators `any` / `all` with `conds` (for nested pass predicates).

## [0.12.1] — 2026-10-11

### Fixed
- RDS instances that omit `deletion_protection` are now reported as not protected
  (the plan's false value is recorded) instead of unverified.

## [0.12.0] — 2026-10-11

### Added
- PR comments mark findings with `new_rule` (rules the baseline never evaluated)
  with “new rule; not blocking until the default branch is rescanned”.
- Waiver `rule` accepts platform-scoped ids (`FR-AWS-0001`) alongside `FR-0xx`.

## [0.11.0] — 2026-10-10

### Added
- Action input **`mode`**: `scan` (default) or `check`. `check` runs local setup
  checks (OIDC, `api-url`, config, waivers, `plan-file` or
  `terraform init -backend=false` + `validate`) plus **`GET /v1/readiness`** to
  verify GitHub App installation and repository enrollment — no scan submit, PR
  comment, SARIF, or gate.

## [0.10.1] — 2026-10-10

### Changed
- Generated-plan scans with no analysable resources now fail early with a clear
  message instead of an API validation error.
- Action scan step name is now the static **Fray scan** (id unchanged).

### Fixed
- PR comments with no open new/fixed findings always show a status-count summary
  line (including above Waivers), instead of a Waivers-only comment.

## [0.10.0] — 2026-10-10

### Added
- Action input **`plan-file`**: path (relative to `working-directory`) to a
  `terraform show -json` plan. Skips `setup-terraform` / `terraform init` /
  `plan` / `show`. Validates JSON (not binary/state), 32 MiB cap, managed
  `resource_changes`, plan↔source mismatch warning, and refuses an empty DFD
  before any API call. Docs: README **Bring your own plan**.

## [0.9.1] — pending tag

### Security
- **Hardening:** strip Terraform-marked sensitive plan values (`after_sensitive` /
  `sensitive_values`) before parsing; enforce a closed Element.Attributes
  allow-list (drop unknown keys / bad values); regression test that secrets do
  not appear in scan requests (redaction on and off).

## [0.9.0] — pending tag

### Added
- **[Getting started](docs/getting-started.md)** — shortest path to a first green
  scan; linked from the README.
- README **Troubleshooting** table (OIDC, enrollment, rate limits, redaction,
  Terraform, API, waivers, fork PRs, SARIF, gate, soft-skips).
- Action input **`fail-on-skip`** (default `false`): fail on any enrollment or
  rate-limit soft-skip. Soft-skips emit `::warning::` plus a prominent job
  summary; `fail-on-rate-limit` still works (also covered when `fail-on-skip`
  is true).
- First scan without a baseline always writes a PR comment in absolute mode
  with: `No baseline yet — comparison against the default branch starts after
  its first Fray scan.`

### Changed
- User-facing errors name the fix and link
  `https://github.com/fluong/fray#troubleshooting` (OIDC, workdir / missing
  `.tf` / `fray.yaml`, terraform init/plan wrapper, API failures, gate blocked,
  rate-limit free-plan limits).

## [0.8.1] — pending tag

### Fixed
- Don't upload waived findings to code scanning (GitHub does not honour SARIF
  suppressions; v0.8.0 re-opened waived alerts).

## [0.8.0] — pending tag

### Added
- SARIF **`partialFingerprints["fray/v1"]`**: sha256 hex of
  `<rule_id>|<cause Terraform address>` (falls back to `<rule_id>|<DFD id>`),
  stable across HCL line moves.
- SARIF driver metadata: `version` / `semanticVersion` and
  `informationUri` (`https://github.com/fluong/fray`). Per-rule `helpUri` is
  omitted until public docs have rule anchors.
- Action input **`upload-sarif`** (default `true`): set `false` to skip
  `github/codeql-action/upload-sarif` while still writing `findings.sarif`.
- Composite Action outputs **`has-sarif`** and **`sarif-file`**.
- After a failed SARIF upload (`continue-on-error`), a follow-up step emits
  `::warning::` reminding workflows to grant `security-events: write` and enable
  code scanning on private repos.

### Changed
- ~~SARIF included waived findings with SARIF `suppressions`.~~ **Reverted in
  0.8.1** — GitHub Code Scanning imports suppressed results as open alerts.
  Waived / mitigated / unverified / legacy `accepted` findings are omitted from
  SARIF so Code Scanning closes prior alerts as fixed; the accepted-risk record
  remains `.fray/waivers.yml`, the PR comment, and the Fray dashboard.

## [0.7.0] — pending tag

### Added
- **Waivers** (`.fray/waivers.yml`, `schema/waivers.schema.json`): accepted-risk
  register with `id` / `rule` / `address` / `reason` / `owner` / `expires`.
  Action input **`waivers-file`** (default `.fray/waivers.yml`). Client validates
  JSON Schema, 64 KiB / 200-entry caps, and the 365-day horizon; server remains
  authoritative (including the 90-day high-severity horizon). Wire uses the
  existing `accepted_mitigations` field with `{id, rule_id, target_id, expires}`
  only — reason, owner, and address never leave CI. PR comment and job summary
  render applied / new-in-PR / expiring-soon / expired / stale outcomes (or
  “server did not report waiver outcomes” on older APIs). Finding status enum
  includes **`waived`**.
- Action input **`fail-on-rate-limit`** (default `false`): when the hosted API
  returns HTTP 429 with `error: rate_limited`, the CLI writes `enrollment.json`
  (`status: rate_limited`, message, `retry_after`), exits like an enrollment
  soft-skip, and the Action emits a warning (or error when the input is true),
  a short job-summary note, and sets `skipped=true` / `skip_reason=rate_limited`.
  Independent of `fail-on-unenrolled`. No automatic retries.
- README **Limits** note: 30 scans per repository per hour and 100 per
  organization per day on the free plan.

### Changed
- **`mitigations.yaml` deprecated.** Non-empty files fail with a migration
  message (copy entries to `.fray/waivers.yml`, add `id`/`owner`/`expires`, drop
  `status: accepted`). Empty or missing files are ignored. `-mitigations` remains
  for one release as an alias that errors the same way when non-empty.
- PR comment “Accept this risk” snippet shows `.fray/waivers.yml` instead of
  `mitigations.yaml`.

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

[Unreleased]: https://github.com/fluong/fray/compare/v0.29.1...HEAD
[0.29.1]: https://github.com/fluong/fray/compare/v0.29.0...v0.29.1
[0.29.0]: https://github.com/fluong/fray/compare/v0.28.2...v0.29.0
[0.28.2]: https://github.com/fluong/fray/compare/v0.28.1...v0.28.2
[0.28.1]: https://github.com/fluong/fray/compare/v0.28.0...v0.28.1
[0.28.0]: https://github.com/fluong/fray/compare/v0.27.2...v0.28.0
[0.27.2]: https://github.com/fluong/fray/compare/v0.27.1...v0.27.2
[0.27.1]: https://github.com/fluong/fray/compare/v0.27.0...v0.27.1
[0.27.0]: https://github.com/fluong/fray/compare/v0.26.1...v0.27.0
[0.26.1]: https://github.com/fluong/fray/compare/v0.26.0...v0.26.1
[0.26.0]: https://github.com/fluong/fray/compare/v0.25.1...v0.26.0
[0.25.1]: https://github.com/fluong/fray/compare/v0.25.0...v0.25.1
[0.25.0]: https://github.com/fluong/fray/compare/v0.24.1...v0.25.0
[0.24.1]: https://github.com/fluong/fray/compare/v0.24.0...v0.24.1
[0.24.0]: https://github.com/fluong/fray/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/fluong/fray/compare/v0.22.1...v0.23.0
[0.22.1]: https://github.com/fluong/fray/compare/v0.22.0...v0.22.1
[0.22.0]: https://github.com/fluong/fray/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/fluong/fray/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/fluong/fray/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/fluong/fray/compare/v0.18.0...v0.19.0
