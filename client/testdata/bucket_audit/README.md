# bucket_audit fixtures

Minimal Terraform shapes for S3 `attributes.audit_logging`. Unit tests in
`client/aws_bucket_audit_test.go` synthesize plan values; they do not run
`terraform plan`.

Logging or a covering CloudTrail data-event selector sets `audit_logging: true`
regardless of `audit_config`. `owned_by_this_root` only decides whether missing
evidence is `false` or omitted (unverified).

Expected attribute outcome is in the directory name suffix: `_true`, `_false`, `_absent`.
