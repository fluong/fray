# bucket_audit fixtures

Minimal Terraform shapes for S3 `attributes.audit_logging` when
`audit_config: owned_by_this_root`. Unit tests in `client/aws_bucket_audit_test.go`
synthesize plan values; they do not run `terraform plan`.

Expected attribute outcome is in the directory name suffix: `_true`, `_false`, `_absent`.
