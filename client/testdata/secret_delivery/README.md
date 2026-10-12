# secret_delivery fixtures

Each directory is a minimal Terraform shape for Cloud Run
`secret_delivery` cases (`env` vs `volume`). Unit tests in
`client/parse_test.go` (`TestCloudRunSecretDelivery`) synthesize the plan
values these configurations produce; they do not run `terraform plan` here.

Expected delivery is in the directory name: `volume_only`, `env_only`,
`both_env` (env wins), `declared_not_mounted` (no flow),
`two_containers_mixed` (env wins).
