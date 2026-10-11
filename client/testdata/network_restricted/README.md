# network_restricted fixtures

Each directory is a minimal Terraform shape for one STEP 0 §4 row (plus extras).
Unit tests in `client/aws_network_restricted_test.go` synthesize the plan values these
configurations produce; they do not run `terraform plan` here (provider/init cost).

Expected `attributes.network_restricted` is in the directory name suffix: `_true`, `_false`, `_absent`.
