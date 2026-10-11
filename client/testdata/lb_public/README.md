# lb_public fixtures

Each directory is a minimal Terraform shape for ALB `attributes.public` cases.
Unit tests in `client/aws_lb_public_test.go` synthesize the plan values these
configurations produce; they do not run `terraform plan` here.

Expected `attributes.public` is in the directory name suffix: `_true`, `_false`, `_absent`,
or `_world` (public=true via world ingress on a listener port).
