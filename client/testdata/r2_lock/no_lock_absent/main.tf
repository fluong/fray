# Fixture: no_lock_absent — object_lock absent (locks may exist outside this root)
terraform {
  required_providers { cloudflare = { source = "cloudflare/cloudflare" } }
}
resource "cloudflare_r2_bucket" "archive" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name       = "archive"
}
