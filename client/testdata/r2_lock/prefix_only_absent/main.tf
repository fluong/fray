# Fixture: prefix_only_absent — prefix-scoped lock → object_lock absent
terraform {
  required_providers { cloudflare = { source = "cloudflare/cloudflare" } }
}
resource "cloudflare_r2_bucket" "archive" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name       = "archive"
}
resource "cloudflare_r2_bucket_lock" "archive" {
  account_id  = cloudflare_r2_bucket.archive.account_id
  bucket_name = cloudflare_r2_bucket.archive.name
  rules = [{
    id = "logs"
    enabled = true
    prefix = "logs/"
    condition = { type = "Indefinite" }
  }]
}
