# Fixture: two_buckets_other_absent — lock on archive only; other → object_lock absent
terraform {
  required_providers { cloudflare = { source = "cloudflare/cloudflare" } }
}
resource "cloudflare_r2_bucket" "archive" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name       = "archive"
}
resource "cloudflare_r2_bucket" "other" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  name       = "other"
}
resource "cloudflare_r2_bucket_lock" "archive" {
  account_id  = cloudflare_r2_bucket.archive.account_id
  bucket_name = cloudflare_r2_bucket.archive.name
  rules = [{
    id = "all"
    enabled = true
    condition = { type = "Indefinite" }
  }]
}
