# Fixture: eu_jurisdiction_mismatch_absent — lock default vs bucket eu → no match → absent
terraform {
  required_providers { cloudflare = { source = "cloudflare/cloudflare" } }
}
resource "cloudflare_r2_bucket" "archive" {
  account_id   = "023e105f4ecef8ad9ca31a8372d0c353"
  name         = "archive"
  jurisdiction = "eu"
}
resource "cloudflare_r2_bucket_lock" "archive" {
  account_id  = cloudflare_r2_bucket.archive.account_id
  bucket_name = cloudflare_r2_bucket.archive.name
  # jurisdiction unset (= default) does not match bucket eu
  rules = [{
    id = "all"
    enabled = true
    condition = { type = "Indefinite" }
  }]
}
