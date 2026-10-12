# Fixture: declared_not_mounted — volume declared but not mounted → no credentials flow
terraform {
  required_providers { google = { source = "hashicorp/google" } }
}
resource "google_secret_manager_secret" "app" { secret_id = "app-secret" replication { auto {} } }
resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "us-central1"
  template {
    volumes {
      name = "secvol"
      secret {
        secret = google_secret_manager_secret.app.secret_id
        items { path = "token"; version = "latest" }
      }
    }
    containers {
      image = "gcr.io/x/y@sha256:abc"
    }
  }
}
