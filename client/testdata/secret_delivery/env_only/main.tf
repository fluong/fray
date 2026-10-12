# Fixture: env_only — secret_delivery=env (FR-003 open)
terraform {
  required_providers { google = { source = "hashicorp/google" } }
}
resource "google_secret_manager_secret" "app" { secret_id = "app-secret" replication { auto {} } }
resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "us-central1"
  template {
    containers {
      image = "gcr.io/x/y@sha256:abc"
      env {
        name = "TOK"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.app.secret_id
            version = "latest"
          }
        }
      }
    }
  }
}
