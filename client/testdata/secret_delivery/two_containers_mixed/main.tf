# Fixture: two_containers_mixed — one container mounts, another injects env → secret_delivery=env (FR-003 open)
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
      volume_mounts { name = "secvol"; mount_path = "/secrets" }
    }
    containers {
      image = "gcr.io/x/y@sha256:def"
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
