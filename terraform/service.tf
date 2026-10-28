data "google_project" "this" {}

resource "google_service_account" "app" {
  account_id   = "pr-app"
  display_name = "plan-review runtime"
}
resource "google_project_iam_member" "app_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.app.email}"
}
resource "google_project_iam_member" "app_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.app.email}"
  condition {
    title      = "only-planreview-database"
    expression = "resource.name == 'projects/${var.project_id}/databases/planreview'"
  }
}
resource "google_project_iam_member" "app_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_cloud_run_v2_service" "app" {
  count               = var.image != "" ? 1 : 0
  name                = "plan-review"
  location            = var.region
  deletion_protection = false
  labels              = { env = "demo", owner = "platform" }
  template {
    service_account                  = google_service_account.app.email
    timeout                          = "120s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      startup_probe {
        http_get { path = "/healthz" }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "PLANREVIEW_LLM"
        value = "vertex"
      }
      env {
        name  = "PLANREVIEW_MODEL"
        value = var.model
      }
      env {
        name  = "PLANREVIEW_ALLOWED_PROVIDERS"
        value = "vertex,none"
      }
      env {
        name  = "PLANREVIEW_STORE"
        value = "firestore"
      }
      env {
        name  = "PLANREVIEW_FIRESTORE_DB"
        value = google_firestore_database.reviews.name
      }
      env {
        name  = "PLANREVIEW_DAILY_BUDGET_USD"
        value = tostring(var.daily_budget_usd)
      }
    }
  }
  depends_on = [
    google_project_iam_member.app_vertex,
    google_project_iam_member.app_firestore,
  ]
}

# Private: only the admin may invoke. No allUsers binding.
resource "google_cloud_run_v2_service_iam_member" "admin_invoker" {
  count    = var.image != "" ? 1 : 0
  name     = google_cloud_run_v2_service.app[0].name
  location = var.region
  role     = "roles/run.invoker"
  member   = "user:${var.admin_email}"
}
