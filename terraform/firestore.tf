# Named database so this stack never touches (default), which other stacks in the project may use.
resource "google_firestore_database" "reviews" {
  name                    = "planreview"
  location_id             = var.region
  type                    = "FIRESTORE_NATIVE"
  deletion_policy         = "DELETE"
  delete_protection_state = "DELETE_PROTECTION_DISABLED"
  depends_on              = [google_project_service.api]
}

resource "google_firestore_field" "review_ttl" {
  database   = google_firestore_database.reviews.name
  collection = "reviews"
  field      = "expires_at"
  ttl_config {}
  index_config {}
}
resource "google_firestore_field" "meta_ttl" {
  database   = google_firestore_database.reviews.name
  collection = "meta"
  field      = "expires_at"
  ttl_config {}
  index_config {}
}
