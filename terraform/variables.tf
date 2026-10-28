variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "admin_email" {
  type        = string
  description = "The only human allowed to invoke the service (roles/run.invoker)"
}
variable "image" {
  type        = string
  default     = ""
  description = "Container image. Empty on the first (foundation-only) apply."
}
variable "model" {
  type    = string
  default = "gemini-2.5-flash"
}
variable "daily_budget_usd" {
  type        = number
  default     = 0.5
  description = "Daily model-spend cap; above it the service falls back to rules-only reviews"
}
