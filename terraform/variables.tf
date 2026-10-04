variable "pf_admin_url" {
  description = "PingFederate admin API base URL, as reached from the terraform container."
  type        = string
  default     = "https://pingfederate:9999"
}

variable "pf_admin_user" {
  description = "Admin API user for the restapi provider (set from PF_ADMIN_USER)."
  type        = string
  default     = "administrator"
}

variable "pf_admin_password" {
  description = "Admin API password for the restapi provider (set from PF_ADMIN_PASSWORD)."
  type        = string
  sensitive   = true
}

variable "pf_runtime_url" {
  description = "PingFederate runtime base URL as seen from the browser."
  type        = string
  default     = "https://localhost:9031"
}

variable "demo_users" {
  description = "Usernames for the HTML form login. Passwords are generated; see `make tf-creds`."
  type        = set(string)
  default     = ["alice", "bob"]
}

variable "client_id" {
  description = "OAuth client used for the HTML form login and the token exchange."
  type        = string
  default     = "orders-web"
}

variable "redirect_uris" {
  description = "Redirect URIs for the authorization code flow."
  type        = list(string)
  default     = ["http://localhost:8090/callback"]
}

variable "scopes" {
  description = "OAuth scopes; each becomes a scope(...) fact in the Biscuit."
  type        = map(string)
  default = {
    "orders:read"  = "Read orders"
    "orders:write" = "Create and change orders"
  }
}

variable "biscuit_root_private_key" {
  description = "Hex Ed25519 private key for the Biscuit generator (written by `make tf-keys`)."
  type        = string
  sensitive   = true
}

variable "biscuit_root_public_key" {
  description = "Matching public key (ed25519/<hex>) handed to verifying services."
  type        = string
}

variable "biscuit_root_key_id" {
  description = "Root key ID written into each Biscuit so verifiers can rotate keys."
  type        = number
  default     = 1
}

variable "biscuit_audiences" {
  description = "Audiences the Biscuit is valid for."
  type        = list(string)
  default     = ["orders-api"]
}

variable "biscuit_lifetime_seconds" {
  description = "Biscuit lifetime in seconds."
  type        = number
  default     = 300
}
