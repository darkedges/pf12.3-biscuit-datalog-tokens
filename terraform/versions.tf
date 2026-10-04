terraform {
  required_version = ">= 1.9.0"

  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "= 1.10.0"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = "= 3.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.9.1"
    }
  }
}

# Credentials come from PINGFEDERATE_PROVIDER_USERNAME / PINGFEDERATE_PROVIDER_PASSWORD
# (set by the terraform service in docker-compose.yaml). The local admin API uses a
# self-signed certificate.
provider "pingfederate" {
  https_host             = var.pf_admin_url
  product_version        = "12.3"
  insecure_trust_all_tls = true
}

# The pingfederate provider has no resources for SP token generators or token exchange
# generator groups, so those two objects are managed directly through the Admin API.
provider "restapi" {
  uri                   = "${var.pf_admin_url}/pf-admin-api/v1"
  username              = var.pf_admin_user
  password              = var.pf_admin_password
  insecure              = true
  write_returns_object  = true
  create_returns_object = true
  update_method         = "PUT"
  id_attribute          = "id"
  headers = {
    "X-XSRF-Header" = "PingFederate"
    "Content-Type"  = "application/json"
  }
}
