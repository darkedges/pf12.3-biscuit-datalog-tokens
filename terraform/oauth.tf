# OAuth: scopes, a JWT access token manager, the HTML form -> access token mapping, and the client.

# Singleton: these are the server-wide authorization server settings.
resource "pingfederate_oauth_server_settings" "this" {
  authorization_code_timeout = 60
  authorization_code_entropy = 30
  refresh_token_length       = 42
  refresh_rolling_interval   = 0
  scopes = [
    for name, description in var.scopes : {
      name        = name
      description = description
      dynamic     = false
    }
  ]
}

# HS256 key; with a blank "Encoding" PingFederate expects the key as hex.
resource "random_bytes" "atm_signing_key" {
  length = 32
}

resource "pingfederate_oauth_access_token_manager" "jwt" {
  manager_id = "biscuitJwtAtm"
  name       = "Biscuit demo JWT access tokens"

  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }
  configuration = {
    fields = [
      { name = "Token Lifetime", value = "60" },
      { name = "JWS Algorithm", value = "HS256" },
      { name = "Active Symmetric Key ID", value = "k1" },
      { name = "Issuer Claim Value", value = var.pf_runtime_url },
      { name = "JWT ID Claim Length", value = "22" },
    ]
    tables = [{
      name = "Symmetric Keys"
      rows = [{
        default_row = false
        fields = [
          { name = "Key ID", value = "k1" },
          { name = "Encoding", value = "" },
        ]
        sensitive_fields = [
          { name = "Key", value = random_bytes.atm_signing_key.hex },
        ]
      }]
    }]
  }
  attribute_contract = {
    extended_attributes = [
      { name = "username", multi_valued = false },
    ]
  }
  access_control_settings = {
    restrict_clients = false
  }
  session_validation_settings = {
    check_valid_authn_session       = false
    check_session_revocation_status = false
    update_authn_session_activity   = false
    include_session_id              = false
  }
}

# Authorization code flow via the HTML form: put the username in the access token.
resource "pingfederate_oauth_access_token_mapping" "html_form" {
  access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.jwt.manager_id
  }
  context = {
    type = "IDP_ADAPTER"
    context_ref = {
      id = pingfederate_idp_adapter.html_form.adapter_id
    }
  }
  attribute_contract_fulfillment = {
    username = { source = { type = "ADAPTER" }, value = "username" }
  }

  depends_on = [pingfederate_oauth_idp_adapter_mapping.html_form]
}

resource "random_password" "client_secret" {
  length  = 40
  special = false
}

resource "pingfederate_oauth_client" "orders_web" {
  client_id   = var.client_id
  name        = "Orders web (Biscuit demo)"
  description = "Logs users in with the HTML form, then exchanges its access token for a Biscuit."
  enabled     = true
  grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN", "TOKEN_EXCHANGE"]

  client_auth = {
    type   = "SECRET"
    secret = random_password.client_secret.result
  }

  redirect_uris                       = var.redirect_uris
  restrict_scopes                     = true
  restricted_scopes                   = keys(var.scopes)
  require_proof_key_for_code_exchange = false
  bypass_approval_page                = true

  default_access_token_manager_ref = {
    id = pingfederate_oauth_access_token_manager.jwt.manager_id
  }
  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.biscuit.policy_id
  }

  depends_on = [pingfederate_oauth_server_settings.this]
}
