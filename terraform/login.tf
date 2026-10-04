# Demo login: HTML form backed by a simple username/password validator.
# Passwords are generated per user and live in local Terraform state; show them with `make tf-creds`.

resource "random_password" "demo_user" {
  for_each = var.demo_users

  length      = 16
  special     = false
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

resource "pingfederate_password_credential_validator" "demo" {
  validator_id = "biscuitDemoPCV"
  name         = "Biscuit demo users"

  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }
  attribute_contract = {}
  configuration = {
    tables = [{
      name = "Users"
      rows = [
        for user in sort(tolist(var.demo_users)) : {
          default_row = false
          fields = [
            { name = "Username", value = user },
            { name = "Relax Password Requirements", value = "false" },
          ]
          sensitive_fields = [
            { name = "Password", value = random_password.demo_user[user].result },
            { name = "Confirm Password", value = random_password.demo_user[user].result },
          ]
        }
      ]
    }]
  }
}

resource "pingfederate_idp_adapter" "html_form" {
  adapter_id = "biscuitHTMLForm"
  name       = "Biscuit demo HTML form"

  plugin_descriptor_ref = {
    id = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
  }
  configuration = {
    fields = [
      { name = "Challenge Retries", value = "3" },
      { name = "Session State", value = "None" },
      { name = "Login Template", value = "html.form.login.template.html" },
      { name = "Allow Password Changes", value = "false" },
      { name = "Enable 'Remember My Username'", value = "false" },
    ]
    tables = [{
      name = "Credential Validators"
      rows = [{
        default_row = false
        fields = [{
          name  = "Password Credential Validator Instance"
          value = pingfederate_password_credential_validator.demo.validator_id
        }]
      }]
    }]
  }
  attribute_contract = {
    core_attributes = [
      { name = "policy.action", pseudonym = false, masked = false },
      { name = "username", pseudonym = true, masked = false },
    ]
    unique_user_key_attribute = "username"
  }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      "policy.action" = { source = { type = "ADAPTER" }, value = "policy.action" }
      username        = { source = { type = "ADAPTER" }, value = "username" }
    }
  }
}

# Persistent grant: who the authorization code / refresh token belongs to.
resource "pingfederate_oauth_idp_adapter_mapping" "html_form" {
  mapping_id = pingfederate_idp_adapter.html_form.adapter_id
  attribute_contract_fulfillment = {
    USER_KEY  = { source = { type = "ADAPTER" }, value = "username" }
    USER_NAME = { source = { type = "ADAPTER" }, value = "username" }
  }
}
