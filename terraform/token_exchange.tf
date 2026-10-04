# Token exchange: PF access token (subject_token) -> Biscuit.
#
#   processor (validates the JWT with the ATM that issued it)
#     -> processor policy (subject, client_id, scope)
#       -> generator mapping -> Biscuit token generator
#   generator group: requested_token_type urn:darkedges:params:oauth:token-type:biscuit -> Biscuit generator

locals {
  biscuit_token_type   = "urn:darkedges:params:oauth:token-type:biscuit"
  biscuit_generator_id = "biscuit"
}

resource "pingfederate_idp_token_processor" "access_token" {
  processor_id = "biscuitAccessTokenProcessor"
  name         = "Biscuit demo access token processor"

  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor"
  }
  configuration = {
    fields = [
      { name = "Access Token Manager", value = pingfederate_oauth_access_token_manager.jwt.manager_id },
      { name = "Scope value as single string", value = "true" },
    ]
  }
  attribute_contract = {
    core_attributes = [
      { name = "aud" },
      { name = "authorization_details" },
      { name = "client_id" },
      { name = "expires_at" },
      { name = "iss" },
      { name = "scope" },
    ]
    extended_attributes = [
      { name = "username" },
    ]
  }
}

resource "pingfederate_oauth_token_exchange_processor_policy" "biscuit" {
  policy_id            = "biscuitExchange"
  name                 = "Access token to Biscuit"
  actor_token_required = false

  # "subject" is a built-in core attribute of every processor policy.
  attribute_contract = {
    extended_attributes = [
      { name = "client_id" },
      { name = "scope" },
    ]
  }

  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
    subject_token_processor = { id = pingfederate_idp_token_processor.access_token.processor_id }
    attribute_contract_fulfillment = {
      subject   = { source = { type = "SUBJECT_TOKEN" }, value = "username" }
      client_id = { source = { type = "SUBJECT_TOKEN" }, value = "client_id" }
      scope     = { source = { type = "SUBJECT_TOKEN" }, value = "scope" }
    }
  }]
}

# --- Admin API objects the provider doesn't cover ---------------------------------------

resource "restapi_object" "biscuit_generator" {
  path      = "/sp/tokenGenerators"
  object_id = local.biscuit_generator_id

  data = jsonencode({
    id   = local.biscuit_generator_id
    name = "Biscuit token generator"
    pluginDescriptorRef = {
      id = "com.darkedges.pingfederate.biscuit.BiscuitTokenGenerator"
    }
    configuration = {
      fields = [
        { name = "Root Private Key", value = var.biscuit_root_private_key },
        { name = "Root Key ID", value = tostring(var.biscuit_root_key_id) },
        { name = "Issuer", value = var.pf_runtime_url },
        { name = "Token Lifetime (seconds)", value = tostring(var.biscuit_lifetime_seconds) },
        { name = "Audiences", value = join(",", var.biscuit_audiences) },
        { name = "Fact Attributes", value = "subject,client_id,scope" },
      ]
    }
    attributeContract = {
      coreAttributes     = [{ name = "subject" }]
      extendedAttributes = [{ name = "client_id" }, { name = "scope" }]
    }
  })

  # PF adds location/lastModified, returns the private key as encryptedValue instead of value,
  # and treats the extended contract as an unordered set. None of that is drift; changes made
  # in this file are still applied.
  ignore_server_additions = true
  ignore_changes_to       = ["configuration.fields", "attributeContract.extendedAttributes"]
}

resource "restapi_object" "biscuit_generator_group" {
  path      = "/oauth/tokenExchange/generator/groups"
  object_id = local.biscuit_generator_id

  data = jsonencode({
    id   = local.biscuit_generator_id
    name = "Biscuit"
    generatorMappings = [{
      requestedTokenType = local.biscuit_token_type
      tokenGenerator     = { id = restapi_object.biscuit_generator.object_id }
      defaultMapping     = true
    }]
  })

  # PF adds tokenGenerator.location and an empty resourceUris list.
  ignore_server_additions = true
}

resource "pingfederate_oauth_token_exchange_token_generator_mapping" "biscuit" {
  source_id = pingfederate_oauth_token_exchange_processor_policy.biscuit.policy_id
  target_id = restapi_object.biscuit_generator.object_id

  attribute_contract_fulfillment = {
    subject   = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    client_id = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "client_id" }
    scope     = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "scope" }
  }
}

# Singleton: the server-wide default generator group.
resource "pingfederate_oauth_token_exchange_generator_settings" "this" {
  default_generator_group_ref = {
    id = restapi_object.biscuit_generator_group.object_id
  }
}
