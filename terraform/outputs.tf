output "client_id" {
  value = pingfederate_oauth_client.orders_web.client_id
}

output "client_secret" {
  value     = random_password.client_secret.result
  sensitive = true
}

output "demo_users" {
  description = "Demo usernames and generated passwords for the HTML form."
  value       = { for user in var.demo_users : user => random_password.demo_user[user].result }
  sensitive   = true
}

output "authorize_url" {
  description = "Open in a browser to log in; the code arrives on the redirect URI."
  value = format("%s/as/authorization.oauth2?response_type=code&client_id=%s&redirect_uri=%s&scope=%s",
    var.pf_runtime_url,
    pingfederate_oauth_client.orders_web.client_id,
    urlencode(var.redirect_uris[0]),
    urlencode(join(" ", keys(var.scopes))),
  )
}

output "token_endpoint" {
  value = "${var.pf_runtime_url}/as/token.oauth2"
}

output "biscuit_token_type" {
  value = local.biscuit_token_type
}

output "biscuit_root_public_key" {
  value = var.biscuit_root_public_key
}
