#!/usr/bin/env bash
# Drive the PingFederate side of the demo: authorization code -> JWT -> Biscuit -> orders-api.
#
#   pf-flow.sh token <code>            exchange an authorization code for an access token
#   pf-flow.sh auto-login <user>       log in through the HTML form with curl (no browser), then `token`
#   pf-flow.sh exchange                RFC 8693: access token -> Biscuit
#   pf-flow.sh mfa                     step-up: append amr("mfa") signed by the attestation key
#   pf-flow.sh call [path]             GET and POST orders-api with the Biscuit
#
# Client settings come from `terraform output`; state is kept in .flow/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/.flow"
API="${ORDERS_API:-http://127.0.0.1:${API_PORT:-8091}}"
mkdir -p "$STATE"
cd "$ROOT"

tf_out() { docker compose run --rm --no-deps -T terraform output -raw "$1" 2>/dev/null; }
# Cache terraform outputs so each step doesn't spin up a container per value.
load_config() {
  if [[ ! -s "$STATE/config" ]]; then
    {
      echo "CLIENT_ID='$(tf_out client_id)'"
      echo "CLIENT_SECRET='$(tf_out client_secret)'"
      echo "TOKEN_ENDPOINT='$(tf_out token_endpoint)'"
      echo "AUTHORIZE_URL='$(tf_out authorize_url)'"
      echo "BISCUIT_TYPE='$(tf_out biscuit_token_type)'"
    } > "$STATE/config"
  fi
  # shellcheck disable=SC1091
  . "$STATE/config"
  REDIRECT_URI="$(python -c 'import sys,urllib.parse as u;print(u.parse_qs(u.urlparse(sys.argv[1]).query)["redirect_uri"][0])' "$AUTHORIZE_URL")"
}

json() { python -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1],""))' "$1"; }

token() {
  local code="$1" resp
  resp="$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_ENDPOINT" \
    -d grant_type=authorization_code --data-urlencode "code=$code" --data-urlencode "redirect_uri=$REDIRECT_URI")"
  local at; at="$(json access_token <<<"$resp")"
  [[ -n "$at" ]] || { echo "token request failed: $resp" >&2; exit 1; }
  printf '%s' "$at" > "$STATE/access_token"
  echo "access token (JWT) saved to .flow/access_token"
  python - "$at" <<'EOF'
import sys, json, base64
p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
EOF
}

auto_login() {
  local user="$1" pass="${2:-}" jar="$STATE/cookies" page action loc code
  [[ -n "$pass" ]] || pass="$(docker compose run --rm --no-deps -T terraform output -json demo_users 2>/dev/null | json "$user")"
  rm -f "$jar"
  page="$(curl -sk -L -c "$jar" -b "$jar" "$AUTHORIZE_URL")"
  action="$(grep -o 'action="[^"]*"' <<<"$page" | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')"
  [[ -n "$action" ]] || { echo "login form not found" >&2; exit 1; }
  [[ "$action" == http* ]] || action="${AUTHORIZE_URL%%/as/*}$action"
  loc="$(curl -sk -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$action" \
    --data-urlencode "pf.username=$user" --data-urlencode "pf.pass=$pass" -d pf.ok=clicked -d pf.cancel=)"
  code="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$loc")"
  [[ -n "$code" ]] || { echo "login failed, redirected to: ${loc:-<none>}" >&2; exit 1; }
  echo "logged in as $user"
  token "$code"
}

exchange() {
  local at resp biscuit
  at="$(cat "$STATE/access_token" 2>/dev/null)" || { echo "no access token; run token or auto-login first" >&2; exit 1; }
  resp="$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" "$TOKEN_ENDPOINT" \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    --data-urlencode "subject_token=$at" \
    -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    --data-urlencode "requested_token_type=$BISCUIT_TYPE")"
  biscuit="$(json access_token <<<"$resp")"
  [[ -n "$biscuit" ]] || { echo "token exchange failed: $resp" >&2; exit 1; }
  printf '%s' "$biscuit" > "$STATE/biscuit"
  echo "issued_token_type=$(json issued_token_type <<<"$resp") expires_in=$(json expires_in <<<"$resp")"
  echo "Biscuit saved to .flow/biscuit"
  "$ROOT/orders-api/target/debug/hop" inspect "$biscuit" 2>/dev/null || echo "$biscuit"
}

# Stand-in for PingFederate attesting step-up MFA: biscuit-java 4.0.1 can't read the v3.3
# third-party request format yet, so the Rust hop CLI signs with the attestation key.
mfa() {
  local hop="$ROOT/orders-api/target/debug/hop" biscuit req resp
  biscuit="$(cat "$STATE/biscuit" 2>/dev/null)" || { echo "no Biscuit; run exchange first" >&2; exit 1; }
  # shellcheck disable=SC1091
  . "$ROOT/.keys/attestation.env"
  req="$("$hop" request "$biscuit")"
  resp="$("$hop" attest "$ATTEST_PRIVATE_KEY" "$req" 'amr("mfa");' 2>/dev/null)"
  "$hop" append "$biscuit" "$resp" | tr -d '\r\n' > "$STATE/biscuit"
  echo "appended amr(\"mfa\") signed by $ATTEST_PUBLIC_KEY"
  "$hop" inspect "$(cat "$STATE/biscuit")" | tail -n 4
}

call() {
  local path="${1:-/orders/123}" biscuit
  biscuit="$(cat "$STATE/biscuit")"
  echo "GET  $path -> $(curl -s -w ' [%{http_code}]' -H "Authorization: Bearer $biscuit" "$API$path")"
  echo "POST $path -> $(curl -s -w ' [%{http_code}]' -X POST -H "Authorization: Bearer $biscuit" "$API$path")"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  token)      load_config; token "${1:?usage: token <code>}" ;;
  auto-login) load_config; auto_login "${1:?usage: auto-login <user> [password]}" "${2:-}" ;;
  exchange)   load_config; exchange ;;
  mfa)        mfa ;;
  call)       call "${1:-}" ;;
  reset)      rm -rf "$STATE"; echo "cleared .flow/" ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
