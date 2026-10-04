#!/usr/bin/env bash
# End-to-end walk through: PingFederate mints -> gateway attenuates -> service authorizes.
#
# The mint step runs the plugin's own BiscuitMinter through its CLI, i.e. exactly the code the
# PingFederate token generator executes, without needing a licensed PingFederate server.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAVA="${JAVA:-java}"
JAR="$ROOT/pf-biscuit-generator/target/pf.plugins.biscuit-token-generator.jar"
BIN="$ROOT/orders-api/target/debug"
HOP="$BIN/hop"
API="http://127.0.0.1:${API_PORT:-8091}"
WORK="$(mktemp -d)"
PASS=0; FAIL=0

pf()  { "$JAVA" -jar "$JAR" "$@"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# expect <status> <description> <curl args...>
expect() {
  local want="$1" desc="$2"; shift 2
  local body status
  body="$(curl -s -w '\n%{http_code}' "$@")"
  status="${body##*$'\n'}"; body="${body%$'\n'*}"
  if [[ "$status" == "$want" ]]; then PASS=$((PASS+1)); printf '  PASS %s -> %s %s\n' "$desc" "$status" "$body"
  else FAIL=$((FAIL+1)); printf '  FAIL %s -> got %s want %s %s\n' "$desc" "$status" "$want" "$body"; fi
}
get()  { expect "$1" "$2" -H "Authorization: Bearer $3" "$API$4" "${@:5}"; }
post() { expect "$1" "$2" -X POST -H "Authorization: Bearer $3" "$API$4" "${@:5}"; }

say "Keys: PingFederate Biscuit root key + PingFederate attestation key"
eval "$(pf keygen | sed 's/^/ROOT_/')"      # ROOT_private, ROOT_public
eval "$(pf keygen | sed 's/^/ATTEST_/')"    # ATTEST_private, ATTEST_public
echo "  root   $ROOT_public"
echo "  attest $ATTEST_public"

say "Start orders-api (trusts root key, and attestation key for amr)"
: > "$WORK/revoked.txt"
LISTEN="127.0.0.1:${API_PORT:-8091}" BISCUIT_ROOT_PUBLIC_KEY="$ROOT_public" BISCUIT_ATTEST_PUBLIC_KEY="$ATTEST_public" \
  BISCUIT_REVOCATION_FILE="$WORK/revoked.txt" "$BIN/orders-api" > "$WORK/api.log" 2>&1 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 50); do curl -s "$API/orders/1" >/dev/null && break; sleep 0.1; done

say "PingFederate token exchange: JWT for alice -> Biscuit"
TOKEN="$(pf mint --key "$ROOT_private" --issuer https://sso.example.com --aud orders-api,billing-api \
  --lifetime 300 subject=alice client_id=orders-web 'scope=orders:read orders:write' 2>"$WORK/mint.txt")"
sed 's/^/  /' "$WORK/mint.txt"
echo "  token: ${#TOKEN} chars"

say "Service authorizes using only the public key"
get  200 "read with PF token"                  "$TOKEN" /orders/123
post 403 "write without MFA attestation"       "$TOKEN" /orders/123
get  401 "no token"                            ""       /orders/123
TAMPERED="${TOKEN:0:40}$( [[ ${TOKEN:40:1} == A ]] && echo B || echo A )${TOKEN:41}"
get  401 "tampered token"                      "$TAMPERED" /orders/123
OTHER="$(pf keygen | sed -n 's/^private=//p')"
FORGED="$(pf mint --key "$OTHER" --issuer https://evil.example.com --aud orders-api subject=mallory 'scope=orders:read orders:write' 2>/dev/null)"
get  401 "token minted by another key"         "$FORGED" /orders/123

say "Gateway attenuates offline: read-only, one order, 60s, tagged with its hop"
EXP="$(date -u -d '+60 seconds' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+60S +%Y-%m-%dT%H:%M:%SZ)"
NARROW="$("$HOP" attenuate "$TOKEN" "hop(\"gateway-1\");
check if operation(\"read\");
check if resource(\$r), \$r.starts_with(\"/orders/123\");
check if time(\$t), \$t <= $EXP;")"
"$HOP" inspect "$NARROW" | sed 's/^/  /'
get  200 "attenuated: read /orders/123"        "$NARROW" /orders/123
get  403 "attenuated: read /orders/999"        "$NARROW" /orders/999
post 403 "attenuated: write"                   "$NARROW" /orders/123

say "A holder cannot widen a token by adding facts"
SELF="$("$HOP" attenuate "$TOKEN" 'amr("mfa"); scope("orders:admin");')"
post 403 "self-asserted amr(\"mfa\") ignored"  "$SELF" /orders/123

say "Sealed token cannot be attenuated further"
SEALED="$("$HOP" seal "$NARROW")"
get  200 "sealed token still works"            "$SEALED" /orders/123
if "$HOP" attenuate "$SEALED" 'check if true;' >/dev/null 2>&1; then
  FAIL=$((FAIL+1)); echo "  FAIL attenuating a sealed token succeeded"
else PASS=$((PASS+1)); echo "  PASS attenuating a sealed token is refused"; fi

say "Step-up: PingFederate attests amr(\"mfa\") as a third-party block"
REQ="$("$HOP" request "$TOKEN")"
if RESP="$(pf attest --key "$ATTEST_private" --request "$REQ" amr=mfa 2>"$WORK/attest.err")"; then
  echo "  biscuit-java signed the request"
else
  echo "  biscuit-java 4.0.1 could not read a biscuit-auth 6 request:"
  sed 's/^/    /' "$WORK/attest.err" | grep -v '^\s*at ' | head -3
  echo "  falling back to the Rust attestor with the same PingFederate attestation key"
  RESP="$("$HOP" attest "$ATTEST_private" "$REQ" 'amr("mfa");' 2>/dev/null)"
fi
MFA="$("$HOP" append "$TOKEN" "$RESP")"
"$HOP" inspect "$MFA" | sed 's/^/  /'
post 200 "write with PF-attested MFA"          "$MFA" /orders/123
WRONG_REQ="$("$HOP" request "$TOKEN")"
WRONG="$("$HOP" append "$TOKEN" "$("$HOP" attest "$OTHER" "$WRONG_REQ" 'amr("mfa");' 2>/dev/null)")"
post 403 "write with amr from untrusted key"   "$WRONG" /orders/123

say "Sender-constrained token (RFC 8705-style cert binding)"
BOUND="$(pf mint --key "$ROOT_private" --issuer https://sso.example.com --aud orders-api \
  subject=alice 'scope=orders:read' cnf_x5t_s256=thumb-abc 2>/dev/null)"
get  403 "bound token, no client cert"         "$BOUND" /orders/123
get  403 "bound token, other client cert"      "$BOUND" /orders/123 -H "X-Client-Cert-Sha256: thumb-xyz"
get  200 "bound token, matching client cert"   "$BOUND" /orders/123 -H "X-Client-Cert-Sha256: thumb-abc"

say "Revocation: revoke the authority block, every descendant dies"
sed -n 's/^revocation_ids=\[\([0-9a-fA-F]*\).*/\1/p' "$WORK/mint.txt" > "$WORK/revoked.txt"
echo "  revoked $(cat "$WORK/revoked.txt" | cut -c1-24)..."
get  401 "original token after revocation"     "$TOKEN"  /orders/123
get  401 "attenuated child after revocation"   "$NARROW" /orders/123
get  200 "unrelated token still fine"          "$BOUND"  /orders/123 -H "X-Client-Cert-Sha256: thumb-abc"

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
