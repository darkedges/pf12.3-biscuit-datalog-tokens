# PingFederate x Biscuit - build, test, demo and run PingFederate with the plugin deployed.
#
# Machine-specific settings go in local.mk, which is git-ignored:
#   JAVA_HOME := C:/Program Files/Microsoft/jdk-11.0.16.101-hotspot
#   GIT_BASH  := C:/PROGRA~1/Git/bin/bash.exe

-include local.mk

# Recipes need a POSIX shell. On Windows a bare "bash" is ambiguous (from PowerShell it resolves to
# WSL's bash, and if make can't find it at all it silently falls back to cmd.exe), so use Git Bash
# explicitly. The 8.3 path avoids the space in "Program Files", which make's SHELL can't handle.
ifeq ($(OS),Windows_NT)
  GIT_BASH ?= C:/PROGRA~1/Git/bin/bash.exe
  ifeq ($(wildcard $(GIT_BASH)),)
    $(error Git Bash not found at $(GIT_BASH); set GIT_BASH in local.mk)
  endif
  SHELL := $(GIT_BASH)
else
  SHELL := bash
endif
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PLUGIN_DIR  := pf-biscuit-generator
API_DIR     := orders-api
PLUGIN_JAR  := $(PLUGIN_DIR)/target/pf.plugins.biscuit-token-generator.jar
SERVICE     := pingfederate
SKIP_TESTS  ?= false

MVN := mvn -B -f $(PLUGIN_DIR)/pom.xml
ifdef JAVA_HOME
  # Exported through make's environment, so it works no matter which shell runs the recipe.
  export JAVA_HOME
  JAVA := $(JAVA_HOME)/bin/java
else
  JAVA := java
endif

# Stop Git Bash rewriting container paths like /opt/out/... into Windows paths (no-op elsewhere).
COMPOSE := MSYS_NO_PATHCONV=1 docker compose

##@ Help
.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
	  /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Build
.PHONY: plugin api demo-web build
plugin: ## Build the PingFederate plugin jar (runs tests unless SKIP_TESTS=true)
	$(MVN) -DskipTests=$(SKIP_TESTS) package

api: ## Build orders-api and the hop CLI
	cd $(API_DIR) && cargo build

demo-web: ## Build the demo web app
	cd demo-web && cargo build

build: plugin api demo-web ## Build everything locally

##@ Test
.PHONY: test test-plugin test-api demo keygen
test-plugin: ## Run the plugin unit tests
	$(MVN) test

test-api: ## Build and test the Rust crate
	cd $(API_DIR) && cargo test

test: test-plugin test-api ## Run all tests

demo: build ## End-to-end demo: mint -> attenuate -> authorize (no PingFederate needed)
	JAVA="$(JAVA)" bash scripts/demo.sh

keygen: plugin ## Generate an Ed25519 key pair for the plugin / services
	"$(JAVA)" -jar $(PLUGIN_JAR) keygen

##@ PingFederate (docker compose)
.PHONY: image up down reset restart redeploy logs log-file ps shell check-env
image: ## Build the PingFederate image with the plugin deployed (SKIP_TESTS=true to skip tests)
	$(COMPOSE) build --build-arg SKIP_TESTS=$(SKIP_TESTS) $(SERVICE)

up: check-env ## Start PingFederate (builds the image if needed)
	$(COMPOSE) up -d --build $(SERVICE)
	@echo "Admin console: https://localhost:9999/pingfederate/app   Runtime: https://localhost:9031"

down: ## Stop PingFederate (keeps the /opt/out volume)
	$(COMPOSE) down

reset: ## Stop PingFederate and delete its /opt/out volume (wipes runtime config)
	$(COMPOSE) down -v

restart: ## Restart the container without rebuilding
	$(COMPOSE) restart $(SERVICE)

# /opt/server is only copied into /opt/out/instance on a fresh volume, so picking up a
# rebuilt plugin requires discarding the volume.
redeploy: check-env reset up ## Rebuild the plugin into the image and start on a fresh volume

LINES ?= 200
LOG   ?= server.log

logs: ## Follow the container log, which includes server.log (LINES=200)
	$(COMPOSE) logs -f --tail $(LINES) $(SERVICE)

log-file: ## Follow a PingFederate log file inside the container (LOG=audit.log, LINES=200)
	$(COMPOSE) exec $(SERVICE) tail -n $(LINES) -F /opt/out/instance/log/$(LOG)

ps: ## Show container status
	$(COMPOSE) ps

shell: ## Open a shell in the running PingFederate container
	$(COMPOSE) exec $(SERVICE) sh

check-env:
	@if [ -z "$${PING_IDENTITY_DEVOPS_USER:-}" ] && ! grep -qs '^PING_IDENTITY_DEVOPS_USER=.' .env; then \
	  echo "PING_IDENTITY_DEVOPS_USER / PING_IDENTITY_DEVOPS_KEY must be exported or set in .env" >&2; exit 1; fi

##@ Terraform (PingFederate config, runs in the terraform container)
TF          := $(COMPOSE) run --rm terraform
# Reading outputs only needs the local state, not a running PingFederate.
TF_OUT      := $(COMPOSE) run --rm --no-deps -T terraform output
TF_KEYS     := terraform/biscuit.auto.tfvars
PLUGIN_IN_PF := /opt/out/instance/server/default/deploy/pf.plugins.biscuit-token-generator.jar

.PHONY: tf-keys tf-init tf-validate tf-fmt tf-plan tf-apply tf-destroy tf-output tf-creds
tf-keys: $(TF_KEYS) ## Generate the Biscuit root key pair (once) into terraform/biscuit.auto.tfvars

# Uses the plugin jar inside the PingFederate container, so no host JDK is needed.
$(TF_KEYS):
	@keys="$$($(COMPOSE) exec -T $(SERVICE) java -jar $(PLUGIN_IN_PF) keygen)"; \
	  priv="$$(sed -n 's/^private=//p' <<<"$$keys" | tr -d '\r')"; \
	  pub="$$(sed -n 's/^public=//p' <<<"$$keys" | tr -d '\r')"; \
	  [ -n "$$priv" ] && [ -n "$$pub" ] || { echo "keygen failed (is PingFederate running?)" >&2; exit 1; }; \
	  printf '# Generated by make tf-keys. Keep private: this signs every Biscuit.\nbiscuit_root_private_key = "%s"\nbiscuit_root_public_key  = "%s"\n' "$$priv" "$$pub" > $@; \
	  echo "wrote $@ (public key $$pub)"

tf-init: ## terraform init
	$(TF) init -input=false

tf-validate: tf-init ## terraform validate
	$(TF) validate

tf-fmt: ## terraform fmt
	$(TF) fmt

tf-plan: tf-keys tf-init ## Plan the PingFederate token exchange config (saved to terraform/tfplan)
	$(TF) plan -input=false -out=tfplan

tf-apply: ## Apply the plan saved by tf-plan
	@[ -f terraform/tfplan ] || { echo "no saved plan; run make tf-plan first" >&2; exit 1; }
	$(TF) apply -input=false tfplan
	@rm -f terraform/tfplan

tf-destroy: tf-keys ## Remove everything Terraform created in PingFederate
	$(TF) destroy -input=false

tf-output: ## Show Terraform outputs
	$(TF_OUT)

tf-creds: ## Show the demo users' generated passwords and the client secret
	@$(TF_OUT) -json demo_users
	@echo "client_secret: $$($(TF_OUT) -raw client_secret)"

##@ Demo flow against PingFederate (after tf-apply)
.PHONY: web attest-keys login token auto-login exchange mfa api-pf call flow-reset
TF_Q        := $(COMPOSE) run --rm --no-deps -T terraform
ATTEST_KEYS := .keys/attestation.env
ROOT_PUB     = $$(sed -n 's/^biscuit_root_public_key *= *"\(.*\)"/\1/p' $(TF_KEYS))

# WEB_PORT must match the client's redirect URI (terraform var redirect_uris).
# Defaults avoid 8080-8083, which other local containers commonly publish.
WEB_PORT ?= 8090
API_PORT ?= 8091
PF_RUNTIME ?= https://localhost:9031
export API_PORT

# Fails with the name of whatever already answers on a port (often another compose project).
define check_port
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$(1)/; then \
  owner="$$(docker ps --filter publish=$(1) --format '{{.Names}}' 2>/dev/null | head -1)"; \
  echo "port $(1) is already in use$${owner:+ by container $$owner}; set $(2)=<free port>" >&2; exit 1; fi
endef

# Polls until a background process answers on its port; fails fast if it exits first.
define wait_for_port
for i in $$(seq 60); do \
  curl -s -o /dev/null --max-time 1 http://127.0.0.1:$(1)/ && break; \
  kill -0 $(2) 2>/dev/null || { echo "$(3) exited before listening on port $(1)" >&2; exit 1; }; \
  [ $$i -eq 60 ] && { echo "$(3) is not listening on port $(1) after 30s" >&2; exit 1; }; \
  sleep 0.5; \
done
endef

web: api demo-web $(ATTEST_KEYS) ## Run orders-api + the web app on http://localhost:8090 (after tf-apply)
	@secret="$$($(TF_Q) output -raw client_secret 2>/dev/null | tr -d '\r')"; \
	  [ -n "$$secret" ] || { echo "no client secret in terraform state; run make tf-plan tf-apply first" >&2; exit 1; }; \
	  if ! curl -sk -o /dev/null --max-time 2 $(PF_RUNTIME)/pf/heartbeat.ping; then \
	    [ -n "$$($(COMPOSE) ps -q $(SERVICE) 2>/dev/null)" ] || { echo "PingFederate is not running; start it with make up" >&2; exit 1; }; \
	    printf "waiting for PingFederate on $(PF_RUNTIME) "; \
	    for i in $$(seq 90); do \
	      curl -sk -o /dev/null --max-time 2 $(PF_RUNTIME)/pf/heartbeat.ping && break; \
	      [ $$i -eq 90 ] && { echo; echo "PingFederate did not come up within 3 minutes (make logs)" >&2; exit 1; }; \
	      printf "."; sleep 2; \
	    done; echo " up"; \
	  fi; \
	  $(call check_port,$(API_PORT),API_PORT); \
	  $(call check_port,$(WEB_PORT),WEB_PORT); \
	  . ./$(ATTEST_KEYS); root="$(ROOT_PUB)"; \
	  LISTEN=127.0.0.1:$(API_PORT) BISCUIT_ROOT_PUBLIC_KEY="$$root" BISCUIT_ATTEST_PUBLIC_KEY="$$ATTEST_PUBLIC_KEY" \
	    $(API_DIR)/target/debug/orders-api & api=$$!; \
	  CLIENT_SECRET="$$secret" BISCUIT_ROOT_PUBLIC_KEY="$$root" ATTEST_PRIVATE_KEY="$$ATTEST_PRIVATE_KEY" \
	  LISTEN=127.0.0.1:$(WEB_PORT) REDIRECT_URI=http://localhost:$(WEB_PORT)/callback ORDERS_API=http://127.0.0.1:$(API_PORT) \
	    demo-web/target/debug/demo-web & web=$$!; \
	  trap 'kill $$web $$api 2>/dev/null' EXIT INT TERM; \
	  $(call wait_for_port,$(API_PORT),$$api,orders-api); \
	  $(call wait_for_port,$(WEB_PORT),$$web,demo-web); \
	  echo; \
	  echo "  Ready: http://localhost:$(WEB_PORT)   (orders-api on :$(API_PORT); Ctrl+C stops both)"; \
	  echo; \
	  wait $$web

attest-keys: $(ATTEST_KEYS) ## Generate the (simulated) PingFederate MFA attestation key pair once

# Builds only hop, so it works while a running orders-api has its exe locked.
$(ATTEST_KEYS):
	cd $(API_DIR) && cargo build --bin hop
	@mkdir -p $(dir $@)
	@$(API_DIR)/target/debug/hop keygen | tr -d '\r' \
	  | sed 's/^private=/ATTEST_PRIVATE_KEY=/; s/^public=/ATTEST_PUBLIC_KEY=/' > $@
	@echo "wrote $@ ($$(sed -n 's/^ATTEST_PUBLIC_KEY=//p' $@))"

login: ## Print the authorize URL to open in a browser
	@$(TF_OUT) -raw authorize_url; echo
	@echo "Log in, then copy ?code=... from the (unreachable) redirect and run: make token CODE=<code>"

token: ## Exchange an authorization code for a JWT access token (CODE=...)
	@bash scripts/pf-flow.sh token "$(CODE)"

auto-login: ## Log in through the HTML form with curl instead of a browser (LOGIN_USER=alice)
	@bash scripts/pf-flow.sh auto-login "$(or $(LOGIN_USER),alice)"

exchange: ## Token exchange: JWT access token -> Biscuit
	@bash scripts/pf-flow.sh exchange

mfa: $(ATTEST_KEYS) ## Step-up: append amr("mfa") signed by the attestation key to .flow/biscuit
	@bash scripts/pf-flow.sh mfa

api-pf: api $(ATTEST_KEYS) ## Run orders-api trusting the PingFederate root and attestation keys (foreground)
	@$(call check_port,$(API_PORT),API_PORT)
	. ./$(ATTEST_KEYS); LISTEN=127.0.0.1:$(API_PORT) BISCUIT_ROOT_PUBLIC_KEY="$(ROOT_PUB)" BISCUIT_ATTEST_PUBLIC_KEY="$$ATTEST_PUBLIC_KEY" \
	  $(API_DIR)/target/debug/orders-api

call: ## Call orders-api with the Biscuit (PATH_=/orders/123)
	@bash scripts/pf-flow.sh call "$(or $(PATH_),/orders/123)"

flow-reset: ## Forget cached client settings and tokens in .flow/
	@bash scripts/pf-flow.sh reset

##@ Housekeeping
.PHONY: clean
clean: ## Remove local build output
	$(MVN) -q clean
	cd $(API_DIR) && cargo clean
	cd demo-web && cargo clean
