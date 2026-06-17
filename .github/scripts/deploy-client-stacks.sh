#!/usr/bin/env bash
set -euo pipefail

require_vars() {
  local missing=0
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      echo "::error title=Deploy variable missing::Missing ${name}"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ]
}

urlencode() {
  jq -rn --arg value "$1" '$value | @uri'
}

stack_file="$(cat docker-compose.deploy.yml)"
repo_lc="$(echo "${GITHUB_REPOSITORY}" | tr '[:upper:]' '[:lower:]')"
deploy_target="${PORTLESS_CLIENT_DEPLOY_TARGET:-${GITHUB_REF_NAME}}"

if [ "$deploy_target" = "main" ] || [ "$deploy_target" = "production" ]; then
  default_image="ghcr.io/${repo_lc}:prod"
  nas_target_name="production"
  deploy_primary_staging=0
elif [ "$deploy_target" = "dev" ] || [ "$deploy_target" = "staging" ]; then
  default_image="ghcr.io/${repo_lc}:dev"
  nas_target_name="staging-nas"
  deploy_primary_staging=1
else
  echo "::error title=Deploy target invalid::Unsupported PORTLESS_CLIENT_DEPLOY_TARGET/GITHUB_REF_NAME: ${deploy_target}"
  exit 1
fi

deploy_stack() {
  local target_name="$1"
  local api_url="$2"
  local api_key="$3"
  local stack_id="$4"
  local endpoint_id_fallback="$5"

  require_vars CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET GHCR_USERNAME GHCR_TOKEN

  if [ -z "$api_url" ] || [ -z "$api_key" ] || [ -z "$stack_id" ]; then
    echo "::error title=Deploy target incomplete::${target_name} is missing URL, API key, or stack ID"
    exit 1
  fi

  local api="${api_url%/}/api"
  local auth_headers=(-A "crbl-ops/1.0" \
    -H "X-API-Key: ${api_key}" \
    -H "CF-Access-Client-Id: ${CF_ACCESS_CLIENT_ID}" \
    -H "CF-Access-Client-Secret: ${CF_ACCESS_CLIENT_SECRET}")

  local stack_resp
  if ! stack_resp="$(curl -sf --max-time 30 "${auth_headers[@]}" "$api/stacks/${stack_id}")"; then
    echo "::error title=Deploy stack fetch failed::${target_name} stack ${stack_id} could not be fetched"
    exit 1
  fi

  local stack_endpoint_id
  stack_endpoint_id="$(echo "$stack_resp" | jq -r '.EndpointId // empty')"
  if [ -z "$stack_endpoint_id" ]; then
    stack_endpoint_id="$endpoint_id_fallback"
  fi
  if [ -z "$stack_endpoint_id" ]; then
    echo "::error title=Deploy endpoint missing::${target_name} stack ${stack_id} did not include EndpointId"
    exit 1
  fi

  local env_json
  env_json="$(echo "$stack_resp" | jq -c '[.Env[]? | {name: .name, value: .value}]')"

  current_env_value() {
    local name="$1"
    echo "$env_json" | jq -r --arg name "$name" '.[]? | select(.name == $name) | .value' | tail -n 1
  }

  local client_image
  if [ "${DAEMON_CHANGED}" = "true" ]; then
    client_image="ghcr.io/${repo_lc}:sha-${GITHUB_SHA}"
  elif [ "${PORTLESS_CLIENT_USE_DEFAULT_IMAGE:-}" = "true" ]; then
    client_image="$default_image"
  else
    client_image="$(current_env_value PORTLESS_CLIENT_IMAGE)"
    if [ -z "$client_image" ] || [ "$client_image" = "null" ]; then
      client_image="$default_image"
    fi
  fi

  set_stack_env() {
    local name="$1"
    local value="$2"
    env_json="$(echo "$env_json" | jq -c \
      --arg name "$name" \
      --arg value "$value" \
      'map(select(.name != $name)) + [{"name":$name,"value":$value}]')"
  }

  set_stack_env PORTLESS_CLIENT_IMAGE "$client_image"
  if [ -n "${PORTLESS_CLIENT_CONTROL_URL:-}" ]; then
    set_stack_env PORTLESS_CONTROL_URL "$PORTLESS_CLIENT_CONTROL_URL"
  fi

  local env_file payload_file update_response_file
  env_file="$(mktemp)"
  payload_file="$(mktemp)"
  update_response_file="$(mktemp)"
  printf '%s' "$env_json" > "$env_file"
  jq -n --arg file "$stack_file" --slurpfile env "$env_file" \
    '{stackFileContent: $file, env: $env[0], pullImage: true}' > "$payload_file"

  pull_image() {
    local image="$1"
    local repo="${image%:*}"
    local tag="${image##*:}"
    local registry_auth
    registry_auth="$(jq -nc \
      --arg username "$GHCR_USERNAME" \
      --arg password "$GHCR_TOKEN" \
      '{"username":$username,"password":$password,"serveraddress":"ghcr.io"}' | base64 -w0)"
    curl -sf --max-time 300 -X POST \
      "${auth_headers[@]}" \
      -H "X-Registry-Auth: ${registry_auth}" \
      -o /tmp/portless-image-pull.log \
      "$api/endpoints/${stack_endpoint_id}/docker/images/create?fromImage=$(urlencode "$repo")&tag=$(urlencode "$tag")"
  }

  local endpoint_ready=0
  local i status
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ "$i" -gt 1 ] && sleep 15
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
      "${auth_headers[@]}" "$api/endpoints/${stack_endpoint_id}/docker/info")"
    if [ "$status" -lt 400 ]; then
      endpoint_ready=1
      break
    fi
    echo "${target_name} endpoint warmup ${i}/10 returned HTTP ${status}"
  done
  if [ "$endpoint_ready" -ne 1 ]; then
    echo "::error title=Deploy endpoint unavailable::${target_name} endpoint ${stack_endpoint_id} did not become ready"
    exit 1
  fi

  if [ "${DAEMON_CHANGED}" = "true" ]; then
    pull_image "$client_image"
  fi

  if ! curl -sf --max-time 180 -X PUT \
    "${auth_headers[@]}" \
    -H "Content-Type: application/json" \
    -o "$update_response_file" \
    -d @"$payload_file" \
    "$api/stacks/${stack_id}?endpointId=${stack_endpoint_id}"; then
    echo "::error title=Deploy stack update failed::${target_name} stack ${stack_id} update failed"
    exit 1
  fi

  local verified=0
  local updated_file
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if updated_file="$(curl -sf --max-time 30 \
      "${auth_headers[@]}" \
      "$api/stacks/${stack_id}/file?endpointId=${stack_endpoint_id}" |
      jq -r '.StackFileContent')"; then
      if [ "$updated_file" = "$stack_file" ]; then
        verified=1
        break
      fi
    fi
    sleep 3
  done
  if [ "$verified" -ne 1 ]; then
    echo "::warning title=Deploy verification delayed::${target_name} stored stack file did not match repository compose file within the verification window"
  fi

  echo "Deployed ${target_name} stack ${stack_id} on endpoint ${stack_endpoint_id} with image ${client_image}"
  rm -f "$env_file" "$payload_file" "$update_response_file"
}

if [ "$deploy_primary_staging" -eq 1 ]; then
  require_vars \
    PORTLESS_CLIENT_DEPLOY_API_URL \
    PORTLESS_CLIENT_DEPLOY_API_KEY \
    PORTLESS_CLIENT_STACK_ID
  deploy_stack \
    "staging-primary" \
    "$PORTLESS_CLIENT_DEPLOY_API_URL" \
    "$PORTLESS_CLIENT_DEPLOY_API_KEY" \
    "$PORTLESS_CLIENT_STACK_ID" \
    "${PORTLESS_CLIENT_DEPLOY_ENDPOINT_ID:-}"
fi

require_vars \
  PORTLESS_CLIENT_NAS_DEPLOY_API_URL \
  PORTLESS_CLIENT_NAS_DEPLOY_API_KEY \
  PORTLESS_CLIENT_NAS_STACK_ID \
  PORTLESS_CLIENT_NAS_DEPLOY_ENDPOINT_ID
deploy_stack \
  "$nas_target_name" \
  "$PORTLESS_CLIENT_NAS_DEPLOY_API_URL" \
  "$PORTLESS_CLIENT_NAS_DEPLOY_API_KEY" \
  "$PORTLESS_CLIENT_NAS_STACK_ID" \
  "$PORTLESS_CLIENT_NAS_DEPLOY_ENDPOINT_ID"
