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
  local stack_name
  stack_name="$(echo "$stack_resp" | jq -er '.Name')"
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

  migrate_bridge_network_env() {
    local pms_url
    pms_url="$(current_env_value PORTLESS_PMS_URL)"
    case "$pms_url" in
      http://127.0.0.1:32400|http://127.0.0.1:32400/|http://localhost:32400|http://localhost:32400/)
        set_stack_env PORTLESS_PMS_URL "http://host.docker.internal:32400"
        ;;
    esac

    local ui_addr ui_publish_addr
    ui_addr="$(current_env_value PORTLESS_UI_ADDR)"
    ui_publish_addr="$(current_env_value PORTLESS_UI_PUBLISH_ADDR)"
    if [ -z "$ui_publish_addr" ] || [ "$ui_publish_addr" = "null" ] || [ "$ui_publish_addr" = "off" ]; then
      if [ -n "$ui_addr" ] && [ "$ui_addr" != "null" ] && [ "$ui_addr" != "off" ]; then
        ui_publish_addr="$ui_addr"
      else
        ui_publish_addr="127.0.0.1:43180"
      fi
      set_stack_env PORTLESS_UI_PUBLISH_ADDR "$ui_publish_addr"
    fi

    if [ "$ui_addr" != "off" ]; then
      set_stack_env PORTLESS_UI_ADDR "0.0.0.0:43180"
    fi
  }

  set_stack_env PORTLESS_CLIENT_IMAGE "$client_image"
  migrate_bridge_network_env
  if [ -n "${PORTLESS_CLIENT_CONTROL_URL:-}" ]; then
    set_stack_env PORTLESS_CONTROL_URL "$PORTLESS_CLIENT_CONTROL_URL"
  fi

  local env_file payload_file
  env_file="$(mktemp)"
  payload_file="$(mktemp)"
  printf '%s' "$env_json" > "$env_file"
  local expected_config_hash
  expected_config_hash="$(python3 - "$env_file" "$stack_name" <<'PY'
import json, os, subprocess, sys
try:
    with open(sys.argv[1]) as source:
        values = json.load(source)
    env = {name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ}
    env.update({entry["name"]: entry["value"] or "" for entry in values})
    result = subprocess.run(
        ["docker", "compose", "--env-file", "/dev/null", "--project-name", sys.argv[2],
         "-f", "docker-compose.deploy.yml", "config", "--hash", "portless-daemon"],
        env=env, text=True, capture_output=True, check=True,
    )
    print(dict(line.split() for line in result.stdout.splitlines())["portless-daemon"])
except Exception:
    sys.exit("Could not calculate the intended client configuration; deployment aborted")
PY
  )"
  jq -n --arg file "$stack_file" --slurpfile env "$env_file" \
    '{stackFileContent: $file, env: $env[0], pullImage: true}' > "$payload_file"

  pull_image() {
    local image="$1"
    local repo="${image%:*}"
    local tag="${image##*:}"
    local registry_auth
    local pull_response
    pull_response="$(mktemp)"
    registry_auth="$(jq -nc \
      --arg username "$GHCR_USERNAME" \
      --arg password "$GHCR_TOKEN" \
      '{"username":$username,"password":$password,"serveraddress":"ghcr.io"}' | base64 -w0)"
    curl -sf --max-time 300 -X POST \
      "${auth_headers[@]}" \
      -H "X-Registry-Auth: ${registry_auth}" \
      -o "$pull_response" \
      "$api/endpoints/${stack_endpoint_id}/docker/images/create?fromImage=$(urlencode "$repo")&tag=$(urlencode "$tag")"
    if ! jq -se 'length > 0 and all(.[]; .error == null and .errorDetail == null)' "$pull_response" >/dev/null; then
      rm -f "$pull_response"
      echo "::error title=Image pull failed::Registry did not confirm the requested client image" >&2
      return 1
    fi
    rm -f "$pull_response"
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

  pull_image "$client_image"
  local expected_image_id image_json
  image_json="$(curl -sf --max-time 30 "${auth_headers[@]}" \
    "$api/endpoints/$stack_endpoint_id/docker/images/$(urlencode "$client_image")/json")"
  if ! jq -e '.Config.Healthcheck.Test == ["CMD", "/usr/local/bin/portless-daemon", "healthcheck"]' <<< "$image_json" >/dev/null; then
    echo "::error title=Client image upgrade required::Select a healthcheck-enabled client image before updating this stack" >&2
    exit 1
  fi
  expected_image_id="$(jq -er '.Id' <<< "$image_json")"

  if ! curl -sf --max-time 180 -X PUT \
    "${auth_headers[@]}" \
    -H "Content-Type: application/json" \
    -o /dev/null \
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
    echo "::error title=Deploy verification failed::${target_name} stored stack file did not match repository compose file within the verification window"
    exit 1
  fi

  local container_name container_json
  container_name="$(current_env_value PORTLESS_CONTAINER_NAME)"
  verified=0
  for i in {1..36}; do
    if container_json="$(curl -sf --max-time 30 "${auth_headers[@]}" \
      "$api/endpoints/$stack_endpoint_id/docker/containers/$(urlencode "$container_name")/json")" &&
      jq -e --arg image "$client_image" --arg image_id "$expected_image_id" --arg config_hash "$expected_config_hash" '
        .Config.Image == $image and .Image == $image_id and .State.Running == true and
        .Config.Labels["com.docker.compose.config-hash"] == $config_hash and
        .State.Paused == false and .State.Restarting == false and
        .State.Health.Status == "healthy"
      ' <<< "$container_json" >/dev/null; then
      verified=1
      break
    fi
    [ "$i" -eq 36 ] || sleep 5
  done
  if [ "$verified" -ne 1 ]; then
    echo "::error title=Deploy verification failed::${target_name} client did not become healthy with the requested image"
    exit 1
  fi

  echo "Deployed ${target_name} stack ${stack_id} on endpoint ${stack_endpoint_id} with image ${client_image}"
  rm -f "$env_file" "$payload_file"
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
