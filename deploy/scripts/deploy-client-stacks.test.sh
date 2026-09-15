#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

for dockerfile in Dockerfile Dockerfile.package; do
  grep -Fq 'CMD ["/usr/local/bin/portless-daemon", "healthcheck"]' "$dockerfile"
done

for scenario in healthy staging-registries stopped restarting unhealthy old-image bad-compose old-config legacy-image config-render-error pull-error pull-transport-error missing-image mutable-image wrong-repo malformed-sha missing-registry-id invalid-registry-id invalid-primary-registry-id invalid-staging-nas-registry-id; do
  scenario_dir="$work_dir/$scenario"
  deploy_tmp="$scenario_dir/tmp"
  mkdir -p "$deploy_tmp"
  if (
    export TMPDIR="$deploy_tmp"
    export GITHUB_REPOSITORY=CRBL-Technologies/portless-client GITHUB_REF_NAME=main
    export GITHUB_SHA=test DAEMON_CHANGED=false
    export PORTLESS_CLIENT_DEPLOY_IMAGE=ghcr.io/crbl-technologies/portless-client:sha-0123456789abcdef0123456789abcdef01234567
    export PORTLESS_CLIENT_NAS_DEPLOY_API_URL=https://portainer.invalid PORTLESS_CLIENT_NAS_DEPLOY_API_KEY=test
    export PORTLESS_CLIENT_NAS_STACK_ID=1 PORTLESS_CLIENT_NAS_DEPLOY_ENDPOINT_ID=3
    export PORTLESS_CLIENT_NAS_REGISTRY_ID=7
    unset GHCR_USERNAME GHCR_TOKEN
    case "$scenario" in
      missing-image) unset PORTLESS_CLIENT_DEPLOY_IMAGE;;
      mutable-image) export PORTLESS_CLIENT_DEPLOY_IMAGE=ghcr.io/crbl-technologies/portless-client:prod;;
      wrong-repo) export PORTLESS_CLIENT_DEPLOY_IMAGE=ghcr.io/other/client:sha-0123456789abcdef0123456789abcdef01234567;;
      malformed-sha) export PORTLESS_CLIENT_DEPLOY_IMAGE=ghcr.io/crbl-technologies/portless-client:sha-invalid;;
      missing-registry-id) unset PORTLESS_CLIENT_NAS_REGISTRY_ID;;
      invalid-registry-id) export PORTLESS_CLIENT_NAS_REGISTRY_ID=0;;
      staging-registries|invalid-primary-registry-id|invalid-staging-nas-registry-id)
        export GITHUB_REF_NAME=dev
        export PORTLESS_CLIENT_DEPLOY_API_URL=https://primary.invalid PORTLESS_CLIENT_DEPLOY_API_KEY=test
        export PORTLESS_CLIENT_STACK_ID=2 PORTLESS_CLIENT_DEPLOY_ENDPOINT_ID=4
        export PORTLESS_CLIENT_REGISTRY_ID=11
        ;;
    esac
    case "$scenario" in
      invalid-primary-registry-id) export PORTLESS_CLIENT_REGISTRY_ID=not-an-integer;;
      invalid-staging-nas-registry-id) export PORTLESS_CLIENT_NAS_REGISTRY_ID=-1;;
      config-render-error)
        mkdir -p "$scenario_dir/bin"
        printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$scenario_dir/bin/docker"
        chmod +x "$scenario_dir/bin/docker"
        export PATH="$scenario_dir/bin:$PATH"
        ;;
    esac
    export CF_ACCESS_CLIENT_ID=test CF_ACCESS_CLIENT_SECRET=test
    curl() {
      touch "$scenario_dir/api-called"
      local url="${@: -1}"
      case "$url" in
        */docker/info) printf '200';;
        */file\?*)
          if [ "$scenario" = bad-compose ]; then
            printf '{"StackFileContent":"old"}'
          else
            jq -n --rawfile file docker-compose.deploy.yml '{StackFileContent:$file}'
          fi;;
        */images/create\?*)
          local expected_registry_id
          case "$url" in
            https://portainer.invalid/api/endpoints/3/docker/images/create\?fromImage=ghcr.io%2Fcrbl-technologies%2Fportless-client\&tag=sha-0123456789abcdef0123456789abcdef01234567)
              expected_registry_id=7;;
            https://primary.invalid/api/endpoints/4/docker/images/create\?fromImage=ghcr.io%2Fcrbl-technologies%2Fportless-client\&tag=sha-0123456789abcdef0123456789abcdef01234567)
              expected_registry_id=11;;
            *) return 1;;
          esac
          local output="" previous="" arg registry_auth=""
          for arg in "$@"; do
            [ "$previous" != -o ] || output="$arg"
            if [ "$previous" = -H ] && [[ "$arg" = "X-Registry-Auth: "* ]]; then
              registry_auth="${arg#X-Registry-Auth: }"
            fi
            previous="$arg"
          done
          local decoded_auth
          decoded_auth="$(printf '%s' "$registry_auth" | base64 -d)" || return 1
          jq -e --argjson expected "$expected_registry_id" '
            type == "object" and keys == ["registryId"] and
            .registryId == $expected and (.registryId | type == "number") and
            (has("username") | not) and (has("password") | not)
          ' <<< "$decoded_auth" >/dev/null || return 1
          [ "${output%/*}" = "${env_file%/*}" ] || return 1
          [ "${output%/*}" = "${payload_file%/*}" ] || return 1
          [ "$(stat -c '%a' "${output%/*}")" = 700 ] || return 1
          [ "$scenario" != pull-transport-error ] || return 1
          if [ "$scenario" = pull-error ]; then
            printf '{"error":"image not found"}\n' > "$output"
          else
            printf '{"status":"Downloaded"}\n' > "$output"
          fi;;
        */images/*/json)
          if [ "$scenario" = legacy-image ]; then
            printf '{"Id":"sha256:requested","Config":{}}'
          else
            printf '{"Id":"sha256:requested","Config":{"Healthcheck":{"Test":["CMD","/usr/local/bin/portless-daemon","healthcheck"]}}}'
          fi;;
        */containers/*/json)
          jq -n --arg scenario "$scenario" --arg hash "$expected_config_hash" --arg image "$PORTLESS_CLIENT_DEPLOY_IMAGE" '{
            Config:{Image:$image, Labels:{"com.docker.compose.config-hash":(if $scenario == "old-config" then "old" else $hash end)}},
            Image:(if $scenario == "old-image" then "sha256:old" else "sha256:requested" end),
            State:{Running:($scenario != "stopped"), Paused:false, Restarting:($scenario == "restarting"),
              Health:{Status:(if $scenario == "unhealthy" then "unhealthy" else "healthy" end)}}
          }';;
        */stacks/1\?*|*/stacks/2\?*)
          case "$url" in
            https://portainer.invalid/api/stacks/1\?endpointId=3|https://primary.invalid/api/stacks/2\?endpointId=4) :;;
            *) return 1;;
          esac
          jq -e --arg image "$PORTLESS_CLIENT_DEPLOY_IMAGE" '.env | any(.name == "PORTLESS_CLIENT_IMAGE" and .value == $image)' "$payload_file" >/dev/null || return 1
          printf '%s\n' "$url" >> "$scenario_dir/mutations"
          case " $* " in
            *" -o /dev/null "*) :;;
            *) echo 'STACK_SECRET_MUST_NOT_APPEAR';;
          esac;;
        */stacks/2)
          printf '%s' '{"Name":"portless-primary-test","EndpointId":4,"Env":[{"name":"PORTLESS_CONTAINER_NAME","value":"portless-client-primary"},{"name":"PORTLESS_CLIENT_IMAGE","value":"ghcr.io/crbl-technologies/portless-client:dev"},{"name":"PORTLESS_UI_ADDR","value":"off"},{"name":"PORTLESS_DEVICE_TOKEN","value":"test-only"},{"name":"PORTLESS_PMS_URL","value":"http://plex:32400"},{"name":"PORTLESS_CONTROL_URL","value":"https://control.example.test"}]}';;
        */stacks/1)
          printf '%s' '{"Name":"portless-test","EndpointId":3,"Env":[{"name":"PORTLESS_CONTAINER_NAME","value":"portless-client"},{"name":"PORTLESS_CLIENT_IMAGE","value":"ghcr.io/crbl-technologies/portless-client:prod"},{"name":"PORTLESS_UI_ADDR","value":"off"},{"name":"PORTLESS_DEVICE_TOKEN","value":"test-only"},{"name":"PORTLESS_PMS_URL","value":"http://plex:32400"},{"name":"PORTLESS_CONTROL_URL","value":"https://control.example.test"}]}';;
        *) echo "Unexpected API path" >&2; return 1;;
      esac
    }
    sleep() { :; }
    export -f curl sleep
    export scenario scenario_dir
    bash deploy/scripts/deploy-client-stacks.sh
  ) >"$scenario_dir/result" 2>&1; then
    case "$scenario" in
      healthy|staging-registries) :;;
      *) echo "Incorrect success: $scenario" >&2; exit 1;;
    esac
  else
    case "$scenario" in
      healthy|staging-registries) cat "$scenario_dir/result" >&2; exit 1;;
    esac
  fi
  if grep -q STACK_SECRET_MUST_NOT_APPEAR "$scenario_dir/result"; then
    echo "Stack update exposed its response" >&2
    exit 1
  fi
  case "$scenario" in
    legacy-image|config-render-error|pull-error|pull-transport-error|missing-image|mutable-image|wrong-repo|malformed-sha|missing-registry-id|invalid-registry-id|invalid-primary-registry-id|invalid-staging-nas-registry-id)
      [ ! -e "$scenario_dir/mutations" ] || { echo "Preflight failure mutated the stack: $scenario" >&2; exit 1; };;
  esac
  case "$scenario" in
    missing-image|mutable-image|wrong-repo|malformed-sha|missing-registry-id|invalid-registry-id|invalid-primary-registry-id|invalid-staging-nas-registry-id)
      [ ! -e "$scenario_dir/api-called" ] || { echo "Invalid preflight reached the API: $scenario" >&2; exit 1; };;
  esac
  if find "$deploy_tmp" -mindepth 1 -print -quit | grep -q .; then
    echo "Temporary deploy files remained after $scenario" >&2
    exit 1
  fi
  if [ "$scenario" = staging-registries ] && [ "$(wc -l < "$scenario_dir/mutations")" -ne 2 ]; then
    echo "Staging did not update both targets" >&2
    exit 1
  fi
done
echo 'Client rollout verification scenarios passed'
