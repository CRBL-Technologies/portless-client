#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

for dockerfile in Dockerfile Dockerfile.package; do
  grep -Fq 'CMD ["/usr/local/bin/portless-daemon", "healthcheck"]' "$dockerfile"
done

for scenario in healthy stopped restarting unhealthy old-image bad-compose old-config legacy-image; do
  rm -f "$work_dir/mutated"
  if (
    export TMPDIR="$work_dir"
    export GITHUB_REPOSITORY=CRBL-Technologies/portless-client GITHUB_REF_NAME=main
    export GITHUB_SHA=test DAEMON_CHANGED=false
    export CF_ACCESS_CLIENT_ID=test CF_ACCESS_CLIENT_SECRET=test GHCR_USERNAME=test GHCR_TOKEN=test
    export PORTLESS_CLIENT_NAS_DEPLOY_API_URL=https://portainer.invalid PORTLESS_CLIENT_NAS_DEPLOY_API_KEY=test
    export PORTLESS_CLIENT_NAS_STACK_ID=1 PORTLESS_CLIENT_NAS_DEPLOY_ENDPOINT_ID=3
    curl() {
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
          local output="" previous="" arg
          for arg in "$@"; do
            [ "$previous" != -o ] || output="$arg"
            previous="$arg"
          done
          printf '{"status":"Downloaded"}\n' > "$output";;
        */images/*/json)
          if [ "$scenario" = legacy-image ]; then
            printf '{"Id":"sha256:requested","Config":{}}'
          else
            printf '{"Id":"sha256:requested","Config":{"Healthcheck":{"Test":["CMD","/usr/local/bin/portless-daemon","healthcheck"]}}}'
          fi;;
        */containers/*/json)
          jq -n --arg scenario "$scenario" --arg hash "$expected_config_hash" '{
            Config:{Image:"ghcr.io/crbl-technologies/portless-client:prod", Labels:{"com.docker.compose.config-hash":(if $scenario == "old-config" then "old" else $hash end)}},
            Image:(if $scenario == "old-image" then "sha256:old" else "sha256:requested" end),
            State:{Running:($scenario != "stopped"), Paused:false, Restarting:($scenario == "restarting"),
              Health:{Status:(if $scenario == "unhealthy" then "unhealthy" else "healthy" end)}}
          }';;
        */stacks/1\?*)
          touch "$work_dir/mutated"
          case " $* " in
            *" -o /dev/null "*) :;;
            *) echo 'STACK_SECRET_MUST_NOT_APPEAR';;
          esac;;
        */stacks/1)
          printf '%s' '{"Name":"portless-test","EndpointId":3,"Env":[{"name":"PORTLESS_CONTAINER_NAME","value":"portless-client"},{"name":"PORTLESS_CLIENT_IMAGE","value":"ghcr.io/crbl-technologies/portless-client:prod"},{"name":"PORTLESS_UI_ADDR","value":"off"},{"name":"PORTLESS_DEVICE_TOKEN","value":"test-only"},{"name":"PORTLESS_PMS_URL","value":"http://plex:32400"},{"name":"PORTLESS_CONTROL_URL","value":"https://control.example.test"}]}';;
        *) echo "Unexpected API path" >&2; return 1;;
      esac
    }
    sleep() { :; }
    source .github/scripts/deploy-client-stacks.sh
  ) >"$work_dir/result" 2>&1; then
    [ "$scenario" = healthy ] || { echo "Incorrect success: $scenario" >&2; exit 1; }
  else
    [ "$scenario" != healthy ] || { cat "$work_dir/result" >&2; exit 1; }
  fi
  if grep -q STACK_SECRET_MUST_NOT_APPEAR "$work_dir/result"; then
    echo "Stack update exposed its response" >&2
    exit 1
  fi
  if [ "$scenario" = legacy-image ] && [ -e "$work_dir/mutated" ]; then
    echo "Legacy image was rejected after mutating the stack" >&2
    exit 1
  fi
done
echo 'Client rollout verification scenarios passed'
