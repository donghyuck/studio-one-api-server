#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f ".env.local" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue

    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    key="${key#export }"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"

    [[ -z "$key" ]] && continue
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "WARN: skip invalid env key in .env.local: $key"
      continue
    fi

    if [[ "$value" =~ ^\".*\"$ ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" =~ ^\'.*\'$ ]]; then
      value="${value:1:${#value}-2}"
    fi

    export "$key=$value"
  done < ".env.local"
  echo "OK: loaded .env.local"
else
  echo "INFO: .env.local not found; running with current environment"
fi

profile="${RUN_PROFILE:-dev}"
if [[ $# -gt 0 && "${1#-}" == "$1" ]]; then
  profile="$1"
  shift
fi

: "${NEXUS_RELEASES_URL:=http://localhost:8081/repository/maven-releases/}"
: "${NEXUS_ALLOW_INSECURE:=true}"

is_port_in_use() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  return 1
}

if [[ -z "${SERVER_PORT:-}" ]]; then
  SERVER_PORT=8080
  if is_port_in_use "$SERVER_PORT"; then
    for candidate in 8082 8083 8084 8085; do
      if ! is_port_in_use "$candidate"; then
        SERVER_PORT="$candidate"
        echo "WARN: port 8080 is already in use; using SERVER_PORT=$SERVER_PORT"
        break
      fi
    done
  fi
  export SERVER_PORT
fi

gradle_args=(
  "bootRun"
  "-Pprofile=${profile}"
  "-Pnexus.releasesUrl=${NEXUS_RELEASES_URL}"
  "-Pnexus.allowInsecure=${NEXUS_ALLOW_INSECURE}"
)

if [[ -n "${OPENAI_API_KEY:-}" ]]; then
  export SPRING_AI_OPENAI_API_KEY="${SPRING_AI_OPENAI_API_KEY:-$OPENAI_API_KEY}"
  export OPENAI_PROVIDER_ENABLED="${OPENAI_PROVIDER_ENABLED:-true}"
  echo "OK: OpenAI API key detected"
else
  export OPENAI_PROVIDER_ENABLED="${OPENAI_PROVIDER_ENABLED:-false}"
  openai_excludes=(
    "org.springframework.ai.model.openai.autoconfigure.OpenAiChatAutoConfiguration"
    "org.springframework.ai.model.openai.autoconfigure.OpenAiEmbeddingAutoConfiguration"
    "org.springframework.ai.model.openai.autoconfigure.OpenAiImageAutoConfiguration"
    "org.springframework.ai.model.openai.autoconfigure.OpenAiModerationAutoConfiguration"
    "org.springframework.ai.model.openai.autoconfigure.OpenAiAudioSpeechAutoConfiguration"
    "org.springframework.ai.model.openai.autoconfigure.OpenAiAudioTranscriptionAutoConfiguration"
  )
  IFS=,
  gradle_args+=("-Dspring.autoconfigure.exclude=${openai_excludes[*]}")
  unset IFS
  echo "INFO: OPENAI_API_KEY not set; excluding OpenAI auto-configurations"
fi

./gradlew "${gradle_args[@]}" "$@"
