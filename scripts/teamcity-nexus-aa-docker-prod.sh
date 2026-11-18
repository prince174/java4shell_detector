#!/bin/sh
set -eu

build_id=${1-}
case "$build_id" in
  ''|*[!0-9]*)
    printf '%s\n' 'Usage: sh scripts/teamcity-nexus-aa-docker-prod.sh <TeamCity build ID>' >&2
    exit 2
    ;;
esac

: "${NEXUS_URL:?Set env.NEXUS_URL in TeamCity}"
: "${NEXUS_REST_USERNAME:?Set env.NEXUS_REST_USERNAME in TeamCity}"
: "${NEXUS_REST_PASSWORD:?Set env.NEXUS_REST_PASSWORD in TeamCity}"

exec docker compose run --build --rm --no-deps -T \
  -e NEXUS_URL \
  -e NEXUS_REST_USERNAME \
  -e NEXUS_REST_PASSWORD \
  -e NEXUS_TOKEN= \
  -e NEXUS_DOCKER_USERNAME= \
  -e NEXUS_DOCKER_PASSWORD= \
  java4shell_detector \
  python nexus_inventory.py \
    --repository aa-docker-prod \
    --java-majors 17,21,25,27 \
    --delay 0.1 \
    --output "/reports/nexus-cli/$build_id"
