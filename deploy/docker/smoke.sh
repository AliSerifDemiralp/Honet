#!/usr/bin/env bash
# Build the image for one platform and check that it starts and serves the
# setup page. Usage: deploy/docker/smoke.sh linux/arm/v6
set -euo pipefail
platform=${1:-linux/amd64}
root=$(cd "$(dirname "$0")/../.." && pwd)
name=honet-smoke-$$
tag=honet:smoke
port=${SMOKE_PORT:-18443}

docker build -q --platform "$platform" -t "$tag" "$root" >/dev/null
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" --platform "$platform" --cap-drop ALL --cap-add NET_RAW \
  --read-only -p "$port:8443" "$tag" >/dev/null

for _ in $(seq 1 90); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$port/setup" || true)
  [ "$code" = 200 ] && break
  sleep 1
done
if [ "${code:-}" != 200 ]; then
  echo "smoke FAILED: /setup returned ${code:-nothing}"; docker logs "$name" 2>&1 | tail -20; exit 1
fi
if ! docker logs "$name" 2>&1 | grep -q "HONET SETUP CODE"; then
  echo "smoke FAILED: no setup code in logs"; exit 1
fi
docker run --rm --platform "$platform" "$tag" version
echo "smoke ok ($platform)"
