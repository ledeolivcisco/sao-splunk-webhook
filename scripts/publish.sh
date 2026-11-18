#!/usr/bin/env bash
# Build the image for amd64 + arm64 and push it to the registry.
#
#   ./scripts/publish.sh                 # leandrovo/sao-hec-bridge:latest
#   ./scripts/publish.sh v1.2.0          # ...:v1.2.0 and :latest
#   REPO=myorg/my-image ./scripts/publish.sh
#
# Multi-arch images cannot be loaded into the local Docker, so this builds and
# pushes in one step. Run `docker login` first.
set -euo pipefail

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${REPO:-leandrovo/sao-hec-bridge}"
TAG="${1:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

TAGS=(-t "$REPO:$TAG")
[[ "$TAG" != "latest" ]] && TAGS+=(-t "$REPO:latest")

# The default builder cannot do multi-arch; a docker-container one can.
docker buildx inspect multiarch >/dev/null 2>&1 \
  || docker buildx create --name multiarch --driver docker-container >/dev/null

echo "==> Building $REPO:$TAG for $PLATFORMS"
docker buildx build --builder multiarch --platform "$PLATFORMS" "${TAGS[@]}" --push "$ROOT"

echo "==> Pushed $REPO:$TAG"
docker buildx imagetools inspect "$REPO:$TAG" | grep -E 'Name|Platform'
