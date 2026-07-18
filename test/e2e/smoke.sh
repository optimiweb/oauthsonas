#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-ghcr.io/optimiweb/oauthsonas:latest}"
NAME="oauthsonas-smoke-$$"

cleanup() {
  docker rm -f "$NAME" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== smoke: --version ==="
docker run --rm "$IMAGE" --version
echo ""

echo "=== smoke: default CMD (start server) ==="
docker run -d --rm --name "$NAME" -e OAUTHSONAS_ALLOW_NON_LOOPBACK=true -p 0:8181 "$IMAGE"
PORT=$(docker port "$NAME" 8181 | head -1 | cut -d: -f2)
BASE="http://127.0.0.1:${PORT}"

for i in $(seq 1 30); do
  if curl -sf "$BASE/healthz" > /dev/null 2>&1; then
    echo "  server ready after ${i}s"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  server did not start within 30s" >&2
    docker logs "$NAME"
    exit 1
  fi
  sleep 1
done

echo "=== smoke: /healthz ==="
HEALTH=$(curl -sf "$BASE/healthz")
echo "  $HEALTH"
echo "$HEALTH" | grep -q '"status":"ok"'
echo "$HEALTH" | grep -q '"issuer"'

echo "=== smoke: /readyz ==="
READY=$(curl -sf "$BASE/readyz")
echo "  $READY"
echo "$READY" | grep -q '"status":"ready"'

echo "=== smoke: /.well-known/openid-configuration ==="
DISC=$(curl -sf "$BASE/.well-known/openid-configuration")
echo "  issuer: $(echo "$DISC" | grep -o '"issuer":"[^"]*"')"
echo "$DISC" | grep -q '"authorization_endpoint"'
echo "$DISC" | grep -q '"token_endpoint"'
echo "$DISC" | grep -q '"jwks_uri"'

echo ""
echo "=== smoke: PASS ==="
