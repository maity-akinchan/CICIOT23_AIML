#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../collector-go"
[ "$(go env GOOS)" = linux ] || { echo 'Build on Linux with libpcap development headers installed'; exit 1; }
arch=$(go env GOARCH)
case "$arch" in amd64|arm64);; *) echo 'Unsupported architecture'; exit 1;; esac
mkdir -p ../dist/collectors
CGO_ENABLED=1 go build -trimpath -o "../dist/collectors/sentinel-service-linux-$arch" .
(cd ../dist/collectors; sha256sum sentinel-service-linux-* > LIVE-SHA256SUMS)
echo 'Built Linux live monitoring service. Target needs libpcap runtime.'
