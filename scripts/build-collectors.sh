#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../collector-go"
mkdir -p ../dist/collectors
for os in linux darwin windows; do
 for arch in amd64 arm64; do
  suffix=''; [ "$os" != windows ] || suffix='.exe'
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "../dist/collectors/collector-${os}-${arch}${suffix}" .
 done
done
(cd ../dist/collectors && sha256sum collector-* > SHA256SUMS)
echo 'Offline replay binaries generated. Live Linux capture requires a native CGO/libpcap build.'
