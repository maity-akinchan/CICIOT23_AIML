#!/usr/bin/env bash
# Download and verify a replay collector.
set -euo pipefail
base=${1:?Usage: setup-collector.sh http://server.example:8000}
case "$base" in http://*|https://*) ;; *) echo 'HTTP or HTTPS server URL required'; exit 1;; esac
case "$(uname -s)" in Linux) os=linux;; Darwin) os=darwin;; *) exit 1;; esac
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
umask 077
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
name="collector-$os-$arch"
curl --fail --silent --show-error "$base/api/v1/downloads/collectors/$name" -o "$work/$name"
curl --fail --silent --show-error "$base/api/v1/downloads/collectors/SHA256SUMS" -o "$work/SHA256SUMS"
(cd "$work"; if command -v sha256sum >/dev/null; then sha256sum --check --ignore-missing SHA256SUMS; else awk -v name="$name" '$2 == name' SHA256SUMS | shasum -a 256 --check; fi)
mkdir -p "$HOME/.local/bin"
install -m 700 "$work/$name" "$HOME/.local/bin/sentinel-collector"
echo 'Installed ~/.local/bin/sentinel-collector. Run:'
printf '%s\n' "~/.local/bin/sentinel-collector --mode pcap --pcap-file capture.pcap --api-url $base/api/v1/ingest/windows"
