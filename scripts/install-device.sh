#!/usr/bin/env bash
# Linux/systemd installer. Run as root on the monitored host, not on the server.
set -euo pipefail
base=${1:?Server HTTPS address required}
[[ "$base" =~ ^https://[a-zA-Z0-9.:_-]+$ ]] || { echo 'HTTPS server origin required'; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Run with sudo'; exit 1; }
[ "$(uname -s)" = Linux ] && command -v systemctl >/dev/null || { echo 'Linux/systemd required'; exit 1; }
if command -v apt-get >/dev/null; then
 apt-get update -qq
 apt-get install -y curl python3 libpcap-dev iproute2
elif command -v dnf >/dev/null; then
 dnf install -y curl python3 libpcap iproute
fi
iface=$(ip -o route show default | awk '{print $5; exit}')
read -rp "Network interface [${iface}]: " selected </dev/tty
iface=${selected:-$iface}
[[ "$iface" =~ ^[a-zA-Z0-9_.:-]+$ ]] && [ -e "/sys/class/net/$iface" ] || { echo 'Interface not found'; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) exit 1;; esac
if ! ldconfig -p | grep 'libpcap.so' >/dev/null; then
 echo 'Install the libpcap runtime first (Debian/Ubuntu: apt install libpcap0.8; Fedora: dnf install libpcap)'; exit 1
fi
read -rsp 'Paste the setup code from Monitoring service: ' code </dev/tty; echo
[[ "$code" =~ ^[A-Za-z0-9_-]+$ ]] || exit 1
umask 077
work=$(mktemp -d); trap 'rm -rf "$work"; unset code token' EXIT
printf '{"code":"%s"}' "$code" > "$work/enroll.json"
curl --fail-with-body --silent --show-error --proto '=https' -H 'Content-Type: application/json' --data-binary @"$work/enroll.json" "$base/api/v1/services/enroll" -o "$work/credential.json"
token=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' "$work/credential.json")
service_id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["collector_id"])' "$work/credential.json")
[[ "$service_id" =~ ^[a-zA-Z0-9_-]{1,64}$ && "$token" =~ ^[A-Za-z0-9_-]+$ ]] || exit 1
printf 'Authorization: Bearer %s\n' "$token" > "$work/header"
name="sentinel-service-linux-$arch"
curl --fail --silent --show-error --proto '=https' -H @"$work/header" "$base/api/v1/downloads/collectors/$name" -o "$work/$name"
curl --fail --silent --show-error --proto '=https' -H @"$work/header" "$base/api/v1/downloads/collectors/LIVE-SHA256SUMS" -o "$work/LIVE-SHA256SUMS"
(cd "$work"; awk -v n="$name" '$2==n' LIVE-SHA256SUMS > selected; test -s selected; sha256sum --check selected)
chmod 700 "$work/$name"
"$work/$name" --help >/dev/null 2>&1 || { echo 'Binary/runtime incompatible with this host. Build for this Linux distribution.'; exit 1; }
# Confirm the token is bound to the requested ID without submitting observations.
printf 'Authorization: Bearer %s\n' "$token" > "$work/header"
printf '{"collector_id":"%s"}' "$service_id" > "$work/check.json"
curl --fail --silent --show-error --proto '=https' -H @"$work/header" -H 'Content-Type: application/json' --data-binary @"$work/check.json" "$base/api/v1/services/verify" >/dev/null
install -m 755 "$work/$name" /usr/local/bin/sentinel-service
install -d -m 700 /etc/sentinel
printf 'SENTINEL_COLLECTOR_TOKEN=%s\n' "$token" > /etc/sentinel/service.env
chmod 600 /etc/sentinel/service.env
cat > /etc/systemd/system/sentinel-monitor.service <<EOF
[Unit]
Description=Sentinel network monitoring
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
DynamicUser=yes
EnvironmentFile=/etc/sentinel/service.env
ExecStart=/usr/local/bin/sentinel-service --mode live --iface $iface --collector-id $service_id --api-url $base/api/v1/ingest/windows
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_NETLINK AF_UNIX
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sentinel-monitor.service
echo 'Installed. Check: systemctl status sentinel-monitor; journalctl -u sentinel-monitor'
echo 'Uninstall: systemctl disable --now sentinel-monitor; remove /etc/systemd/system/sentinel-monitor.service, /usr/local/bin/sentinel-service and /etc/sentinel; systemctl daemon-reload'
