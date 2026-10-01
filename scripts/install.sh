#!/usr/bin/env bash
# Max301 one-command installer for a Linux node.
#
#   curl -fsSL https://raw.githubusercontent.com/OWNER/max301/main/scripts/install.sh | sudo bash -s -- \
#       --role exit --password 'SHARED_SECRET'
#
#   curl -fsSL .../install.sh | sudo bash -s -- \
#       --role relay --password 'SHARED_SECRET' --next-hop 1.2.3.4 --redundancy 3
#
# Builds from source when Go is present, otherwise fetches a release binary.
# Writes the config, installs a systemd service, tunes UDP buffers, opens ports.

set -euo pipefail

REPO="${MAX301_REPO:-OWNER/max301}"
BRANCH="${MAX301_BRANCH:-main}"

ROLE=""
PASSWORD=""
NEXT_HOP=""
REDUNDANCY=""
IN_PORTS=""
OUT_PORTS=""

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)        ROLE="${2:-}"; shift 2 ;;
    --password)    PASSWORD="${2:-}"; shift 2 ;;
    --next-hop)    NEXT_HOP="${2:-}"; shift 2 ;;
    --redundancy)  REDUNDANCY="${2:-}"; shift 2 ;;
    --in-ports)    IN_PORTS="${2:-}"; shift 2 ;;
    --out-ports)   OUT_PORTS="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "must run as root (prefix the command with sudo)"
[[ "$ROLE" == "relay" || "$ROLE" == "exit" ]] || die "--role must be 'relay' or 'exit'"
[[ -n "$PASSWORD" ]] || die "--password is required; the same value must be used on every node"
[[ ${#PASSWORD} -ge 16 ]] || die "--password must be at least 16 characters"

if [[ "$ROLE" == "relay" ]]; then
  [[ -n "$NEXT_HOP" ]] || die "--next-hop is required for a relay: the IP of the hop closer to the game server"
fi

# Defaults. A relay listens on two ports and fans out to four; an exit accepts
# four so it can receive whatever the last hop spreads across.
if [[ "$ROLE" == "exit" ]]; then
  IN_PORTS="${IN_PORTS:-20001,20002,20003,20004}"
else
  IN_PORTS="${IN_PORTS:-20001,20002}"
  OUT_PORTS="${OUT_PORTS:-20001,20002,20003,20004}"
  REDUNDANCY="${REDUNDANCY:-2}"
fi

yaml_list() { echo "[$(echo "$1" | tr -d ' ')]"; }

port_lo() { echo "$1" | tr ',' '\n' | sort -n | head -1; }
port_hi() { echo "$1" | tr ',' '\n' | sort -n | tail -1; }

# Redundancy above the port count would send copies to ports nobody listens on;
# the binary rejects it at startup, so catch it here with a clearer message.
if [[ "$ROLE" == "relay" ]]; then
  out_count=$(echo "$OUT_PORTS" | tr ',' '\n' | grep -c .)
  [[ "$REDUNDANCY" -le "$out_count" ]] || \
    die "--redundancy $REDUNDANCY exceeds the $out_count outbound ports; add ports or lower it"
fi

info "installing dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl ca-certificates >/dev/null
fi

BIN_PATH="/usr/local/bin/max301-$ROLE"

info "obtaining the $ROLE binary"
if command -v go >/dev/null 2>&1; then
  # Build from source: no trust in a prebuilt artefact required.
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  curl -fsSL "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
    | tar xz -C "$WORK" --strip-components=1
  ( cd "$WORK" && go build -trimpath -ldflags="-s -w" -o "$BIN_PATH" "./cmd/$ROLE" )
  echo "    built from source with $(go version | awk '{print $3}')"
else
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)  ASSET="$ROLE-linux-amd64" ;;
    aarch64) ASSET="$ROLE-linux-arm64" ;;
    *) die "no prebuilt binary for $ARCH; install Go and rerun to build from source" ;;
  esac
  URL="https://github.com/$REPO/releases/latest/download/$ASSET"
  curl -fsSL -o "$BIN_PATH" "$URL" || \
    die "could not download $URL (no release published yet? install Go to build from source instead)"
  echo "    downloaded $ASSET"
fi
chmod 0755 "$BIN_PATH"

info "writing /etc/max301/$ROLE.yaml"
mkdir -p /etc/max301
chmod 0750 /etc/max301

if [[ "$ROLE" == "exit" ]]; then
  cat > "/etc/max301/$ROLE.yaml" <<EOF
mode: exit
inbound:
  listen: "0.0.0.0"
  ports: $(yaml_list "$IN_PORTS")
  password: "$PASSWORD"
outbound:
  mode: "nat"
  nat_timeout: 2m
log:
  level: "info"
EOF
else
  cat > "/etc/max301/$ROLE.yaml" <<EOF
mode: relay
inbound:
  listen: "0.0.0.0"
  ports: $(yaml_list "$IN_PORTS")
  password: "$PASSWORD"
outbound:
  host: "$NEXT_HOP"
  ports: $(yaml_list "$OUT_PORTS")
  password: "$PASSWORD"
  redundancy: $REDUNDANCY
log:
  level: "info"
EOF
fi
chmod 0600 "/etc/max301/$ROLE.yaml"

info "tuning UDP buffers"
# Redundant sending multiplies packet counts and the default 212 KiB socket
# buffer overflows during a burst.
cat > /etc/sysctl.d/99-max301.conf <<'SYSCTL'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 4096
SYSCTL
sysctl -q -p /etc/sysctl.d/99-max301.conf || true

info "installing the systemd service"
cat > "/etc/systemd/system/max301-$ROLE.service" <<UNIT
[Unit]
Description=Max301 $ROLE node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_PATH -c /etc/max301/$ROLE.yaml
Restart=always
RestartSec=2

# A game tunnel is latency-sensitive: a shorter GC cycle trades a little CPU for
# fewer pauses.
Environment=GOGC=20

LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/max301

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "max301-$ROLE" >/dev/null 2>&1

LO="$(port_lo "$IN_PORTS")"
HI="$(port_hi "$IN_PORTS")"
info "opening UDP $LO-$HI"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$LO:$HI/udp" >/dev/null && echo "    ufw rule added"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$LO-$HI/udp" >/dev/null
  firewall-cmd --reload >/dev/null
  echo "    firewalld rule added"
else
  echo "    no active host firewall detected"
fi

if [[ "$ROLE" == "exit" ]]; then
  info "enabling IP forwarding"
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-max301-forward.conf
  sysctl -q -p /etc/sysctl.d/99-max301-forward.conf || true
fi

info "starting max301-$ROLE"
systemctl restart "max301-$ROLE"
sleep 2

if systemctl is-active --quiet "max301-$ROLE"; then
  echo
  echo "max301-$ROLE is running."
  systemctl status "max301-$ROLE" --no-pager -n 4 | tail -5
else
  echo
  echo "max301-$ROLE failed to start:" >&2
  journalctl -u "max301-$ROLE" -n 20 --no-pager >&2
  exit 1
fi

PUBLIC_IP="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || echo '<this-host>')"
cat <<DONE

------------------------------------------------------------
Role        : $ROLE
Public IP   : $PUBLIC_IP
Inbound     : UDP $IN_PORTS
$(if [[ "$ROLE" == "relay" ]]; then echo "Next hop    : $NEXT_HOP (UDP $OUT_PORTS, redundancy $REDUNDANCY)"; fi)

Point the previous hop at:  $PUBLIC_IP  ports $IN_PORTS

Logs    : journalctl -u max301-$ROLE -f
Restart : systemctl restart max301-$ROLE
------------------------------------------------------------

If a cloud firewall or security group sits in front of this host, open UDP
$LO-$HI there too. The host firewall rule above does not cover it.
DONE
