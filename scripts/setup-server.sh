#!/usr/bin/env bash
# Prepare a Linux node (relay or exit) to run Max301.
#
# Usage: ./setup-server.sh <relay|exit> [first-port] [port-count]
#
# Installs the binary as a systemd service, tunes the UDP buffers, and opens the
# ports. Run as root.

set -euo pipefail

ROLE="${1:-}"
FIRST_PORT="${2:-20001}"
PORT_COUNT="${3:-4}"

if [[ "$ROLE" != "relay" && "$ROLE" != "exit" ]]; then
  echo "usage: $0 <relay|exit> [first-port] [port-count]" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

BIN="/usr/local/bin/max301-$ROLE"
CONF="/etc/max301/$ROLE.yaml"

if [[ ! -f "./$ROLE" ]]; then
  echo "expected the compiled '$ROLE' binary in the current directory" >&2
  echo "build it with: GOOS=linux GOARCH=amd64 go build -o $ROLE ./cmd/$ROLE" >&2
  exit 1
fi

echo "==> installing binary"
install -m 0755 "./$ROLE" "$BIN"

echo "==> preparing configuration directory"
mkdir -p /etc/max301
if [[ ! -f "$CONF" ]]; then
  echo "no $CONF yet; copy the example and edit it before starting the service"
fi
chmod 0750 /etc/max301

echo "==> tuning UDP buffers"
# Redundant sending multiplies packet counts, and the default 212 KiB socket
# buffer overflows during a burst. These survive reboots.
cat > /etc/sysctl.d/99-max301.conf <<'SYSCTL'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 4096
SYSCTL
sysctl -q -p /etc/sysctl.d/99-max301.conf

echo "==> writing systemd unit"
cat > "/etc/systemd/system/max301-$ROLE.service" <<UNIT
[Unit]
Description=Max301 $ROLE node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -c $CONF
Restart=always
RestartSec=2

# A game tunnel is latency-sensitive: a shorter GC cycle trades a little CPU
# for fewer pauses.
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
systemctl enable "max301-$ROLE" >/dev/null

LAST_PORT=$((FIRST_PORT + PORT_COUNT - 1))
echo "==> opening UDP ${FIRST_PORT}-${LAST_PORT}"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${FIRST_PORT}:${LAST_PORT}/udp" >/dev/null
  echo "    added a ufw rule"
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${FIRST_PORT}-${LAST_PORT}/udp" >/dev/null
  firewall-cmd --reload >/dev/null
  echo "    added a firewalld rule"
else
  echo "    no active firewall found; open UDP ${FIRST_PORT}-${LAST_PORT} yourself if one is in front of this host"
fi

if [[ "$ROLE" == "exit" ]]; then
  echo "==> enabling IP forwarding"
  # The exit node forwards inner payloads from its own address.
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-max301-forward.conf
  sysctl -q -p /etc/sysctl.d/99-max301-forward.conf
fi

cat <<DONE

Done. Next:
  1. Put your configuration at $CONF (see configs/$ROLE.yaml.example)
  2. chmod 600 $CONF     # it holds the shared password
  3. systemctl start max301-$ROLE
  4. journalctl -u max301-$ROLE -f
DONE
