#!/usr/bin/env bash
# Max301 one-command installer for a Linux node.
#
# Interactive: asks for the role, next hop and password, and detects this host's
# public address.
#
#   curl -fsSL https://raw.githubusercontent.com/l2039693695-boop/max301/main/scripts/install.sh | sudo bash
#
# Or pass everything up front, for a scripted install:
#
#   curl -fsSL .../install.sh | sudo bash -s -- --role exit --password 'SECRET'
#   curl -fsSL .../install.sh | sudo bash -s -- --role relay --password 'SECRET' \
#       --next-hop 1.2.3.4 --redundancy 3
#
# Builds from source when Go is present, otherwise fetches a release binary.
# Writes the config, installs a systemd service, tunes UDP buffers, opens ports.

set -euo pipefail

REPO="${MAX301_REPO:-l2039693695-boop/max301}"
BRANCH="${MAX301_BRANCH:-main}"

ROLE=""
PASSWORD=""
NEXT_HOP=""
REDUNDANCY=""
IN_PORTS=""
OUT_PORTS=""
WIZARD=0

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
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "must run as root (prefix the command with sudo)"

# ----------------------------------------------------------------- wizard ---
# With "curl ... | bash" the script itself occupies stdin, so prompts have to
# read the terminal directly or they would consume the script's own text.
ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [[ -n "$def" ]]; then
    printf '%s [%s]: ' "$prompt" "$def" > /dev/tty
  else
    printf '%s: ' "$prompt" > /dev/tty
  fi
  IFS= read -r ans < /dev/tty || true
  echo "${ans:-$def}"
}

say() { printf '%s\n' "$*" > /dev/tty; }

# The public address a client must point at, which on a NAT'd cloud instance is
# not any address the host itself can see.
detect_ip() {
  local ip u
  for u in https://api.ipify.org https://ifconfig.me/ip https://ipinfo.io/ip; do
    ip="$(curl -fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]')" || true
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "$ip"; return; fi
  done
  # No outbound HTTP: fall back to the source address of the default route.
  ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1
}

valid_ip() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }

if [[ -z "$ROLE" ]]; then
  [[ -r /dev/tty ]] || die "无法交互（没有终端）。请改用参数形式：--role exit --password '...'"
  command -v curl >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 || true; apt-get install -y -qq curl >/dev/null 2>&1 || true; }

  MY_IP="$(detect_ip)"
  say ""
  say "=============================================="
  say "        Max301 游戏加速 一键部署"
  say "=============================================="
  say ""
  say "  本机公网 IP : ${MY_IP:-未能自动识别}"
  say "  系统        : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s) / $(uname -m)"
  say ""
  say "  请选择本机的角色："
  say ""
  say "    1) 落地节点  —— 离游戏服最近的那台，流量从这里出去"
  say "    2) 中转节点  —— 中间跳，把流量转给下一跳"
  say ""
  while :; do
    sel="$(ask '  输入 1 或 2' '1')"
    case "$sel" in
      1) ROLE="exit";  say "  → 落地节点"; break ;;
      2) ROLE="relay"; say "  → 中转节点"; break ;;
      *) say "  只能输入 1 或 2" ;;
    esac
  done
  say ""

  if [[ "$ROLE" == "relay" ]]; then
    say "  中转节点需要知道「下一跳」的 IP —— 也就是更靠近游戏服的那台。"
    say "  如果下一跳就是落地节点，填落地节点的公网 IP。"
    say ""
    while :; do
      NEXT_HOP="$(ask '  下一跳 IP')"
      if ! valid_ip "$NEXT_HOP"; then
        say "  不是合法的 IPv4 地址"
      elif [[ "$NEXT_HOP" == "$MY_IP" ]]; then
        # Forwarding to itself would loop packets until the IP TTL expired.
        say "  下一跳不能是本机 IP，那样会自己转给自己"
      else
        break
      fi
    done
    say ""
    say "  冗余份数：每个游戏包复制几份发出去，用来对冲丢包。"
    say "    1 = 不复制（专线/很稳的线路，复制纯浪费带宽）"
    say "    2 = 普通线路"
    say "    3 = 抖动大的国际线路"
    say ""
    while :; do
      REDUNDANCY="$(ask '  冗余份数（1-4）' '2')"
      if [[ "$REDUNDANCY" =~ ^[1-4]$ ]]; then break; fi
      say "  请输入 1 到 4 之间的数字"
    done
    say ""
  fi
  say "  通信密码：所有节点和客户端必须填完全一样的一串，不一样的话"
  say "  连得上但一个包都通不了（密钥不同，解不开）。"
  say ""
  say "  第一台机器直接回车，脚本帮你生成；之后的机器粘贴同一串。"
  say ""
  while :; do
    PASSWORD="$(ask '  通信密码（回车=自动生成）')"
    if [[ -z "$PASSWORD" ]]; then
      PASSWORD="$(openssl rand -base64 32 2>/dev/null | tr -d '/+=' | cut -c1-32)"
      [[ -n "$PASSWORD" ]] || PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | cut -c1-32)"
      say "  已生成：$PASSWORD"
      break
    elif (( ${#PASSWORD} < 16 )); then
      say "  太短了，至少 16 位（当前 ${#PASSWORD} 位）"
    else
      break
    fi
  done

  say ""
  say "----------------------------------------------"
  say "  即将部署"
  say "----------------------------------------------"
  if [[ "$ROLE" == "exit" ]]; then
    say "  角色     : 落地节点"
  else
    say "  角色     : 中转节点"
    say "  下一跳   : $NEXT_HOP"
    say "  冗余份数 : $REDUNDANCY"
  fi
  say "  监听端口 : UDP 20001-20004"
  say "  密码     : $PASSWORD"
  say "----------------------------------------------"
  say ""
  c="$(ask '  确认开始？(y/n)' 'y')"
  case "$c" in [yY]*) ;; *) say "  已取消"; exit 0 ;; esac
  say ""
  WIZARD=1
fi
# --------------------------------------------------------------- /wizard ---
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

if [[ "$WIZARD" == "1" ]]; then
cat > /dev/tty <<ZH

==============================================
  部署完成
==============================================

  重要：云服务商的安全组在主机之外，上面的防火墙规则
  管不到它。请去控制台放行入站 UDP $LO-$HI，否则连不上。

ZH
  if [[ "$ROLE" == "exit" ]]; then
    cat > /dev/tty <<ZH
  这是落地节点。下一步装中转节点时，「下一跳 IP」填：
      $PUBLIC_IP

  也可以让客户端直连本机先验证通不通（推荐这样起步，
  少一跳出问题好定位）。客户端 client.yaml 填：

      host: "$PUBLIC_IP"
      ports: [20001, 20002]
      password: "$PASSWORD"

ZH
  else
    cat > /dev/tty <<ZH
  这是中转节点，流量转给 $NEXT_HOP。

  客户端 client.yaml 填本机地址：

      host: "$PUBLIC_IP"
      ports: [20001, 20002]
      password: "$PASSWORD"
      redundancy: 2

ZH
  fi
  cat > /dev/tty <<ZH
  常用命令：
      journalctl -u max301-$ROLE -f      看日志
      systemctl restart max301-$ROLE     重启
      systemctl status max301-$ROLE      看状态
==============================================

ZH
fi
