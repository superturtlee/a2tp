#!/usr/bin/env bash
#
# wifi-multiip.sh - multi-IP NIC test on the real WiFi NIC: the host keeps its
# own IP on the NIC, a second IP is handed to a remote client through the
# tunnel (deleted from the host stack; the server mirrors only traffic for it,
# ARP passes through and the client's stack answers for it).  Both the NIC
# (host IP) and the cloned tap (moved IP) must reach the internet.  Needs root.
#
#   root netns                                 netns l2t-mip
#   ┌─────────────────────────────┐            ┌────────────────────────┐
#   │ wlp8s0 192.168.1.101 (kept) │            │ wifi0 (tap, MAC clone  │
#   │        192.168.1.123 ══► DELETED          │        of wlp8s0)      │
#   │ a2tp-srv --filter-ip .123   │   real     │ 192.168.1.123/24       │
#   │   (only .123 is mirrored)   │   WiFi     │ a2tp-cli               │
#   └───────┬─────────────────────┘  L2        └────────┬───────────────┘
#           │ underlay veth 10.9.2.1/2 (udp 1702)       │
#
# ARP: the server stays stateless and passes ARP through.  Ownership is
# disjoint -- the host stack answers for .101 (still its address), the
# client's stack answers for .123 (the only place it exists now) -- so there
# is nobody to race with.
#
set -u
cd "$(dirname "$0")/.."

WIFI_IF=${1:-wlp8s0}
TUNNEL_IP=${2:-192.168.1.123}
NS=l2t-mip
U_HOST=l2t-wm0; U_NS=l2t-wm1
U_HOST_IP=10.9.2.1; U_NS_IP=10.9.2.2
TAP=wifi0
SRV_LOG=/tmp/a2tp-mip-srv.log; CLI_LOG=/tmp/a2tp-mip-cli.log

PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }
ok()  { say "PASS: $*"; PASS=$((PASS+1)); }
bad() { say "FAIL: $*"; FAIL=$((FAIL+1)); }

SRV_PID=""; CLI_PID=""; IP_RESTORE=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    sleep 0.4
    ip netns del "$NS" 2>/dev/null
    ip link del "$U_HOST" 2>/dev/null
    rm -rf "/etc/netns/$NS"
    command -v firewall-cmd >/dev/null && firewall-cmd --zone=trusted \
        --remove-interface="$U_HOST" >/dev/null 2>&1
    # put the moved IP back exactly as we found it
    if [ -n "$IP_RESTORE" ]; then
        ip addr add "$IP_RESTORE" dev "$WIFI_IF" 2>/dev/null
        say "restored $IP_RESTORE on $WIFI_IF"
    fi
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/wifi-multiip.sh [iface] [ip]"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }

# ---------- facts about the real network ----------
WIFI_MAC=$(cat "/sys/class/net/$WIFI_IF/address" 2>/dev/null) || { say "no such iface: $WIFI_IF"; exit 1; }
LAN_ADDR=$(ip -4 addr show dev "$WIFI_IF" | awk '/inet /{print $2; exit}')
GW=$(ip route show default dev "$WIFI_IF" | awk '{print $3; exit}')
[ -n "$LAN_ADDR" ] && [ -n "$GW" ] || { say "$WIFI_IF has no IPv4/default route (not associated?)"; exit 1; }
HOST_IP=${LAN_ADDR%/*}
say "wifi: $WIFI_IF mac=$WIFI_MAC ip=$LAN_ADDR gw=$GW ; host keeps $HOST_IP, client takes $TUNNEL_IP"

# ---------- take the IP away from the host stack ----------
if ip -4 addr show dev "$WIFI_IF" | grep -q "inet $TUNNEL_IP/"; then
    IP_RESTORE=$(ip -4 addr show dev "$WIFI_IF" | awk -v ip="$TUNNEL_IP" \
        '$0 ~ "inet "ip"/" {print $2; exit}')
    ip addr del "$IP_RESTORE" dev "$WIFI_IF" \
        || { say "could not delete $TUNNEL_IP from $WIFI_IF"; exit 1; }
    say "deleted $IP_RESTORE from the host stack (restored on exit)"
elif ping -I "$WIFI_IF" -c1 -W1 "$TUNNEL_IP" >/dev/null 2>&1; then
    say "$TUNNEL_IP answers somewhere else on the LAN; pick a free address"; exit 1
else
    say "$TUNNEL_IP is not on the host and seems free"
fi
ip neigh flush dev "$WIFI_IF" 2>/dev/null

# ---------- topology: underlay veth + client netns (same as wifi.sh) --------
ip netns del "$NS" 2>/dev/null; ip link del "$U_HOST" 2>/dev/null
ip netns add "$NS"
ip link add "$U_HOST" type veth peer name "$U_NS"
ip link set "$U_NS" netns "$NS"
ip addr add "$U_HOST_IP/24" dev "$U_HOST"
ip -n "$NS" addr add "$U_NS_IP/24" dev "$U_NS"
ip link set "$U_HOST" mtu 2000 up
ip -n "$NS" link set "$U_NS" mtu 2000 up
ip -n "$NS" link set lo up
command -v ethtool >/dev/null && {
    ethtool -K "$U_HOST" tx off 2>/dev/null
    ip netns exec "$NS" ethtool -K "$U_NS" tx off 2>/dev/null
}
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --zone=trusted --add-interface="$U_HOST" >/dev/null
    say "firewalld: $U_HOST added to trusted zone (runtime)"
fi
mkdir -p "/etc/netns/$NS"
printf 'nameserver %s\nnameserver %s\n' "$GW" "223.5.5.5" > "/etc/netns/$NS/resolv.conf"

# ---------- tunnel ----------
: > "$SRV_LOG"; : > "$CLI_LOG"
"$PWD/a2tp-srv" -i "$WIFI_IF" --bind "$U_HOST_IP" --filter-ip "$TUNNEL_IP" \
    >"$SRV_LOG" 2>&1 & SRV_PID=$!
sleep 0.7
ip netns exec "$NS" "$PWD/a2tp-cli" -s "$U_HOST_IP" -p 0 --tap "$TAP" \
    --mac "$WIFI_MAC" >"$CLI_LOG" 2>&1 & CLI_PID=$!
sleep 1
ip -n "$NS" addr replace "$TUNNEL_IP/24" dev "$TAP"
ip -n "$NS" route replace default via "$GW" dev "$TAP"
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.arp_notify=1 2>/dev/null

say "tunnel up: server pid $SRV_PID (filter $TUNNEL_IP), client pid $CLI_PID"

# ---------- M1: host internet through the NIC's own IP (unfiltered path) ----
sleep 1
if ping -I "$WIFI_IF" -c3 -W2 223.5.5.5 >/dev/null 2>&1; then
    ok "M1 host $HOST_IP still reaches the internet (its IP stayed local)"
else
    bad "M1 host lost internet"
fi

# ---------- M2: client internet through the moved IP (mirrored path) --------
if ip netns exec "$NS" ping -I "$TAP" -c3 -W3 223.5.5.5 >/tmp/m2.ping 2>&1; then
    ok "M2 client $TUNNEL_IP reaches the internet (ARP + traffic via tunnel)"
else
    bad "M2 client cannot reach the internet"; cat /tmp/m2.ping
fi

# ---------- M3: DNS + HTTP through the moved IP -----------------------------
if ip netns exec "$NS" getent hosts www.baidu.com >/tmp/m3.dns 2>&1; then
    ok "M3 DNS via the real LAN resolver ($(head -1 /tmp/m3.dns | awk '{print $1}'))"
else
    bad "M3 DNS failed"; cat /tmp/m3.dns
fi
if command -v curl >/dev/null; then
    code=$(ip netns exec "$NS" curl -s -m 10 -o /dev/null -w '%{http_code}' http://www.baidu.com 2>/dev/null)
    if [ "$code" = "200" ]; then
        ok "M4 HTTP 200 through the moved IP"
    else
        bad "M4 HTTP failed (code='$code')"
    fi
fi

# ---------- M5: isolation -- host traffic must not appear on the tap --------
ip netns exec "$NS" timeout 7 tcpdump -ni "$TAP" -c 8 \
    "ip and host $HOST_IP" >/tmp/m5.cap 2>&1 &
TD=$!
sleep 0.5
ping -I "$WIFI_IF" -c5 -W1 "$GW" >/dev/null 2>&1
wait $TD 2>/dev/null
if grep -q '0 packets captured' /tmp/m5.cap; then
    ok "M5 host traffic ($HOST_IP) never reached the tap (filter held)"
else
    bad "M5 host traffic leaked onto the tap:"; cat /tmp/m5.cap
fi

# ---------- summary ----------
say ""
say "host nic:";  ip -4 -br addr show dev "$WIFI_IF"
say "tap:";       ip -n "$NS" -br addr show "$TAP" 2>/dev/null
say "tap neighbors:"; ip -n "$NS" neigh show dev "$TAP" 2>/dev/null | head -3
say ""
say "server log tail:"; tail -n 4 "$SRV_LOG"
say "client log tail:"; tail -n 3 "$CLI_LOG"
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL  (logs: $SRV_LOG $CLI_LOG)"
say "========================================="
[ "$FAIL" -eq 0 ]
