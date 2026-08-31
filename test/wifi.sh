#!/usr/bin/env bash
#
# wifi.sh - real-NIC test: the server takes over the physical WiFi NIC and a
# client inside a netns gets internet access purely via L2, through a tap that
# clones the WiFi NIC (same MAC).  Needs root.
#
#   root netns                                netns l2t-wifi
#   ┌────────────────────────────┐            ┌────────────────────────┐
#   │ wlp8s0 192.168.1.101/24    │            │ wifi0 (tap, MAC clone  │
#   │  ▲ AF_PACKET promisc       │   real     │      of wlp8s0)        │
#   │  │                         │   WiFi     │ 192.168.1.<free>/24    │
#   │ a2tp-srv -i wlp8s0 ◄───────┼── L2 ──────┼──► a2tp-cli            │
#   └──────┬─────────────────────┘  (overlay) └────────┬───────────────┘
#          │ UDP 1702 (underlay)                        │
#   l2t-wu0 10.9.1.1/24 ══ veth (mtu 2000) ══ l2t-wu1 10.9.1.2/24
#
# The underlay veth carries only the tunnel UDP; every other byte the netns
# sends or receives is a real frame on the real WiFi LAN (ARP to the router,
# ICMP/DNS/HTTP to the internet).  The tap must clone the WiFi MAC: 802.11
# in managed mode only delivers unicast addressed to the station's own MAC.
#
set -u
cd "$(dirname "$0")/.."

WIFI_IF=${1:-wlp8s0}
NS=l2t-wifi
U_HOST=l2t-wu0; U_NS=l2t-wu1
U_HOST_IP=10.9.1.1; U_NS_IP=10.9.1.2
TAP=wifi0
SRV_LOG=/tmp/a2tp-wifi-srv.log; CLI_LOG=/tmp/a2tp-wifi-cli.log
DNS_PRIMARY=192.168.1.1; DNS_SECONDARY=223.5.5.5   # overwritten below

PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }
ok()  { say "PASS: $*"; PASS=$((PASS+1)); }
bad() { say "FAIL: $*"; FAIL=$((FAIL+1)); }

SRV_PID=""; CLI_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    sleep 0.4
    ip netns del "$NS" 2>/dev/null
    ip link del "$U_HOST" 2>/dev/null
    rm -rf "/etc/netns/$NS"
    # firewalld puts unknown interfaces into the default zone, which drops
    # inbound UDP (ping is allowed) -- undo the runtime trust added below
    command -v firewall-cmd >/dev/null && firewall-cmd --zone=trusted \
        --remove-interface="$U_HOST" >/dev/null 2>&1
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/wifi.sh [iface]"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }

# ---------- facts about the real network ----------
WIFI_MAC=$(cat "/sys/class/net/$WIFI_IF/address" 2>/dev/null) || { say "no such iface: $WIFI_IF"; exit 1; }
LAN_ADDR=$(ip -4 addr show dev "$WIFI_IF" | awk '/inet /{print $2; exit}')
GW=$(ip route show default dev "$WIFI_IF" | awk '{print $3; exit}')
[ -n "$LAN_ADDR" ] && [ -n "$GW" ] || { say "$WIFI_IF has no IPv4/default route (not associated?)"; exit 1; }
LAN_BASE=${LAN_ADDR%/*}; LAN_BASE=${LAN_BASE%.*}      # 192.168.1
MY_HOST_IP=${LAN_ADDR%/*}
DNS_PRIMARY=$GW
say "wifi: $WIFI_IF mac=$WIFI_MAC ip=$LAN_ADDR gw=$GW"

# pick a free address in the WiFi subnet (ping + ARP probe from the host)
FREE_IP=""
for n in 250 240 230 220 210 209 208 207; do
    cand="$LAN_BASE.$n"
    [ "$cand" = "$MY_HOST_IP" ] && continue
    ping -I "$WIFI_IF" -c1 -W1 "$cand" >/dev/null 2>&1 && continue
    ip neigh show "$cand" dev "$WIFI_IF" | grep -q lladdr && continue
    FREE_IP="$cand"; break
done
[ -n "$FREE_IP" ] || { say "no free address found in $LAN_BASE.0/24"; exit 1; }
say "using $FREE_IP/24 for the cloned tap"

# ---------- topology: underlay veth + client netns ----------
ip netns del "$NS" 2>/dev/null; ip link del "$U_HOST" 2>/dev/null
ip netns add "$NS"
ip link add "$U_HOST" type veth peer name "$U_NS"
ip link set "$U_NS" netns "$NS"
ip addr add "$U_HOST_IP/24" dev "$U_HOST"
ip -n "$NS" addr add "$U_NS_IP/24" dev "$U_NS"
# mtu 2000 so inner 1514-byte frames never need outer IP fragmentation
ip link set "$U_HOST" mtu 2000 up
ip -n "$NS" link set "$U_NS" mtu 2000 up
ip -n "$NS" link set lo up
# veth tx-checksumming hands the peer stack frames with placeholder L4
# checksums, which it then silently drops; the tunnel's outer UDP rides this
# veth, so both ends must emit plain checksummed datagrams
command -v ethtool >/dev/null && {
    ethtool -K "$U_HOST" tx off 2>/dev/null
    ip netns exec "$NS" ethtool -K "$U_NS" tx off 2>/dev/null
}
# firewalld assigns unknown interfaces to the default zone (drops inbound
# UDP while allowing ping); trust the underlay veth for this run
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --zone=trusted --add-interface="$U_HOST" >/dev/null
    say "firewalld: $U_HOST added to trusted zone (runtime)"
fi
mkdir -p "/etc/netns/$NS"
printf 'nameserver %s\nnameserver %s\n' "$DNS_PRIMARY" "$DNS_SECONDARY" > "/etc/netns/$NS/resolv.conf"

# ---------- tunnel ----------
: > "$SRV_LOG"; : > "$CLI_LOG"
# --bind the underlay veth address: the server runs in the root netns, and a
# 0.0.0.0 bind would also hear loopback, where unrelated local services' UDP
# to the same port would be learned as the peer and steal the mirror
"$PWD/a2tp-srv" -i "$WIFI_IF" --bind "$U_HOST_IP" >"$SRV_LOG" 2>&1 & SRV_PID=$!
sleep 0.7
ip netns exec "$NS" "$PWD/a2tp-cli" -s "$U_HOST_IP" -p 0 --tap "$TAP" \
    --mac "$WIFI_MAC" >"$CLI_LOG" 2>&1 & CLI_PID=$!
sleep 1
# addressing/routing is this script's job, not the client's
ip -n "$NS" addr replace "$FREE_IP/24" dev "$TAP"
ip -n "$NS" route replace default via "$GW" dev "$TAP"
ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.arp_notify=1 2>/dev/null

say "tunnel up: server pid $SRV_PID, client pid $CLI_PID"

# ---------- W1: server learned the client over the underlay ----------
sleep 1
if grep -qE 'peer: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+ \((learned|updated)\)' "$SRV_LOG"; then
    ok "W1 server learned the client peer"
else
    bad "W1 server did not learn a peer"; cat "$SRV_LOG"
fi

# ---------- W2: ARP for the real gateway resolves through the tunnel ----------
if ip netns exec "$NS" ping -I "$TAP" -c3 -W2 "$GW" >/tmp/w2.ping 2>&1; then
    ok "W2 netns -> real gateway $GW ping (ARP+ICMP via cloned WiFi L2)"
else
    bad "W2 cannot ping gateway"; cat /tmp/w2.ping; tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- W3: internet IP reachable ----------
if ip netns exec "$NS" ping -I "$TAP" -c3 -W3 223.5.5.5 >/tmp/w3.ping 2>&1; then
    ok "W3 netns -> internet 223.5.5.5 (routed by the real WiFi router)"
else
    bad "W3 cannot reach the internet"; cat /tmp/w3.ping
fi

# ---------- W4: DNS through the tunnel ----------
if ip netns exec "$NS" getent hosts www.baidu.com >/tmp/w4.dns 2>&1; then
    ok "W4 DNS resolves via the real LAN resolver ($(head -1 /tmp/w4.dns | awk '{print $1}'))"
else
    bad "W4 DNS failed"; cat /tmp/w4.dns
fi

# ---------- W5: HTTP round trip ----------
if command -v curl >/dev/null; then
    code=$(ip netns exec "$NS" curl -s -m 10 -o /dev/null -w '%{http_code}' http://www.baidu.com 2>/tmp/w5.err)
    if [ "$code" = "200" ]; then
        ok "W5 HTTP 200 from www.baidu.com through the L2 tunnel"
    else
        bad "W5 HTTP failed (code='$code')"; cat /tmp/w5.err
    fi
fi

# ---------- summary ----------
say ""
say "tap in netns $NS:"; ip -n "$NS" -br addr show "$TAP" 2>/dev/null
say "neighbors:";       ip -n "$NS" neigh show dev "$TAP" 2>/dev/null | head -5
say "routes:";          ip -n "$NS" route show 2>/dev/null
say ""
say "server log tail:";  tail -n 3 "$SRV_LOG"
say "client log tail:";  tail -n 3 "$CLI_LOG"
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL  (logs: $SRV_LOG $CLI_LOG)"
say "========================================="
[ "$FAIL" -eq 0 ]
