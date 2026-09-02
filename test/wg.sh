#!/usr/bin/env bash
#
# wg.sh - a2tp reliability suite with a WireGuard carrier (the "outer UDP
# rides wg0" production shape).  Needs root, a2tp.ko loaded and wireguard.ko
# plus the wg(8) tool.
#
# Topology (one VM, three netns; wg peers talk over a direct veth "internet"):
#
#   netns l2t-srv                              netns l2t-cli
#   ┌────────────────────────────┐             ┌────────────────────┐
#   │ l2t-s0 10.9.0.1/24 ═══════╪═════════════╪═ (LAN veth)        │
#   │   ▲ rx_handler mirror      │             │                    │
#   │ wg0 10.99.0.1/24  ═════════╪═════════════╪═ wg0 10.99.0.2/24 │
#   │   │ endpoint 192.0.2.21:51820            │   endpoint ...:51821
#   └───┼──────────────────────────────────────┴────────────────────┘
#       └── w-srv 192.0.2.11/24 ══ veth "internet" ══ w-cli 192.0.2.21/24
#
#   netns l2t-lan: l2t-l0 10.9.0.2/24 (the "LAN host" behind the server)
#
# The client's remote is 10.99.0.1 (the server's wg overlay address), so the
# a2tp outer UDP is routed into wg0 and crosses the veth only as encrypted
# Noise_IK traffic.  Then the carrier is broken in three ways and each time
# the tunnel must survive and resume:
#
#   W2  unpinned, route/carrier gone: client `ip link set wg0 down`
#   W3  server carrier pinned (-b 10.99.0.1), address deleted from wg0
#   W4  client carrier pinned (cli ... local 10.99.0.2), address deleted
#
# Never under test is instance teardown: only `srv del` or the taken-over NIC
# itself unregistering destroys anything.
#
set -u
cd "$(dirname "$0")/.."

NS_SRV=l2t-srv; NS_CLI=l2t-cli; NS_LAN=l2t-lan
V_SRV=l2t-s0;  V_LAN=l2t-l0
W_SRV=w-srv;   W_CLI=w-cli          # the veth "internet"
TAP=l2t-tap
WG_PORT_SRV=51821; WG_PORT_CLI=51820
U_SRV=192.0.2.11;  U_CLI=192.0.2.21  # underlay (veth) addresses
WG_SRV=10.99.0.1;  WG_CLI=10.99.0.2  # wg overlay addresses
SRV_IP=10.9.0.1;   LAN_IP=10.9.0.2; TAP_IP=10.9.0.20
SRV_PORT=1702   # keep in sync with A2TP_UDP_PORT
SRV_LOG=/tmp/a2tp-srv.log; CLI_LOG=/tmp/a2tp-cli.log
# Ubuntu confines wg(8) with a dedicated apparmor profile (/etc/apparmor.d/wg)
# that only allows key files under /etc/wireguard -- anywhere else wg set
# private-key dies with "fopen: Permission denied" even for root
mkdir -p /etc/wireguard
KEYDIR=$(mktemp -d /etc/wireguard/a2tp-test.XXXXXXXX)

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { say "PASS: $*"; PASS=$((PASS+1)); }
bad()  { say "FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { say "SKIP: $*"; SKIP=$((SKIP+1)); }

srv_up() {  # extra args: a2tpctl srv add flags (-b, --filter-ip, ...)
    ip netns exec "$NS_SRV" ./a2tpctl srv add -i "$V_SRV" "$@" >>"$SRV_LOG" 2>&1
}
srv_down() { ip netns exec "$NS_SRV" ./a2tpctl srv del -i "$V_SRV" >>"$SRV_LOG" 2>&1; }
# the counters print on their own indented line: "    mirror=N inject=N ..."
srv_tx_err() { ip netns exec "$NS_SRV" ./a2tpctl srv status \
    | grep -o 'tx_err=[0-9]*' | head -1 | cut -d= -f2; }
srv_alive() { ip netns exec "$NS_SRV" ./a2tpctl srv status \
    | grep -q "^srv $V_SRV:"; }
# the client netdev is a plain rtnl_link device: "alive" = it still exists
cli_alive() { ip -n "$NS_CLI" link show "$TAP" >/dev/null 2>&1; }

cleanup() {
    ip -n "$NS_CLI" link del "$TAP" 2>/dev/null
    ip netns exec "$NS_SRV" ./a2tpctl srv del -i "$V_SRV" >/dev/null 2>&1
    sleep 0.3
    for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do ip netns del "$ns" 2>/dev/null; done
    rm -rf "$KEYDIR"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/wg.sh"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }
[ -d /sys/module/a2tp ] || { say "a2tp module not loaded"; exit 1; }
[ -d /sys/module/wireguard ] || modprobe wireguard 2>/dev/null
command -v wg >/dev/null || { say "wg(8) not found"; exit 1; }

# ---------- topology ----------
for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do ip netns del "$ns" 2>/dev/null; done
ip netns add "$NS_SRV"; ip netns add "$NS_CLI"; ip netns add "$NS_LAN"

# LAN veth (server <-> LAN host), same shape as testbed.sh
ip link add "$V_SRV" type veth peer name "$V_LAN"
ip link set "$V_SRV" netns "$NS_SRV"
ip link set "$V_LAN" netns "$NS_LAN"
ip -n "$NS_SRV" addr add "$SRV_IP/24" dev "$V_SRV"
ip -n "$NS_LAN" addr add "$LAN_IP/24" dev "$V_LAN"

# underlay veth ("the internet")
ip link add "$W_SRV" type veth peer name "$W_CLI"
ip link set "$W_SRV" netns "$NS_SRV"
ip link set "$W_CLI" netns "$NS_CLI"
ip -n "$NS_SRV" addr add "$U_SRV/24" dev "$W_SRV"
ip -n "$NS_CLI" addr add "$U_CLI/24" dev "$W_CLI"

for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do
    ip -n "$ns" link set lo up
    # mirrored frames re-enter through the taken-over NIC with the tap's
    # addresses on them; and keep arp_flux from answering for the tap's IP
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.arp_ignore=1
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.arp_ignore=1
done
# links up (per device -- `ip link set up` without a dev is invalid iproute2)
for dev in "$V_SRV" "$W_SRV"; do ip -n "$NS_SRV" link set "$dev" up; done
for dev in "$W_CLI";           do ip -n "$NS_CLI" link set "$dev" up; done
for dev in "$V_LAN";           do ip -n "$NS_LAN" link set "$dev" up; done
# the "LAN host" must emit plain wire frames (see testbed.sh)
command -v ethtool >/dev/null && \
    ip netns exec "$NS_LAN" ethtool -K "$V_LAN" tso off gso off gro off tx off 2>/dev/null

# ---------- WireGuard ----------
# wg's apparmor profile refuses to read world-accessible private key files
# (openat -> EACCES), so keep the keys locked to root: umask 077 + chmod 600
umask 077
wg genkey >"$KEYDIR/srv.key"; wg genkey >"$KEYDIR/cli.key"
chmod 600 "$KEYDIR"/*.key
SRV_PUB=$(wg pubkey <"$KEYDIR/srv.key")
CLI_PUB=$(wg pubkey <"$KEYDIR/cli.key")

ip netns exec "$NS_SRV" ip link add wg0 type wireguard
ip netns exec "$NS_CLI" ip link add wg0 type wireguard
ip netns exec "$NS_SRV" wg set wg0 private-key "$KEYDIR/srv.key" \
    listen-port "$WG_PORT_SRV" peer "$CLI_PUB" \
    endpoint "$U_CLI:$WG_PORT_CLI" allowed-ips "$WG_CLI/32"
ip netns exec "$NS_CLI" wg set wg0 private-key "$KEYDIR/cli.key" \
    listen-port "$WG_PORT_CLI" peer "$SRV_PUB" \
    endpoint "$U_SRV:$WG_PORT_SRV" allowed-ips "$WG_SRV/32" persistent-keepalive 5
ip -n "$NS_SRV" addr add "$WG_SRV/24" dev wg0
ip -n "$NS_CLI" addr add "$WG_CLI/24" dev wg0
ip -n "$NS_SRV" link set wg0 mtu 1420 up
ip -n "$NS_CLI" link set wg0 mtu 1420 up

# ---------- W1: wg carrier up, a2tp rides it encrypted ----------
if ! ip netns exec "$NS_CLI" ping -c 2 -W 2 "$WG_SRV" >/dev/null 2>&1; then
    bad "W1 wg handshake dead (cli cannot ping $WG_SRV); aborting"
    ip netns exec "$NS_CLI" wg show
    exit 1
fi
srv_up
sleep 0.6
ip netns exec "$NS_CLI" ./a2tpctl cli add "$TAP" remote "$WG_SRV" local-port 0 \
    >>"$CLI_LOG" 2>&1
ip -n "$NS_CLI" link set "$TAP" mtu 1350 up
ip -n "$NS_CLI" addr replace "$TAP_IP/24" dev "$TAP"

if ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    ok "W1a tunnel up through wg: tap -> LAN ping over the wg carrier"
else
    bad "W1a tap -> LAN ping through wg failed"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# the underlay must carry wg noise only -- no a2tp UDP in the clear
timeout 6 ip netns exec "$NS_CLI" tcpdump -ni "$W_CLI" -c 8 \
    "udp port $SRV_PORT" >/tmp/w1.clear 2>&1 &
TD=$!
sleep 0.3
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 1 "$LAN_IP" >/dev/null 2>&1
wait $TD 2>/dev/null
grep -q '0 packets captured' /tmp/w1.clear \
    && ok "W1b underlay carries no cleartext a2tp (port $SRV_PORT) traffic" \
    || bad "W1b cleartext a2tp seen on the underlay"; cat /tmp/w1.clear

PEER=$(ip netns exec "$NS_SRV" ./a2tpctl srv status | grep -o "peer learned $WG_CLI:[0-9]*")
[ -n "$PEER" ] && ok "W1c server learned the client's wg overlay endpoint ($PEER)" \
             || bad "W1c no learned peer on the server"

# ---------- W2: unpinned carrier outage (client wg0 down) ----------
ip -n "$NS_CLI" link set wg0 down     # the whole carrier, and its route, gone
sleep 0.5
ip netns exec "$NS_CLI" ping -I "$TAP" -c 2 -W 1 "$LAN_IP" >/dev/null 2>&1 \
    && DOWN=unexpected || DOWN=ok
cli_alive && TAP_OK=ok || TAP_OK=fail
srv_alive && SRV_OK=ok || SRV_OK=fail
ip -n "$NS_CLI" link set wg0 up       # carrier back
sleep 2                              # wg re-handshake + a2tp keepalive re-learn
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && POST=ok || POST=fail

if [ "$DOWN" = ok ] && [ "$TAP_OK" = ok ] && [ "$SRV_OK" = ok ] && [ "$POST" = ok ]; then
    ok "W2 carrier down (unpinned): traffic stopped, both ends waited; resumed on return"
else
    bad "W2 carrier down: down=$DOWN tap_alive=$TAP_OK srv_alive=$SRV_OK post=$POST"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- W3: pinned server carrier (-b), its address deleted ----------
srv_down; sleep 0.5
srv_up -b "$WG_SRV"
sleep 0.7
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && PRE=ok || PRE=fail

TX_BEFORE=$(srv_tx_err)
ip -n "$NS_SRV" addr del "$WG_SRV/24" dev wg0   # the pinned carrier ip itself
sleep 0.5
# drive mirror attempts while the carrier is gone: the LAN host keeps asking
# for the tap's IP; every frame must fail the lookup and be counted, dropped
ip netns exec "$NS_LAN" ping -c 2 -W 1 "$TAP_IP" >/dev/null 2>&1
ip netns exec "$NS_CLI" ping -I "$TAP" -c 2 -W 1 "$LAN_IP" >/dev/null 2>&1 \
    && DOWN=unexpected || DOWN=ok
TX_AFTER=$(srv_tx_err)
srv_alive && ALIVE=ok || ALIVE=fail
cli_alive && TAP_OK=ok || TAP_OK=fail

ip -n "$NS_SRV" addr add "$WG_SRV/24" dev wg0   # carrier back
sleep 2
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && POST=ok || POST=fail

if [ "$PRE" = ok ] && [ "$DOWN" = ok ] && [ "$ALIVE" = ok ] && [ "$TAP_OK" = ok ] \
   && [ "$POST" = ok ] && [ "$TX_AFTER" -gt "$TX_BEFORE" ]; then
    ok "W3 pinned carrier ($WG_SRV) deleted: mirror attempts counted tx_err ($TX_BEFORE->$TX_AFTER), instance waited, resumed"
else
    bad "W3 pinned carrier outage: pre=$PRE down=$DOWN alive=$ALIVE tap=$TAP_OK post=$POST tx_err=$TX_BEFORE->$TX_AFTER"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- W4: pinned client carrier (local), its address deleted ----------
srv_down; sleep 0.5
srv_up           # back to wildcard
sleep 0.7
ip -n "$NS_CLI" link del "$TAP"; ip -n "$NS_CLI" link del wg0 2>/dev/null
ip -n "$NS_CLI" link add wg0 type wireguard
ip netns exec "$NS_CLI" wg set wg0 private-key "$KEYDIR/cli.key" \
    listen-port "$WG_PORT_CLI" peer "$SRV_PUB" \
    endpoint "$U_SRV:$WG_PORT_SRV" allowed-ips "$WG_SRV/32" persistent-keepalive 5
ip -n "$NS_CLI" addr add "$WG_CLI/24" dev wg0
ip -n "$NS_CLI" link set wg0 mtu 1420 up
sleep 1
ip netns exec "$NS_CLI" ./a2tpctl cli add "$TAP" remote "$WG_SRV" \
    local "$WG_CLI" local-port 0 >>"$CLI_LOG" 2>&1
ip -n "$NS_CLI" link set "$TAP" mtu 1350 up
ip -n "$NS_CLI" addr replace "$TAP_IP/24" dev "$TAP"
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && PRE=ok || PRE=fail

ip -n "$NS_CLI" addr del "$WG_CLI/24" dev wg0   # the pinned source is gone
sleep 0.5
ip netns exec "$NS_CLI" ping -I "$TAP" -c 2 -W 1 "$LAN_IP" >/dev/null 2>&1 \
    && DOWN=unexpected || DOWN=ok
cli_alive && TAP_OK=ok || TAP_OK=fail
srv_alive && SRV_OK=ok || SRV_OK=fail
ip -n "$NS_CLI" addr add "$WG_CLI/24" dev wg0   # carrier back
sleep 2
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && POST=ok || POST=fail

if [ "$PRE" = ok ] && [ "$DOWN" = ok ] && [ "$TAP_OK" = ok ] && [ "$SRV_OK" = ok ] \
   && [ "$POST" = ok ]; then
    ok "W4 client carrier (local $WG_CLI) deleted: source invalid -> silent wait, resumed on return"
else
    bad "W4 client pinned carrier: pre=$PRE down=$DOWN tap=$TAP_OK srv=$SRV_OK post=$POST"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- summary ----------
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
say "logs: $SRV_LOG $CLI_LOG"
say "========================================="
[ "$FAIL" -eq 0 ]
