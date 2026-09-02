#!/usr/bin/env bash
#
# testbed.sh - end-to-end test for the a2tp kernel module.  Needs root and
# a2tp.ko loaded (sudo insmod kernel/a2tp.ko).
#
# Topology (no bridge anywhere; the server takes over a veth NIC):
#
#   netns l2t-srv                         netns l2t-lan
#   ┌───────────────────────────┐         ┌──────────────┐
#   │ l2t-s0 10.9.0.1/24 ══════╪═════════╪═ l2t-l0 10.9.0.2/24
#   │   ▲ rx_handler mirror+inject       │   "LAN host" │
#   │   │                                 └──────────────┘
#   │ a2tpctl srv add -i l2t-s0  (UDP :1702)
#   │ a2tp0 (netdev l2t-tap) 10.9.0.20/24  (UDP via lo to 10.9.0.1)
#   └───────────────────────────┘
#
# Every frame l2t-l0 sends must appear on the tap (mirror direction) and
# every frame the tap emits must come out of l2t-l0 (inject direction).
#
set -u
cd "$(dirname "$0")/.."

NS_SRV=l2t-srv; NS_LAN=l2t-lan
V_SRV=l2t-s0;  V_LAN=l2t-l0
TAP=l2t-tap
SRV_IP=10.9.0.1; LAN_IP=10.9.0.2; TAP_IP=10.9.0.20
SRV_PORT=1702   # keep in sync with A2TP_UDP_PORT
FAKE_MAC=02:11:22:33:44:55; FAKE_IP=10.9.0.99
SRV_LOG=/tmp/a2tp-srv.log; CLI_LOG=/tmp/a2tp-cli.log

PASS=0; FAIL=0; SKIP=0

say()  { printf '%s\n' "$*"; }
ok()   { say "PASS: $*"; PASS=$((PASS+1)); }
bad()  { say "FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { say "SKIP: $*"; SKIP=$((SKIP+1)); }

# ---------- instance helpers ----------
srv_up() {  # extra args: a2tpctl srv add flags (-b, --filter-ip, ...)
    ip netns exec "$NS_SRV" ./a2tpctl srv add -i "$V_SRV" "$@" >>"$SRV_LOG" 2>&1
}
srv_down() {
    ip netns exec "$NS_SRV" ./a2tpctl srv del -i "$V_SRV" >>"$SRV_LOG" 2>&1
}
cli_up() {  # optional arg: remote address (default $SRV_IP)
    local remote=${1:-$SRV_IP}
    ip netns exec "$NS_SRV" ./a2tpctl cli add "$TAP" remote "$remote" \
        local-port 0 >>"$CLI_LOG" 2>&1
    ip -n "$NS_SRV" link set "$TAP" up
    sleep 1
    # addressing is the config script's job, not the client's
    ip -n "$NS_SRV" addr replace "$TAP_IP/24" dev "$TAP"
}
cli_down() {
    ip -n "$NS_SRV" link del "$TAP" 2>/dev/null
}
# learned peer "ip:port" from the kernel server instance
peer() { ip netns exec "$NS_SRV" ./a2tpctl srv status \
    | sed -n "s/^srv $V_SRV:.*peer learned \([0-9.]*:[0-9]*\).*/\1/p"; }

cleanup() {
    srv_down 2>/dev/null
    cli_down 2>/dev/null
    sleep 0.3
    ip netns del "$NS_SRV" 2>/dev/null
    ip netns del "$NS_LAN" 2>/dev/null
    ip link del "$TAP" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/testbed.sh"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }
command -v tcpdump >/dev/null || { say "tcpdump not found"; exit 1; }
[ -d /sys/module/a2tp ] || { say "a2tp module not loaded: sudo insmod kernel/a2tp.ko"; exit 1; }

# ---------- setup ----------
ip netns del "$NS_SRV" 2>/dev/null; ip netns del "$NS_LAN" 2>/dev/null

ip netns add "$NS_SRV"
ip netns add "$NS_LAN"
ip link add "$V_SRV" type veth peer name "$V_LAN"
ip link set "$V_SRV" netns "$NS_SRV"
ip link set "$V_LAN" netns "$NS_LAN"
ip -n "$NS_SRV" addr add "$SRV_IP/24" dev "$V_SRV"
ip -n "$NS_LAN" addr add "$LAN_IP/24" dev "$V_LAN"
ip -n "$NS_SRV" link set "$V_SRV" up; ip -n "$NS_SRV" link set lo up
ip -n "$NS_LAN" link set "$V_LAN" up; ip -n "$NS_LAN" link set lo up
# s0 and the tap share one subnet inside NS_SRV: keep the stack from dropping
# mirrored packets over the "other" interface
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.rp_filter=0
# ...and keep it from ARP-flux answering for the tap's IP out of s0: with the
# default arp_ignore=0 the kernel replies "tap-ip is-at <s0 mac>", which needs
# no tunnel -- while the client is down it is the ONLY reply and poisons the
# LAN peer's neighbor entry, so post-restart replies arrive as
# PACKET_OTHERHOST on the tap and are dropped (the T4 roaming check would
# hang forever)
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.arp_ignore=1
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.arp_ignore=1
# the "LAN host" must emit plain wire frames: tso/gso off (no 64K super-frames)
# and tx off (no CHECKSUM_PARTIAL placeholder checksums -- a physical NIC fills
# real checksums in hardware, veth does not).  The server does the same on its
# own NIC at startup.
command -v ethtool >/dev/null && \
    ip netns exec "$NS_LAN" ethtool -K "$V_LAN" tso off gso off gro off tx off 2>/dev/null
say "topology up: $NS_SRV ($V_SRV $SRV_IP) <-> $NS_LAN ($V_LAN $LAN_IP)"

srv_up
sleep 0.6
cli_up

say "--- server log ---";  tail -n 20 "$SRV_LOG"
say "--- client log ---";  tail -n 20 "$CLI_LOG"

# ---------- T1: bidirectional L2 pipe (ARP + ICMP both ways) ----------
if ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/tmp/t1.ping 2>&1; then
    ok "T1 tap -> LAN ping (3/3 through tunnel: ARP req/repl + echo req/repl)"
else
    bad "T1 tap -> LAN ping failed"; cat /tmp/t1.ping
fi

# ---------- T2: promiscuous mirror of frames addressed to a foreign MAC ----------
ip -n "$NS_LAN" neigh replace "$FAKE_IP" lladdr "$FAKE_MAC" dev "$V_LAN" nud permanent
# -e prints the ethernet header so the MAC itself is asserted, not just the IPs
timeout 8 ip netns exec "$NS_SRV" tcpdump -eni "$TAP" -c 2 -Q in \
    "ether host $FAKE_MAC" >/tmp/t2.dump 2>&1 &
TD=$!
sleep 0.5
ip netns exec "$NS_LAN" ping -c 3 -W 1 "$FAKE_IP" >/dev/null 2>&1
wait $TD 2>/dev/null
if grep -q "$FAKE_MAC" /tmp/t2.dump && grep -q "$FAKE_IP" /tmp/t2.dump; then
    ok "T2 promiscuous mirror: unicast frames to $FAKE_MAC seen on tap"
else
    bad "T2 no mirrored frames to $FAKE_MAC on tap"; cat /tmp/t2.dump
fi
ip -n "$NS_LAN" neigh del "$FAKE_IP" dev "$V_LAN" 2>/dev/null

# ---------- T3: no duplication / no storm on the wire ----------
timeout 12 ip netns exec "$NS_LAN" tcpdump -ni "$V_LAN" -l icmp >/tmp/t3.dump 2>&1 &
TD=$!
sleep 0.5
ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1
wait $TD 2>/dev/null
REQ=$(grep -c 'echo request' /tmp/t3.dump || true)
REP=$(grep -c 'echo reply'   /tmp/t3.dump || true)
if [ "$REQ" -eq 3 ] && [ "$REP" -eq 3 ]; then
    ok "T3 exactly 3 echo requests / 3 replies on the wire (no loop, no storm)"
else
    bad "T3 expected 3/3 frames, saw requests=$REQ replies=$REP"; cat /tmp/t3.dump
fi

# ---------- T4: NAT roaming (client comes back from a different port) ----------
PEER_BEFORE=$(peer)
cli_down
sleep 0.5
cli_up
ROAM=ok
ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 || ROAM=fail
PEER_AFTER=$(peer)
[ -n "$PEER_AFTER" ] && [ "$PEER_BEFORE" != "$PEER_AFTER" ] || ROAM=fail
if [ "$ROAM" = ok ]; then
    ok "T4 peer re-learned after endpoint change (NAT roaming), tunnel still up"
else
    bad "T4 roaming failed (before='$PEER_BEFORE' after='$PEER_AFTER')"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- T5: loopback-only listener serves local clients ----------
srv_down; cli_down
sleep 0.5
srv_up -b 127.0.0.1
sleep 0.7
cli_up 127.0.0.1
if ip netns exec "$NS_SRV" ss -H -uln "sport = :$SRV_PORT" | grep -q "127.0.0.1:$SRV_PORT" \
   && ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    ok "T5 server bound to 127.0.0.1 only: socket listens on loopback, local client works"
else
    bad "T5 loopback-bound server broken"
    ip netns exec "$NS_SRV" ss -uln "sport = :$SRV_PORT"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- T6: --filter-ip (multi-IP NIC: only the client's IPs are tunneled) -
srv_down; cli_down
sleep 0.5
FIP=10.9.0.3   # "second IP of the NIC", owned only by the client's tap
srv_up --filter-ip "$FIP"
sleep 0.7
cli_up
ip -n "$NS_SRV" addr replace "$FIP/24" dev "$TAP"
ip -n "$NS_SRV" route replace "$LAN_IP/32" dev "$TAP" src "$FIP"

# a) filtered IP is tunneled: LAN reaches it through the client (ARP passes too)
ip netns exec "$NS_LAN" ping -I "$V_LAN" -c 3 -W 2 "$FIP" >/dev/null 2>&1 \
    && A=ok || A=fail
# b) the NIC's other IP: local stack still answers it, and none of that
#    traffic may appear on the tap
ip netns exec "$NS_SRV" timeout 6 tcpdump -ni "$TAP" \
    -c 4 "icmp and dst host $SRV_IP" >/tmp/t8.cap 2>&1 &
TD=$!
sleep 0.3
ip netns exec "$NS_LAN" ping -I "$V_LAN" -c 3 -W 2 "$SRV_IP" >/dev/null 2>&1 \
    && B=ok || B=fail
wait $TD 2>/dev/null
grep -q '0 packets captured' /tmp/t8.cap && C=ok || C=fail
# c) client -> LAN still works with the filter on (replies match the filter)
ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1 \
    && D=ok || D=fail

if [ "$A" = ok ] && [ "$B" = ok ] && [ "$C" = ok ] && [ "$D" = ok ]; then
    ok "T6 --filter-ip: $FIP tunneled, $SRV_IP stayed with the local stack (nothing on tap)"
else
    bad "T6 --filter-ip: lan->filtered=$A lan->other=$B other-on-tap=$C tap->lan=$D"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- summary ----------
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
say "logs: $SRV_LOG $CLI_LOG"
say "========================================="
[ "$FAIL" -eq 0 ]
