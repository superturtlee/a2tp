#!/usr/bin/env bash
#
# xfrm.sh - kernel-IPsec (XFRM/ESP transport) stacked on the a2tp tunnel.
# Needs root and a2tp.ko loaded (sudo insmod kernel/a2tp.ko).  Proves the
# kernel data plane rides the kernel IPsec framework "for free": the module's
# outer UDP goes through ip_route_output_flow, so global xfrm policies apply
# to it.
#
# Topology: separate inner/outer links, so the underlay sniff only ever sees
# tunnel outer packets:
#
#   netns l2x-srv                             netns l2x-lan
#   l2x-s0 10.10.0.1/24 ══ underlay ══╗       l2x-l1 10.10.1.2/24
#   l2x-l0 10.10.1.1/24 ══ inner  ════╬═══════════════════════╝
#     a2tpctl srv add -i l2x-l0      ╂ netns l2x-cli
#                                    ╚═ l2x-c0 10.10.0.2/24 (ESP to srv)
#                                       a2tp0 l2x-tap 10.10.1.20/24
#
# ESP transport policies on 10.10.0.1 <-> 10.10.0.2 (the outer addresses):
#   X1: tcpdump on the underlay sees ESP but zero UDP:1702 while traffic
#       flows (the outer is really encrypted)
#   X2: tap <-> LAN ping through ESP + a2tp (ARP + ICMP both ways)
#   X3: policies removed -> plaintext UDP:1702 becomes visible and the
#       tunnel still passes traffic (proves X1 was not a capture artifact)
#
set -u
cd "$(dirname "$0")/.."

NS_SRV=l2x-srv; NS_CLI=l2x-cli; NS_LAN=l2x-lan
U_SRV=l2x-s0;  U_CLI=l2x-c0		# underlay (outer, ESP here)
I_SRV=l2x-l0;  I_LAN=l2x-l1		# inner LAN pair
TAP=l2x-tap
OUT_SRV_IP=10.10.0.1; OUT_CLI_IP=10.10.0.2
LAN_IP=10.10.1.2;     TAP_IP=10.10.1.20
SRV_PORT=1702
# 32-byte psk shared by all four xfrm states (cbc(aes) + hmac(sha256))
KEY="a2tpfixedtestkeya2tpfixedtestkey"
SPI_SRV2CLI=0x1001; SPI_CLI2SRV=0x1002
SRV_LOG=/tmp/a2x-srv.log; CLI_LOG=/tmp/a2x-cli.log

PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { say "PASS: $*"; PASS=$((PASS+1)); }
bad()  { say "FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup() {
    ip netns exec "$NS_SRV" ./a2tpctl srv del -i "$I_SRV" >/dev/null 2>&1
    ip netns exec "$NS_CLI" ip link del "$TAP" 2>/dev/null
    sleep 0.3
    for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do ip netns del "$ns" 2>/dev/null; done
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/xfrm.sh"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }
command -v tcpdump >/dev/null || { say "tcpdump not found"; exit 1; }
[ -d /sys/module/a2tp ] || { say "a2tp module not loaded: sudo insmod kernel/a2tp.ko"; exit 1; }

# ---------- topology ----------
for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do ip netns del "$ns" 2>/dev/null; done
ip netns add "$NS_SRV"; ip netns add "$NS_CLI"; ip netns add "$NS_LAN"
ip link add "$U_SRV" type veth peer name "$U_CLI"
ip link add "$I_SRV" type veth peer name "$I_LAN"
ip link set "$U_SRV" netns "$NS_SRV"; ip link set "$U_CLI" netns "$NS_CLI"
ip link set "$I_SRV" netns "$NS_SRV"; ip link set "$I_LAN" netns "$NS_LAN"
ip -n "$NS_SRV" addr add "$OUT_SRV_IP/24" dev "$U_SRV"
ip -n "$NS_SRV" addr add "10.10.1.1/24" dev "$I_SRV"
ip -n "$NS_CLI" addr add "$OUT_CLI_IP/24" dev "$U_CLI"
ip -n "$NS_LAN" addr add "$LAN_IP/24" dev "$I_LAN"
for ns in "$NS_SRV" "$NS_CLI" "$NS_LAN"; do
    ip netns exec "$ns" ip link set lo up
done
ip -n "$NS_SRV" link set "$U_SRV" up; ip -n "$NS_SRV" link set "$I_SRV" up
ip -n "$NS_CLI" link set "$U_CLI" up
ip -n "$NS_LAN" link set "$I_LAN" up
# the inner "LAN host" must emit plain wire frames (same as testbed.sh)
command -v ethtool >/dev/null && \
    ip netns exec "$NS_LAN" ethtool -K "$I_LAN" tso off gso off gro off tx off 2>/dev/null
say "topology up: underlay $OUT_SRV_IP <-> $OUT_CLI_IP, inner LAN 10.10.1.0/24"

# ---------- kernel IPsec: ESP transport on the outer addresses ----------
# enc+auth SAs are wrapped into an aead by the authenc template (CONFIG_CRYPTO_
# AUTHENC=m on Ubuntu) and ESP itself is esp4.ko; load both explicitly so the
# test does not depend on in-kernel module autoload
modprobe authenc 2>/dev/null || true
modprobe esp4 2>/dev/null || true

xfrm_up() {
    for ns in "$NS_SRV" "$NS_CLI"; do
        ip netns exec "$ns" ip xfrm state flush
        ip netns exec "$ns" ip xfrm policy flush
    done
    # both states on both nodes: one for the outbound SA, one to decrypt.
    # names must be kernel xfrm canonical/compat names (xfrm_algo.c table):
    # "cbc(aes)" (compat "aes"), "hmac(sha256)" (compat "sha256") --
    # "aes-cbc" is a userspace (strongSwan-style) spelling the kernel rejects
    for ns in "$NS_SRV" "$NS_CLI"; do
        ip netns exec "$ns" ip xfrm state add \
            src "$OUT_SRV_IP" dst "$OUT_CLI_IP" spi "$SPI_SRV2CLI" \
            proto esp mode transport enc cbc\(aes\) "$KEY" auth hmac\(sha256\) "$KEY"
        ip netns exec "$ns" ip xfrm state add \
            src "$OUT_CLI_IP" dst "$OUT_SRV_IP" spi "$SPI_CLI2SRV" \
            proto esp mode transport enc cbc\(aes\) "$KEY" auth hmac\(sha256\) "$KEY"
    done
    ip netns exec "$NS_SRV" ip xfrm policy add \
        src "$OUT_SRV_IP/32" dst "$OUT_CLI_IP/32" dir out \
        tmpl src "$OUT_SRV_IP" dst "$OUT_CLI_IP" proto esp mode transport
    ip netns exec "$NS_SRV" ip xfrm policy add \
        src "$OUT_CLI_IP/32" dst "$OUT_SRV_IP/32" dir in \
        tmpl src "$OUT_CLI_IP" dst "$OUT_SRV_IP" proto esp mode transport
    ip netns exec "$NS_CLI" ip xfrm policy add \
        src "$OUT_CLI_IP/32" dst "$OUT_SRV_IP/32" dir out \
        tmpl src "$OUT_CLI_IP" dst "$OUT_SRV_IP" proto esp mode transport
    ip netns exec "$NS_CLI" ip xfrm policy add \
        src "$OUT_SRV_IP/32" dst "$OUT_CLI_IP/32" dir in \
        tmpl src "$OUT_SRV_IP" dst "$OUT_CLI_IP" proto esp mode transport
}
xfrm_down() {
    for ns in "$NS_SRV" "$NS_CLI"; do
        ip netns exec "$ns" ip xfrm policy flush
        ip netns exec "$ns" ip xfrm state flush
    done
}

# ---------- tunnel up ----------
start_tunnel() {
    ip netns exec "$NS_SRV" ./a2tpctl srv add -i "$I_SRV" >>"$SRV_LOG" 2>&1
    sleep 0.6
    ip netns exec "$NS_CLI" ./a2tpctl cli add "$TAP" remote "$OUT_SRV_IP" \
        local-port 0 >>"$CLI_LOG" 2>&1
    ip netns exec "$NS_CLI" ip link set "$TAP" up
    sleep 0.8
    ip -n "$NS_CLI" addr replace "$TAP_IP/24" dev "$TAP"
    # reach the inner LAN through the tap
    ip -n "$NS_CLI" route replace "$LAN_IP/32" dev "$TAP" src "$TAP_IP"
}

xfrm_up
start_tunnel
say "tunnel up under ESP (logs: $SRV_LOG $CLI_LOG)"

# ---------- X2: bidirectional through ESP + a2tp ----------
if ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    ok "X2 tap <-> LAN ping through IPsec + a2tp (ARP + ICMP both ways)"
else
    bad "X2 ping failed with ESP on"; tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- X1: underlay carries ESP, never plaintext UDP:1702 ----------
timeout 8 ip netns exec "$NS_SRV" tcpdump -ni "$U_SRV" -c 8 \
    "esp or udp port $SRV_PORT" >/tmp/x1.dump 2>&1 &
TD=$!
sleep 0.5
ip netns exec "$NS_CLI" ping -I "$TAP" -c 4 -W 1 "$LAN_IP" >/dev/null 2>&1
wait $TD 2>/dev/null
if grep -q "ESP" /tmp/x1.dump && ! grep -q "1702" /tmp/x1.dump; then
    ok "X1 underlay carries ESP only, no plaintext UDP:$SRV_PORT"
else
    bad "X1 saw non-ESP tunnel traffic"; cat /tmp/x1.dump
fi

# ---------- X3: drop ipsec -> plaintext visible again, tunnel still fine ----------
xfrm_down
sleep 0.3
timeout 8 ip netns exec "$NS_SRV" tcpdump -ni "$U_SRV" -c 3 \
    "udp port $SRV_PORT" >/tmp/x3.dump 2>&1 &
TD=$!
sleep 0.5
ip netns exec "$NS_CLI" ping -I "$TAP" -c 3 -W 2 "$LAN_IP" >/dev/null 2>&1
wait $TD 2>/dev/null
if grep -q "1702" /tmp/x3.dump; then
    ok "X3 plaintext UDP:$SRV_PORT visible after xfrm removal (X1 was real)"
else
    bad "X3 no UDP traffic after removing xfrm"; cat /tmp/x3.dump
fi
if ip netns exec "$NS_CLI" ping -I "$TAP" -c 2 -W 2 "$LAN_IP" >/dev/null 2>&1; then
    ok "X3 tunnel still passes traffic without ipsec"
else
    bad "X3 tunnel broken after xfrm removal"
fi

say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL"
say "logs: $SRV_LOG $CLI_LOG"
say "========================================="
[ "$FAIL" -eq 0 ]
