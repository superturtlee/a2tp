#!/usr/bin/env bash
#
# bench.sh - throughput / latency benchmark for the l2tp tunnel.  Needs root.
#
# Same topology as testbed.sh (no bridge):
#   netns l2t-srv: l2t-s0 10.9.0.1 + a2tp-srv + a2tp-cli(tap 10.9.0.20)
#   netns l2t-lan: l2t-l0 10.9.0.2   (iperf3 server / ping peer)
#
#   tap -> LAN  : client send path  (tap fd -> UDP -> AF_PACKET inject)
#   LAN -> tap  : mirror path       (AF_PACKET capture -> UDP -> tap fd)
#
set -u
cd "$(dirname "$0")/.."

NS_SRV=l2t-srv; NS_LAN=l2t-lan
V_SRV=l2t-s0;  V_LAN=l2t-l0
TAP=l2t-tap
SRV_IP=10.9.0.1; LAN_IP=10.9.0.2; TAP_IP=10.9.0.20
SRV_LOG=/tmp/a2tp-srv.log; CLI_LOG=/tmp/a2tp-cli.log
T=${T:-5}    # seconds per iperf3 test
TRANSPORT=${TRANSPORT:-udp}   # udp | tcp (tunnel transport under test)

SRV_PID=""; CLI_PID=""; Iperf3_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "$Iperf3_PID" ] && kill "$Iperf3_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS_SRV" 2>/dev/null
    ip netns del "$NS_LAN" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "must run as root: sudo bash test/bench.sh"; exit 1; }
make >/dev/null || { echo "build failed"; exit 1; }

HAVE_IPERF=0
if command -v iperf3 >/dev/null; then HAVE_IPERF=1
else echo "note: iperf3 not found (apt install iperf3); falling back to ping-based tests"; fi

section() { echo; echo "=========== $* ==========="; }

# summary lines of an iperf3 run (sender/receiver rows, loss/jitter)
summary() { grep -E '\] +[0-9.]+-[0-9.]+ +sec.*((sender|receiver)|Jitter)' "$1"; }
# summary, or the raw output when there is none (errors)
report() {
    local out
    out=$(summary "$1")
    if [ -n "$out" ]; then echo "$out"
    else echo "(no summary, raw output:)"; cat "$1"; fi
}

# ---------- topology ----------
ip netns del "$NS_SRV" 2>/dev/null; ip netns del "$NS_LAN" 2>/dev/null
ip netns add "$NS_SRV"; ip netns add "$NS_LAN"
ip link add "$V_SRV" type veth peer name "$V_LAN"
ip link set "$V_SRV" netns "$NS_SRV"
ip link set "$V_LAN" netns "$NS_LAN"
ip -n "$NS_SRV" addr add "$SRV_IP/24" dev "$V_SRV"
ip -n "$NS_LAN" addr add "$LAN_IP/24" dev "$V_LAN"
ip -n "$NS_SRV" link set "$V_SRV" up; ip -n "$NS_SRV" link set lo up
ip -n "$NS_LAN" link set "$V_LAN" up; ip -n "$NS_LAN" link set lo up
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.rp_filter=0
# s0 and the tap share one subnet in NS_SRV: no arp-flux answers for the tap's
# IP out of s0 (see README -- they poison the LAN peer during a tcp outage)
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.arp_ignore=1
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.arp_ignore=1
# the "LAN host" must emit plain wire frames: tso/gso off (no 64K super-frames
# through the veth) and tx off (no CHECKSUM_PARTIAL placeholder checksums --
# a physical NIC fills real checksums in hardware, veth does not, and the
# receiver would silently drop every such frame).  The server disables
# offloads on its own NIC at startup.
if command -v ethtool >/dev/null; then
    ip netns exec "$NS_LAN" ethtool -K "$V_LAN" tso off gso off gro off tx off 2>/dev/null
fi

start_tunnel() {   # $1 = tap mtu (optional)
    local mtu=${1:-}
    local mtu_args=()
    [ -n "$mtu" ] && mtu_args=(--mtu "$mtu")
    local tun_args=()
    [ "$TRANSPORT" = tcp ] && tun_args=(--tcp)
    [ -n "$CLI_PID" ] && { kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null; CLI_PID=""; }
    sleep 0.3
    [ -z "$SRV_PID" ] && {
        ip netns exec "$NS_SRV" "$PWD/a2tp-srv" -i "$V_SRV" "${tun_args[@]}" \
            >"$SRV_LOG" 2>&1 &
        SRV_PID=$!
        sleep 0.5
    }
    ip netns exec "$NS_SRV" "$PWD/a2tp-cli" -s "$SRV_IP" -p 0 --tap "$TAP" \
        "${mtu_args[@]}" "${tun_args[@]}" >>"$CLI_LOG" 2>&1 &
    CLI_PID=$!
    sleep 0.7
    # addressing/routing is this script's job, not the client's
    ip -n "$NS_SRV" addr replace "$TAP_IP/24" dev "$TAP"
    # force LAN traffic through the tap, not the direct s0 route
    ip -n "$NS_SRV" route replace "$LAN_IP/32" dev "$TAP" src "$TAP_IP"
}

# one persistent iperf3 server for all tests (avoids -s -1 spawn/bind races)
if [ "$HAVE_IPERF" -eq 1 ]; then
    ip netns exec "$NS_LAN" iperf3 -s >/dev/null 2>&1 & Iperf3_PID=$!
    sleep 0.5
fi

if [ "$HAVE_IPERF" -eq 1 ]; then
    section "baseline: direct veth TCP, no tunnel"
    ip netns exec "$NS_SRV" iperf3 -B "$SRV_IP" -c "$LAN_IP" -t "$T" >/tmp/b0.txt 2>&1
    report /tmp/b0.txt
fi

# ---------- tunnel up ----------
start_tunnel 1400
echo "tunnel up ($TRANSPORT transport, tap mtu 1400); logs: $SRV_LOG $CLI_LOG"

# ---------- latency ----------
section "latency: ping through tunnel (tap <-> LAN)"
ip netns exec "$NS_SRV" ping -I "$TAP" -c 20 -i 0.05 -q "$LAN_IP" 2>&1 | tail -2

if [ "$HAVE_IPERF" -eq 1 ]; then
    section "TCP tap -> LAN (client send path), tap mtu 1400 (no outer fragmentation)"
    ip netns exec "$NS_SRV" iperf3 -B "$TAP_IP" -c "$LAN_IP" -t "$T" >/tmp/b1.txt 2>&1
    report /tmp/b1.txt

    section "TCP LAN -> tap (mirror path), -R"
    ip netns exec "$NS_SRV" iperf3 -B "$TAP_IP" -c "$LAN_IP" -t "$T" -R >/tmp/b2.txt 2>&1
    report /tmp/b2.txt

    section "UDP tap -> LAN, -l 1370 (no fragmentation), 2 Gbit/s offered"
    ip netns exec "$NS_SRV" iperf3 -u -b 2G -l 1370 -B "$TAP_IP" -c "$LAN_IP" -t "$T" >/tmp/b3.txt 2>&1
    report /tmp/b3.txt

    section "UDP small packets tap -> LAN, -l 64, unthrottled (pps)"
    ip netns exec "$NS_SRV" iperf3 -u -b 0 -l 64 -B "$TAP_IP" -c "$LAN_IP" -t 3 >/tmp/b4.txt 2>&1
    report /tmp/b4.txt
    PPS=$(summary /tmp/b4.txt | grep sender | \
        awk '{u=0; for(i=1;i<=NF;i++){if($i=="Mbits/sec")u=$(i-1); if($i=="Gbits/sec")u=$(i-1)*1000} if(u){printf "%d", u*1000000/8/149}}')
    if [ -n "${PPS:-}" ]; then
        echo "        ~= $PPS pps (64B payload, ~149B on wire)"
    fi

    section "TCP tap -> LAN, tap mtu 1500 (outer IP fragments every packet)"
    if [ "$TRANSPORT" = udp ]; then
        start_tunnel 1500
        ip netns exec "$NS_SRV" iperf3 -B "$TAP_IP" -c "$LAN_IP" -t "$T" >/tmp/b5.txt 2>&1
        report /tmp/b5.txt
        echo "        (compare with the mtu-1400 run above: fragmentation cost)"
    else
        echo "        (skipped: over --tcp the outer never IP-fragments -- the stream
        segments by MSS instead; compare the mtu-1400 run against the udp numbers)"
    fi
else
    section "fallback pps test: ping -f -s 1400 through tunnel, 5 s"
    timeout -s INT 5 ip netns exec "$NS_SRV" ping -I "$TAP" -f -s 1400 -c 100000 "$LAN_IP" 2>&1 | tail -2
fi

section "tunnel process log"
grep -aE 'peer:|connected|udp local' "$SRV_LOG" | tail -n 8

echo
echo "done. logs: $SRV_LOG $CLI_LOG"
