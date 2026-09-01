#!/usr/bin/env bash
#
# auth.sh - end-to-end test of the tcp challenge-response auth
# (--pubkey / --privatekey).  Needs root; same topology as testbed.sh:
#
#   netns l2t-srv                         netns l2t-lan
#   ┌───────────────────────────┐         ┌──────────────┐
#   │ l2t-s0 10.9.0.1/24 ══════╪═════════╪═ l2t-l0 10.9.0.2/24
#   │   ▲ AF_PACKET promisc+inject         │   "LAN host" │
#   │   │                                 └──────────────┘
#   │ a2tp-srv -i l2t-s0 --tcp --bind 127.0.0.1 --pubkey authorized_keys
#   │ a2tp-cli  -s 127.0.0.1 --tcp --tap l2t-tap --privatekey good_key
#   └───────────────────────────┘
#
#   A1  correct key          -> authenticated, tunnel carries traffic
#   A2  wrong key            -> rejected every retry, tunnel never comes up
#   A3  client without key   -> rejected
#   A4  server without --pubkey + keyed client -> proceeds unauthenticated
#   A5  replayed response    -> valid signature over stale challenge bytes
#                               is still rejected (freshness window)
#
set -u
cd "$(dirname "$0")/.."

NS_SRV=l2t-srv; NS_LAN=l2t-lan
V_SRV=l2t-s0;  V_LAN=l2t-l0
TAP=l2t-tap
SRV_IP=10.9.0.1; LAN_IP=10.9.0.2; TAP_IP=10.9.0.20
SRV_PORT=1702   # keep in sync with A2TP_UDP_PORT
KD=/tmp/a2tp-auth-e2e
SRV_LOG=$KD/srv.log; CLI_LOG=$KD/cli.log

PASS=0; FAIL=0; SKIP=0
SRV_PID=""; CLI_PID=""

say()  { printf '%s\n' "$*"; }
ok()   { say "PASS: $*"; PASS=$((PASS+1)); }
bad()  { say "FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { say "SKIP: $*"; SKIP=$((SKIP+1)); }

cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    sleep 0.3
    ip netns del "$NS_SRV" 2>/dev/null
    ip netns del "$NS_LAN" 2>/dev/null
}
trap cleanup EXIT

start_srv() {   # start_srv [extra args...]
    : >"$SRV_LOG"
    ip netns exec "$NS_SRV" "$PWD/a2tp-srv" -i "$V_SRV" --tcp --bind 127.0.0.1 \
        "$@" >"$SRV_LOG" 2>&1 &
    SRV_PID=$!
    sleep 0.7
}
stop_srv() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null && wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
    sleep 0.7
}
start_cli() {   # start_cli <log-suffix> [extra args...]
    local log=$KD/cli-$1.log; shift
    CLI_LOG=$log
    : >"$log"
    ip netns exec "$NS_SRV" "$PWD/a2tp-cli" -s 127.0.0.1 --tcp --tap "$TAP" \
        "$@" >"$log" 2>&1 &
    CLI_PID=$!
    sleep 1.5   # includes the client's 2 s challenge-wait on A4, minus slop
    ip -n "$NS_SRV" addr replace "$TAP_IP/24" dev "$TAP" 2>/dev/null
}
stop_cli() {
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null && wait "$CLI_PID" 2>/dev/null
    CLI_PID=""
    sleep 0.5
}
tunnel_up() {   # traffic through the tunnel?
    ip netns exec "$NS_SRV" ping -I "$TAP" -c 2 -W 2 "$LAN_IP" >/dev/null 2>&1
}
estab() {       # an established tunnel connection on the server port?
    ip netns exec "$NS_SRV" ss -Htn "sport = :$SRV_PORT" | grep -q ESTAB
}

# ---------- preflight ----------
[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/auth.sh"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }
command -v python3 >/dev/null || { say "python3 not found"; exit 1; }

# ---------- keys ----------
rm -rf "$KD" && mkdir -p "$KD"
# the good key comes from openssl so the A5 forger can also sign with it;
# a copy is converted to openssh format for a2tp-cli --privatekey
openssl genpkey -algorithm ed25519 -out "$KD/good.pem" 2>/dev/null
cp "$KD/good.pem" "$KD/good_key"
ssh-keygen -p -N '' -f "$KD/good_key" -P '' >/dev/null 2>&1
ssh-keygen -y -f "$KD/good_key" > "$KD/good.pub" 2>/dev/null
ssh-keygen -q -t ed25519 -N '' -C unused -f "$KD/third" 2>/dev/null
ssh-keygen -q -t ed25519 -N '' -C intruder -f "$KD/bad_key" 2>/dev/null
cat "$KD/good.pub" "$KD/third.pub" > "$KD/authorized_keys"
head -1 "$KD/good_key" | grep -q 'BEGIN OPENSSH PRIVATE KEY' \
    || { say "key conversion failed"; exit 1; }
say "keys ready in $KD"

# ---------- topology (same shape as testbed.sh) ----------
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
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.rp_filter=0
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.all.arp_ignore=1
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.conf.default.arp_ignore=1
command -v ethtool >/dev/null && \
    ip netns exec "$NS_LAN" ethtool -K "$V_LAN" tso off gso off gro off tx off 2>/dev/null
say "topology up"

# ---------- A1: correct key -> authenticated + working tunnel ----------
start_srv --pubkey "$KD/authorized_keys"
grep -q 'auth: 2 key(s)' "$SRV_LOG" \
    || bad "A1 server did not load 2 keys (authorized_keys multi-key parse)"
start_cli a1 --privatekey "$KD/good_key"
if grep -q 'authenticated (key 1 of 2)' "$SRV_LOG" && estab && tunnel_up; then
    ok "A1 good key: challenged, authenticated (key 1 of 2), tunnel carries traffic"
else
    bad "A1 good key rejected or tunnel dead"
    tail -n 5 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- A2: wrong key -> rejected, never establishes ----------
stop_cli
start_cli a2 --privatekey "$KD/bad_key"
sleep 5   # a few retry rounds
# the server's rejection is asserted directly; the client only sees the
# connection drop after its answer (the protocol has no auth-ok message)
if grep -q 'rejected (auth failed)' "$SRV_LOG" \
   && grep -q 'tcp connection lost, reconnecting' "$CLI_LOG" \
   && ! estab && ! tunnel_up && kill -0 "$CLI_PID" 2>/dev/null; then
    ok "A2 wrong key: rejected on every retry, client keeps retrying, no tunnel"
else
    bad "A2 wrong key got through or client died"
    tail -n 6 "$SRV_LOG" "$CLI_LOG"
fi

# ---------- A3: client without any key -> rejected ----------
stop_cli
start_cli a3
sleep 5
if grep -q 'rejected (auth failed)' "$SRV_LOG" && ! estab && ! tunnel_up; then
    ok "A3 keyless client: rejected by the --pubkey server"
else
    bad "A3 keyless client was not rejected"
    tail -n 6 "$SRV_LOG" "$CLI_LOG"
fi
stop_cli

# ---------- A4: keyless server + keyed client -> unauthenticated but up --
stop_srv
start_srv
start_cli a4 --privatekey "$KD/good_key"
sleep 3   # on top of start_cli's wait: the 2 s challenge timeout has passed
A4GREP=ok;  grep -q 'sent no challenge' "$CLI_LOG" || A4GREP=fail
A4ESTAB=ok; estab || A4ESTAB=fail
A4PING=ok;  tunnel_up || A4PING=fail
if [ "$A4GREP" = ok ] && [ "$A4ESTAB" = ok ] && [ "$A4PING" = ok ]; then
    ok "A4 keyless server: keyed client waits, then proceeds unauthenticated, tunnel up"
else
    bad "A4 grep=$A4GREP estab=$A4ESTAB ping=$A4PING"
    ip netns exec "$NS_SRV" ss -Htn "sport = :$SRV_PORT"
    ip netns exec "$NS_SRV" ping -I "$TAP" -c 3 -W 2 "$LAN_IP"
    tail -n 6 "$SRV_LOG" "$CLI_LOG"
fi
stop_cli

# ---------- A5: replayed response (valid sig over stale challenge) ------
stop_srv
stop_cli
start_srv --pubkey "$KD/authorized_keys"
# forge: sign challenge bytes with a timestamp 120 s in the past -- a valid
# signature by the AUTHORIZED key over old nonce material, exactly what a
# recorder would hold
python3 - "$KD/stale.bin" <<'EOF'
import struct, sys, time
open(sys.argv[1], 'wb').write(
    struct.pack('>QI', int(time.time() * 1000) - 120000, 0xdeadbeef))
EOF
openssl pkeyutl -sign -rawin -inkey "$KD/good.pem" \
    -in "$KD/stale.bin" -out "$KD/stale.sig" >/dev/null 2>&1
REPLAY=$(ip netns exec "$NS_SRV" python3 - "$KD/stale.sig" <<'EOF'
import socket, struct, sys
sig = open(sys.argv[1], 'rb').read()
s = socket.create_connection(('127.0.0.1', 1702), timeout=5)
def readn(n):
    b = b''
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b
n = struct.unpack('>H', readn(2))[0]          # the framed challenge
assert n == 13 and readn(n)[0] == 3, 'unexpected challenge'
resp = b'\x04' + sig                           # the recorded response
s.sendall(struct.pack('>H', len(resp)) + resp)
s.settimeout(5)
try:
    d = s.recv(1)
    print('EOF' if not d else 'PEER-SENT-DATA')
except socket.timeout:
    print('KEPT-OPEN')
EOF
)
if [ "$REPLAY" = EOF ] && grep -q 'rejected (auth failed)' "$SRV_LOG" \
   && ! estab; then
    ok "A5 replay: correctly-signed stale answer rejected, connection closed"
else
    bad "A5 replay outcome: $REPLAY"
    tail -n 6 "$SRV_LOG"
fi

# ---------- summary ----------
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
say "logs: $KD"
say "========================================="
[ "$FAIL" -eq 0 ]
