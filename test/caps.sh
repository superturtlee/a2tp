#!/usr/bin/env bash
#
# caps.sh - capability gate matrix: every admin entry point must require
# CAP_NET_ADMIN over the user namespace that owns the *target* netns.
# The kernel side is netlink core enforcement:
#
#   genl (srv add/del)     GENL_UNS_ADMIN_PERM ->
#                          netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)
#   rtnl (client netdev)   rtnetlink.c "kind != RTNL_KIND_GET &&
#                          !netlink_net_capable(skb, CAP_NET_ADMIN)"
#
# Matrix (all against the same module build):
#
#   C1  plain user, no caps, initial netns          -> DENY  (status read: OK)
#   C2  real root (full caps, initial netns)        -> ALLOW
#   C3  uid 0 with CAP_NET_ADMIN dropped            -> DENY
#   C4  userns fake root, initial netns             -> DENY (caps live in the
#                                                       new userns, the init
#                                                       netns belongs to init)
#   C5  userns fake root inside its OWN netns       -> ALLOW (net->user_ns is
#                                                       the userns it owns)
#
# Needs root to run the harness (sudo), plus the `ubuntu` user; the unshare
# cases run under sudo so distro unprivileged-userns policy is not under test.
#
set -u
cd "$(dirname "$0")/.."

DUMMY=d0
SRV_LOG=/tmp/a2tp-caps-srv.log

PASS=0; FAIL=0; SKIP=0
say()  { printf '%s\n' "$*"; }
ok()   { say "PASS: $*"; PASS=$((PASS+1)); }
bad()  { say "FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { say "SKIP: $*"; SKIP=$((SKIP+1)); }

srv_gone() { ! ./a2tpctl srv status 2>/dev/null | grep -q "^srv $DUMMY:"; }
cli_gone() { ! ip link show a2tp0 >/dev/null 2>&1; }

cleanup() {
    ./a2tpctl srv del -i "$DUMMY" >/dev/null 2>&1
    ip link del a2tp0 2>/dev/null
    ip link del "$DUMMY" 2>/dev/null
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { say "must run as root: sudo bash test/caps.sh"; exit 1; }
make >/dev/null || { say "build failed"; exit 1; }
[ -d /sys/module/a2tp ] || { say "a2tp module not loaded"; exit 1; }
id ubuntu >/dev/null 2>&1 || { say "no 'ubuntu' user for C1"; exit 1; }
command -v setpriv >/dev/null || say "note: setpriv missing, C3 will skip"
command -v unshare  >/dev/null || say "note: unshare missing, C4/C5 will skip"

ip link add "$DUMMY" type dummy
ip link set "$DUMMY" up

# ---------- C1: plain user ----------
# srv add must be denied and leave nothing behind...
if sudo -u ubuntu ./a2tpctl srv add -i "$DUMMY" >>"$SRV_LOG" 2>&1; then
    bad "C1 plain user srv add was ACCEPTED"
    ./a2tpctl srv del -i "$DUMMY" >/dev/null 2>&1
else
    srv_gone && ok "C1 plain user: srv add denied (EPERM), no instance left" \
                  || bad "C1 plain user: srv add failed but an instance exists"
fi
# ...the client netdev via rtnl (standard iproute2 path) equally so
if sudo -u ubuntu ./a2tpctl cli add a2tp0 remote 10.0.0.1 >/dev/null 2>&1; then
    bad "C1 plain user client netdev add was ACCEPTED"
    ip link del a2tp0 2>/dev/null
else
    cli_gone && ok "C1 plain user: client netdev add denied (EPERM)" \
                  || bad "C1 plain user: rtnl denied but a2tp0 exists"
fi
# status stays world-readable on purpose (like `ip link`)
if sudo -u ubuntu ./a2tpctl srv status >/dev/null 2>&1; then
    ok "C1 plain user: srv status readable (by design)"
else
    bad "C1 plain user: srv status unreadable (regression: SRV_GET must stay open)"
fi

# ---------- C2: real root ----------
if ./a2tpctl srv add -i "$DUMMY" >>"$SRV_LOG" 2>&1 \
   && ./a2tpctl srv status | grep -q "^srv $DUMMY:" \
   && ./a2tpctl cli add a2tp0 remote 10.0.0.1 >/dev/null 2>&1 \
   && ip link show a2tp0 >/dev/null; then
    ok "C2 root: srv add + client netdev both accepted"
else
    bad "C2 root: rejected despite full capabilities"
    tail -n 5 "$SRV_LOG"
fi
./a2tpctl srv del -i "$DUMMY" >/dev/null 2>&1
ip link del a2tp0 2>/dev/null

# ---------- C3: uid 0 minus CAP_NET_ADMIN ----------
if command -v setpriv >/dev/null; then
    if setpriv --bounding-set=-net_admin -- ./a2tpctl srv add -i "$DUMMY" \
        >>"$SRV_LOG" 2>&1; then
        bad "C3 capless root srv add was ACCEPTED"
        ./a2tpctl srv del -i "$DUMMY" >/dev/null 2>&1
    elif ! srv_gone; then
        bad "C3 capless root: denied but an instance exists"
    elif setpriv --bounding-set=-net_admin -- \
        ./a2tpctl cli add a2tp0 remote 10.0.0.1 >/dev/null 2>&1; then
        bad "C3 capless root client netdev add was ACCEPTED"
        ip link del a2tp0 2>/dev/null
    else
        ok "C3 root without CAP_NET_ADMIN: both admin ops denied (EPERM)"
    fi
else
    skip "C3 (setpriv not installed)"
fi

# ---------- C4: userns fake root, initial netns ----------
# sudo starts the userns so distro unprivileged-userns policy is out of scope;
# uid 0 with full caps *inside the new userns*, but the netns the netlink
# socket lives in still belongs to init_user_ns
if command -v unshare >/dev/null; then
    if unshare -Ur ./a2tpctl srv add -i "$DUMMY" >>"$SRV_LOG" 2>&1; then
        bad "C4 userns-root srv add on the init netns was ACCEPTED"
        ./a2tpctl srv del -i "$DUMMY" >/dev/null 2>&1
    elif ! srv_gone; then
        bad "C4 userns-root: denied but an instance exists"
    elif unshare -Ur ./a2tpctl cli add a2tp0 remote 10.0.0.1 >/dev/null 2>&1; then
        bad "C4 userns-root client netdev add was ACCEPTED"
        ip link del a2tp0 2>/dev/null
    else
        ok "C4 userns fake root, init netns: both admin ops denied (EPERM)"
    fi
else
    skip "C4/C5 (unshare not installed)"
fi

# ---------- C5: userns fake root inside its own netns ----------
# -Urn: new userns + new netns owned by it -> CAP_NET_ADMIN holds over
# net->user_ns; both admin ops must succeed and clean up with the netns
if command -v unshare >/dev/null; then
    OUT=$(unshare -Urn bash -c '
        set -e
        cd /mnt/a2tp
        ip link add v0 type veth peer name v1
        ip link set v0 up
        ./a2tpctl srv add -i v0
        ./a2tpctl srv status | grep -q "^srv v0:"
        ./a2tpctl cli add a2tp0 remote 10.0.0.1
        ip link show a2tp0 >/dev/null
        ./a2tpctl srv del -i v0
        ip link del a2tp0
        echo NS-CLEAN-EXIT
    ' 2>&1)
    if grep -q NS-CLEAN-EXIT <<<"$OUT"; then
        ok "C5 userns fake root, own netns: srv add + client netdev accepted, cleaned up"
    else
        bad "C5 own-netns userns root rejected: $(tail -n 3 <<<"$OUT" | tr "\n" " ")"
    fi
    # netns teardown with instances present must not leave warnings behind
    if dmesg | tail -30 | grep -qE "WARNING|BUG|Oops"; then
        bad "C5 left a kernel warning after netns teardown"
    fi
else
    skip "C5 (unshare not installed)"
fi

# ---------- summary ----------
say ""
say "========================================="
say "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
say "========================================="
[ "$FAIL" -eq 0 ]
