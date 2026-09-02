#!/usr/bin/env bash
#
# qemu.sh - run a2tp tests inside a real-Ubuntu QEMU VM (see tools/qemu-vm.sh).
# Every run boots a fresh throwaway overlay of the baked image; a kernel
# panic only kills that VM.  First-time setup: tools/qemu-vm.sh fetch && bake.
#
# Usage:
#   test/qemu.sh testbed
#   test/qemu.sh xfrm
#   test/qemu.sh sh '<any shell cmd>'  # e.g. sh 'uname -r; lsmod'
#
# Env: passthrough of QDIR/VM_MEM/VM_SMP/SSH_PORT/SERLOG to qemu-vm.sh,
#      TEST_TIMEOUT (default 600) guards the in-VM command.
#
set -u
cd "$(dirname "$0")/.."

TEST_TIMEOUT=${TEST_TIMEOUT:-600}

usage() { sed -n '2,14p' "$0"; exit 2; }
[ $# -ge 1 ] || usage
WHAT=$1; shift || true
EXTRA=$*

case "$WHAT" in
    testbed) INVM="bash /mnt/a2tp/test/testbed.sh" ;;
    xfrm)    INVM="bash /mnt/a2tp/test/xfrm.sh" ;;
    sh)      INVM="$EXTRA" ;;
    *)       usage ;;
esac

# module load: host-built a2tp.ko first (same kernel series), rebuild inside
# the VM as a fallback if the version ever drifts
LOAD='cd /mnt/a2tp && sudo modprobe udp_tunnel 2>/dev/null; sudo rmmod a2tp 2>/dev/null; if ! sudo insmod kernel/a2tp.ko 2>/dev/null; then make kmod >/dev/null 2>&1 && sudo insmod kernel/a2tp.ko || echo "a2tp.ko load FAILED"; else echo "a2tp.ko loaded"; fi'

tools/qemu-vm.sh test "timeout $TEST_TIMEOUT sh -c '$LOAD && sudo sh -c \"cd /mnt/a2tp && $INVM\"'"
