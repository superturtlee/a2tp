#!/usr/bin/env bash
#
# qemu-vm.sh - real-Ubuntu QEMU sandbox for a2tp kernel testing (no host risk:
# every test run boots a fresh throwaway overlay; a kernel panic only kills it).
#
#   tools/qemu-vm.sh fetch        download the Ubuntu cloud image (once)
#   tools/qemu-vm.sh bake         one-time setup boot (apt pkgs, 9p mount,
#                                 ssh key) -> baked.qcow2
#   tools/qemu-vm.sh run          boot baked image, interactive console
#   tools/qemu-vm.sh test "<cmd>" fresh overlay + ssh + run cmd + shutdown
#                                 e.g.: tools/qemu-vm.sh test "bash /mnt/a2tp/test/testbed.sh"
#
# The repo is shared read-write into the VM via 9p at /mnt/a2tp, so tests run
# against the working tree without repacking anything.  The VM's own kernel
# is used (same Ubuntu series as the host); if its version ever drifts from
# the host build, `make kmod` inside the VM rebuilds against VM headers.
#
# Env: QDIR=~/.cache/a2tp-qemu  VM_MEM=4096  VM_SMP=8  SSH_PORT=10022
#      BAKE_TIMEOUT=900  TEST_TIMEOUT=600
#
set -u
cd "$(dirname "$0")/.."
REPO=$PWD

QDIR=${QDIR:-$HOME/.cache/a2tp-qemu}
VM_MEM=${VM_MEM:-4096}
VM_SMP=${VM_SMP:-8}
SSH_PORT=${SSH_PORT:-10022}
IMG_URL=https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img
BASE=$QDIR/ubuntu-26.04-server-cloudimg-amd64.qcow2
BAKED=$QDIR/baked.qcow2
SEED=$QDIR/seed.iso
SSHKEY=$QDIR/id_ed25519
SERLOG=${SERLOG:-/tmp/a2tp-vm-console.log}

say() { printf '%s\n' "$*"; }

ssh_vm() {  # every call is bounded; a hung VM command can't wedge us
    timeout "${SSH_CMD_TIMEOUT:-1800}" \
        ssh -i "$SSHKEY" -p "$SSH_PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        -o LogLevel=ERROR ubuntu@127.0.0.1 "$@"
}

wait_ssh() {  # $1 = seconds
    local i
    for ((i = 0; i < $1 * 2; i++)); do
        ssh_vm true 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

qemu_common() {  # $1 = disk, $2 = extra args...
    set -- qemu-system-x86_64 \
        -enable-kvm -cpu host -smp "$VM_SMP" -m "$VM_MEM" \
        -drive "file=$1,if=virtio,format=qcow2" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
        -device virtio-net-pci,netdev=n0 \
        -virtfs "local,path=$REPO,mount_tag=a2tp,security_model=none" \
        "${@:2}"
    "$@"
}

# ---------------------------------------------------------------- fetch
do_fetch() {
    mkdir -p "$QDIR"
    if [ -f "$BASE" ]; then
        say "fetch: $BASE already present"
    else
        say "fetch: downloading Ubuntu 26.04 cloud image (~600M)..."
        curl -fL --retry 3 -o "$BASE.part" "$IMG_URL" && mv "$BASE.part" "$BASE"
    fi
    if [ ! -f "$SSHKEY" ]; then
        ssh-keygen -q -N "" -t ed25519 -f "$SSHKEY"
    fi
    say "fetch: done"
}

# ---------------------------------------------------------------- bake
do_bake() {
    [ -f "$BASE" ] || { say "bake: run '$0 fetch' first"; exit 1; }
    mkdir -p "$QDIR"
    # cloud-init only injects the ssh key; everything else is driven over
    # ssh below so we can see progress and verify each step deterministically
    cat > "$QDIR/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - $(cat "$SSHKEY.pub")
EOF
    printf 'instance-id: a2tp-bake-002\nlocal-hostname: a2tpvm\n' > "$QDIR/meta-data"
    cloud-localds "$SEED" "$QDIR/user-data" "$QDIR/meta-data"

    rm -f "$BAKED"
    qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$BAKED" 40G
    say "bake: booting setup VM (console log: $SERLOG)"
    qemu_common "$BAKED" \
        -drive "file=$SEED,if=virtio,format=raw,readonly=on" \
        -display none -serial "file:$SERLOG" -monitor none -no-reboot \
        -daemonize -pidfile "$QDIR/bake.pid" || { say "bake: qemu failed to start"; exit 1; }

    if ! wait_ssh 300; then
        say "bake: ssh never came up (console: $SERLOG)"; return 1
    fi
    say "bake: ssh up; installing toolchain + headers (slow via SLIRP)..."
    if ! SSH_CMD_TIMEOUT="${BAKE_TIMEOUT:-1800}" ssh_vm \
        'sudo sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump ethtool build-essential linux-headers-generic wireguard-tools"'; then
        say "bake: package install failed"; ssh_vm 'sudo poweroff' 2>/dev/null; return 1
    fi
    ssh_vm 'sudo mkdir -p /mnt/a2tp && echo "a2tp /mnt/a2tp 9p trans=virtio,version=9p2000.L,msize=104857600 0 0" | sudo tee -a /etc/fstab >/dev/null && grep a2tp /etc/fstab'
    ssh_vm 'sudo poweroff'
    for _ in $(seq 40); do
        kill -0 "$(cat "$QDIR/bake.pid" 2>/dev/null)" 2>/dev/null || break
        sleep 0.5
    done
    rm -f "$QDIR/bake.pid"
    say "bake: done"

    # sanity: boot the baked image once and print kernel + 9p mount state
    do_test 'uname -r; mount | grep a2tp || sudo mount /mnt/a2tp; ls /mnt/a2tp | head -5'
}

# ---------------------------------------------------------------- run (interactive)
do_run() {
    [ -f "$BAKED" ] || { say "run: run '$0 bake' first"; exit 1; }
    local ovl
    ovl=$(mktemp -p "$QDIR" run-XXXXXX.qcow2)
    trap 'rm -f "$ovl"' EXIT
    qemu-img create -f qcow2 -b "$BAKED" -F qcow2 "$ovl" >/dev/null
    say "run: console on this terminal; ctrl-a x to quit"
    qemu_common "$ovl" -nographic -no-reboot
}

# ---------------------------------------------------------------- test
do_test() {  # $1 = command to run inside the VM
    [ -f "$BAKED" ] || { say "test: run '$0 bake' first"; exit 1; }
    local cmd=${1:?usage: $0 test "<command>"} ovl rc=1
    ovl=$(mktemp -p "$QDIR" test-XXXXXX.qcow2)
    # shellcheck disable=SC2064
    trap "rm -f '$ovl'; pkill -f 'hostfwd=tcp:127.0.0.1:$SSH_PORT' 2>/dev/null" EXIT
    qemu-img create -f qcow2 -b "$BAKED" -F qcow2 "$ovl" >/dev/null

    qemu_common "$ovl" -display none -serial "file:$SERLOG" \
        -monitor none -no-reboot -daemonize -pidfile "$QDIR/test-vm.pid"

    if ! wait_ssh "${TEST_SSH_WAIT:-120}"; then
        say "test: ssh never came up (console: $SERLOG)"; return 1
    fi
    ssh_vm "sudo mount /mnt/a2tp 2>/dev/null; $cmd"
    rc=$?
    ssh_vm 'sudo sync; sudo poweroff' 2>/dev/null
    for _ in $(seq 20); do
        [ -e "$QDIR/test-vm.pid" ] && kill -0 "$(cat "$QDIR/test-vm.pid")" 2>/dev/null || break
        sleep 0.5
    done
    say "test: VM shut down, command rc=$rc"
    return "$rc"
}

case "${1:-}" in
    fetch) do_fetch ;;
    bake)  do_bake ;;
    run)   do_run ;;
    test)  shift; do_test "$@" ;;
    *) sed -n '2,15p' "$0"; exit 2 ;;
esac
