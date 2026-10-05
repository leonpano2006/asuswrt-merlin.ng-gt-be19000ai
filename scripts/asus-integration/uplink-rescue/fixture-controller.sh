#!/bin/bash
# Disposable guest's private controller PID/mount/net namespace only.
set -euo pipefail
test -f /QEMU_LAB_GUEST
test "$$" = 1
test "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)"
lab=/usr/libexec/leon-lab/uplink-rescue
run=/run/leon-uplink-rescue-fixture
mount --make-rprivate /
mount -t tmpfs -o mode=1777 tmpfs /tmp
mkdir -m0700 /tmp/leon-uplink-rescue-tools
cp -a "$lab/tools/bin" "$lab/tools/lib" /tmp/leon-uplink-rescue-tools/
install -m0755 "$lab/ip-run.sh" /tmp/leon-uplink-rescue-tools/ip-run.sh
# The signed official ARMv7 BusyBox runs with the same private musl closure.
# This is a fixture-only mount; router/native Ubuntu /bin/busybox is untouched.
mount --bind "$lab/busybox-run.sh" /bin/busybox
printf '%s\n' controller_pid1_ready > "$run/controller-ready"
trap 'exit 125' TERM INT
/bin/busybox ash "$lab/controller.sh" --setup > "$run/controller-setup.log" 2>&1
touch "$run/controller-configured"
for i in $(seq 1 900); do
    test ! -e "$run/controller-cleanup" || break
    sleep 0.1
done
test -e "$run/controller-cleanup"
/bin/busybox ash "$lab/controller.sh" --cleanup-owned > "$run/controller-cleanup.log" 2>&1
touch "$run/controller-cleaned"
