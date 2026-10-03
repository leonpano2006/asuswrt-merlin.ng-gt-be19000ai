#!/bin/sh
# Invoke only inside a private mount namespace; all storage is RAM backed.
set -eu
D=/tmp/leon-resource6
B=$D/busybox
case "$(uname -v)" in '#6 '*) ;; *) exit 91;; esac
grep -q 'root=/dev/mmcblk0p4' /proc/cmdline
$B mount --make-rprivate /
cd "$D"
mkdir ns
chmod 755 "$D" ns
$B mount -t tmpfs tmpfs /sys/fs/cgroup
for c in cpu cpuset blkio; do
 mkdir /sys/fs/cgroup/$c
 $B mount -t cgroup -o $c $c /sys/fs/cgroup/$c
done
loop=$($B losetup -f)
cleanup() {
 $B losetup -d "$loop" 2>/dev/null || :
 $B rm -f "$D/io.img"
}
trap cleanup EXIT HUP INT TERM
$B dd if=/dev/zero of=io.img bs=1048576 count=8
$B losetup "$loop" "$D/io.img"
"$D/resource-probe" --hardware "$loop"
cleanup
trap - EXIT HUP INT TERM
echo HARDWARE_RESOURCE_COMPLETE
