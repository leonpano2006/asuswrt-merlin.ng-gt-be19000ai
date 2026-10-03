#!/bin/sh
set -eu
D=/tmp/leon-kernel4-fs
B=$D/busybox
case "$(uname -v)" in '#4 '*|'#5 '*|'#6 '*) ;; *) exit 91;; esac
grep -q 'root=/dev/mmcblk0p4' /proc/cmdline
$B mount --make-rprivate /
cd "$D"
mkdir -p data
loop=$($B losetup -f)
$B losetup "$loop" "$D/btrfs.img"
cleanup() {
 $B umount "$D/merged" 2>/dev/null || :
 $B umount "$D/data" 2>/dev/null || :
 $B losetup -d "$loop" 2>/dev/null || :
}
trap cleanup EXIT HUP INT TERM
$B mount -t btrfs -o compress-force=zstd "$loop" "$D/data"
$B dd if=/dev/zero of=data/pattern bs=1048576 count=4
sum=$($B sha256sum data/pattern | $B cut -d ' ' -f1)
$B sync
$B umount data
$B mount -t btrfs -o compress-force=zstd "$loop" "$D/data"
test "$sum" = "$($B sha256sum data/pattern | $B cut -d ' ' -f1)"
echo HARDWARE_PASS btrfs_zstd_remount_data_roundtrip
mkdir -p data/lower data/upper data/work merged
echo original > data/lower/file
$B mount -t overlay overlay -o "lowerdir=$D/data/lower,upperdir=$D/data/upper,workdir=$D/data/work" "$D/merged"
test "$(cat merged/file)" = original
echo updated > merged/file
test "$(cat data/lower/file)" = original
test "$(cat data/upper/file)" = updated
echo HARDWARE_PASS overlay_copy_up_on_btrfs
$B umount merged
$B umount data
$B losetup -d "$loop"
trap - EXIT HUP INT TERM
echo HARDWARE_FS_PROBE_COMPLETE
