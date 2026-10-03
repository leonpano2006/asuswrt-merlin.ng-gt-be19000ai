#!/bin/busybox sh
export PATH=/docker:/bin
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
echo QEMU_LAB_INIT_REACHED
failed(){ echo LAB_DOCKER_MEMCG_FAILED; tail -60 /tmp/dockerd.log; poweroff -f; while :; do sleep 1; done; }
trap failed EXIT
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
mkdir -p /dev/pts /dev/shm /var/run /sys/fs/cgroup
mount -t devpts devpts /dev/pts || exit 1
mount -t tmpfs tmpfs /dev/shm || exit 1
mount -t tmpfs tmpfs /sys/fs/cgroup || exit 1
for c in memory cpuacct devices freezer pids; do mkdir /sys/fs/cgroup/$c; mount -t cgroup -o $c $c /sys/fs/cgroup/$c || exit 1; done
echo 1 > /sys/fs/cgroup/memory/memory.use_hierarchy || exit 1
for n in tfat tntfs thfsplus raid6_pq xor btrfs exportfs overlay; do /load_one "$n" "/modules/$n.ko" || exit 1; done
losetup /dev/loop0 /btrfs.img || exit 1
mount -t btrfs -o acl,compress-force=zstd /dev/loop0 /mnt || exit 1
mkdir /mnt/docker
# initramfs rootfs cannot be pivot_root's old root. Give the daemon a
# separate tmpfs root, with the same private bind view used on the router.
mount --make-rprivate / || exit 1
mkdir /view
mount -t tmpfs -o size=1m tmpfs /view || exit 1
for d in bin docker etc dev proc sys tmp mnt var; do mkdir /view/$d; mount --rbind /$d /view/$d || exit 1; done
mkdir /view/root
ln -s var/run /view/run
touch /view/daemon.json
mount --bind /daemon.json /view/daemon.json || exit 1
chroot /view /docker/dockerd --config-file=/daemon.json > /tmp/dockerd.log 2>&1 &
for i in $(seq 1 30); do docker info >/tmp/docker-info 2>&1 && break; sleep 1; done
docker info || exit 1
docker import /image.tar memcg-lab:local || exit 1
docker run --rm --network none --memory 32m --memory-swap 32m --pids-limit 32 --cap-drop ALL --security-opt no-new-privileges memcg-lab:local /bin/sh -c 'test "$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)" = 33554432 && test "$(cat /sys/fs/cgroup/memory/memory.memsw.limit_in_bytes)" = 33554432 && /memload 8 0' || exit 1
echo LAB_DOCKER_PASS memory_and_memswap_limit_visible
# A file-backed allocation exercises the rebuilt filesystem with memcg enabled.
docker run --rm --network none --memory 32m --memory-swap 32m --pids-limit 32 memcg-lab:local /bin/sh -c 'dd if=/dev/zero of=/testfile bs=1048576 count=8 && sync && test "$(wc -c < /testfile)" = 8388608' || exit 1
echo LAB_DOCKER_PASS btrfs_overlay_pagecache
# Expected cgroup OOM, confined to this offline guest container.
docker run --name memcg-oom --network none --memory 32m --memory-swap 32m --pids-limit 32 --cap-drop ALL --security-opt no-new-privileges memcg-lab:local /memload 96 0
rc=$?
test "$rc" = 137 || exit 1
test "$(docker inspect --format '{{.State.OOMKilled}} {{.State.ExitCode}}' memcg-oom)" = 'true 137' || exit 1
docker rm memcg-oom || exit 1
echo LAB_DOCKER_PASS oom_isolated_and_reported
# Make a disposable swap device backed only by the guest's RAM file.
dd if=/dev/zero of=/swap.img bs=1048576 count=64 || exit 1
losetup /dev/loop1 /swap.img || exit 1
mkswap /dev/loop1 || exit 1
swapon /dev/loop1 || exit 1
cat /proc/swaps
docker run -d --name memcg-swap --network none --memory 32m --memory-swap 64m --memory-swappiness 100 --pids-limit 32 memcg-lab:local /memload 48 6 || exit 1
sleep 2
docker logs memcg-swap
cid=$(docker inspect --format '{{.Id}}' memcg-swap)
cg=/sys/fs/cgroup/memory/docker/$cid
cat "$cg/memory.stat"
awk '$1=="total_swap" && $2>0 {ok=1} END {exit !ok}' "$cg/memory.stat" || exit 1
test "$(docker wait memcg-swap)" = 0 || exit 1
docker logs memcg-swap | grep MEMLOAD_VERIFIED || exit 1
docker rm memcg-swap || exit 1
swapoff /dev/loop1 || exit 1
losetup -d /dev/loop1 || exit 1
rm /swap.img
echo LAB_DOCKER_PASS swap_charge_reclaim_and_data_roundtrip
docker run --rm --network none --memory 32m --memory-swap 32m memcg-lab:local /bin/echo LAB_DOCKER_PASS survives_oom || exit 1
test -z "$(docker ps -aq)" || exit 1
kill "$(cat /var/run/leon-docker/dockerd.pid)" || exit 1
for i in $(seq 1 15); do test ! -e /var/run/leon-docker/dockerd.pid && break; sleep 1; done
sync
trap - EXIT
echo QEMU_DOCKER_MEMCG_COMPLETE
poweroff -f
while :; do sleep 1; done
