#!/bin/busybox sh
export PATH=/docker:/bin LC_ALL=C
/bin/busybox --install -s /bin
exec </dev/console >/dev/console 2>&1
stage=entry
failed() {
    trap - EXIT
    echo "LAB_DOCKER_CGROUP_V2_FAILED stage=$stage"
    test ! -f /tmp/dockerd.log || tail -60 /tmp/dockerd.log
    poweroff -f
    while :; do sleep 1; done
}
trap failed EXIT
test "$$" = 1 && test -f /QEMU_LAB_GUEST || exit 1
echo QEMU_DOCKER_CGROUP_V2_INIT_REACHED
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
mkdir -p /dev/pts /dev/shm /var/run /sys/fs/cgroup
mount -t devpts devpts /dev/pts || exit 1
mount -t tmpfs tmpfs /dev/shm || exit 1
stage=unified-hierarchy
mount -t cgroup2 cgroup2 /sys/fs/cgroup || exit 1
grep -q ' /sys/fs/cgroup .* - cgroup2 cgroup2 ' /proc/self/mountinfo || exit 1
for controller in cpu memory pids; do
    grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || exit 1
done
# Move PID1 first. All later fixture workers inherit this leaf; Docker's
# separately empty domain receives controllers rather than host/PID1 tasks.
mkdir /sys/fs/cgroup/fixture-init || exit 1
echo 1 > /sys/fs/cgroup/fixture-init/cgroup.procs || exit 1
grep -qx '1' /sys/fs/cgroup/fixture-init/cgroup.procs || exit 1
echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control || exit 1
mkdir /sys/fs/cgroup/fixture-docker || exit 1
echo '+cpu +memory +pids' > /sys/fs/cgroup/fixture-docker/cgroup.subtree_control || exit 1
echo LAB_DOCKER_CGROUP_V2_PASS pid1_rehomed_controllers_enabled
stage=disposable-storage
for n in raid6_pq xor btrfs exportfs overlay; do
    /load_one "$n" "/modules/$n.ko" || exit 1
done
test -b /dev/loop0 || mknod /dev/loop0 b 7 0 || exit 1
losetup /dev/loop0 /btrfs.img || exit 1
mount -t btrfs -o acl,compress-force=zstd /dev/loop0 /mnt || exit 1
mkdir /mnt/docker || exit 1
# Reuse the accepted tmpfs/chroot view needed because initramfs rootfs cannot
# be pivot_root's old root. All bind sources are disposable guest objects.
mount --make-rprivate / || exit 1
mkdir /view && mount -t tmpfs -o size=1m tmpfs /view || exit 1
for d in bin docker etc dev proc sys tmp mnt var; do
    mkdir /view/$d && mount --rbind /$d /view/$d || exit 1
done
mkdir /view/root && ln -s var/run /view/run || exit 1
touch /view/daemon.json /view/device-probe || exit 1
mount --bind /daemon.json /view/daemon.json || exit 1
mount --bind /device-probe /view/device-probe || exit 1
stage=daemon
chroot /view /docker/dockerd --config-file=/daemon.json > /tmp/dockerd.log 2>&1 &
for i in $(seq 1 30); do
    docker info >/tmp/docker-info 2>&1 && break
    sleep 1
done
test "$(docker info --format '{{.CgroupVersion}} {{.CgroupDriver}}')" = '2 cgroupfs' || exit 1
docker version --format '{{.Server.Version}}' || exit 1
echo LAB_DOCKER_CGROUP_V2_PASS actual_unified_cgroupfs_daemon
docker import /image.tar device-bpf-lab:local || exit 1
stage=normal-container-limits
docker run --rm --pull=never --network none --cgroupns private --cpus .25 --memory 32m --pids-limit 32 --cap-drop ALL --security-opt no-new-privileges device-bpf-lab:local /bin/sh -c 'test "$(cat /sys/fs/cgroup/cpu.max)" = "25000 100000" && test "$(cat /sys/fs/cgroup/memory.max)" = 33554432 && test "$(cat /sys/fs/cgroup/pids.max)" = 32 && /memload 8 0' || exit 1
echo LAB_DOCKER_CGROUP_V2_PASS normal_container_cpu_memory_pids
stage=device-deny
# Plain bind mounts confer no device allowance. The guest-only block7:0
# must be rejected by the real inherited BPF device policy with EPERM.
docker run --rm --pull=never --network none --cgroupns private --cap-drop ALL --security-opt no-new-privileges --mount type=bind,src=/device-probe,dst=/device-probe,readonly --mount type=bind,src=/dev/loop0,dst=/probe-device,readonly device-bpf-lab:local /device-probe deny || exit 1
echo LAB_DOCKER_CGROUP_V2_PASS device_read_open_eperm
stage=device-allow
# The only added permission is Docker's normal explicit read-only --device
# rule for the same disposable block node. No capabilities/privileged mode.
docker run --rm --pull=never --network none --cgroupns private --cap-drop ALL --security-opt no-new-privileges --mount type=bind,src=/device-probe,dst=/device-probe,readonly --device /dev/loop0:/probe-device:r device-bpf-lab:local /device-probe allow || exit 1
echo LAB_DOCKER_CGROUP_V2_PASS explicit_device_read_open_allowed
stage=finish
test -z "$(docker ps -aq)" || exit 1
kill "$(cat /var/run/leon-docker/dockerd.pid)" || exit 1
for i in $(seq 1 15); do
    test ! -e /var/run/leon-docker/dockerd.pid && break
    sleep 1
done
sync
trap - EXIT
echo QEMU_DOCKER_CGROUP_V2_COMPLETE
poweroff -f
while :; do sleep 1; done
