#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin LC_ALL=C.UTF-8
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
[ "$(uname -r)" = 4.19.294 ]
[ "$(uname -v)" = '#11 SMP PREEMPT Sat Oct 3 12:00:00 UTC 2026' ]
[ "$(sha256sum /sys/kernel/notes | cut -d' ' -f1)" = bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c ]
[ "$(findmnt -n -o UUID /)" = ea8e47b8-c606-406c-b931-d2244d26ec55 ]
case "${1:-}" in /var/tmp/leon-development-upload.????????/archive.deb) ;; *) exit 64;; esac
[ -f "$1" ] && [ ! -L "$1" ]
work=/var/tmp/leon-docker-smoke-v3
mkdir -m0700 "$work"
cp --no-dereference -- "$1" "$work/device-probe"
[ -f "$work/device-probe" ] && [ ! -L "$work/device-probe" ]
[ "$(sha256sum "$work/device-probe" | cut -d' ' -f1)" = e614d0efe0a5acd827b2890a0f1b299b871cf9fad20849ceebbbf56fdf39eab3 ]
chmod 0500 "$work/device-probe"
[ -b /dev/loop0 ] && [ ! -L /dev/loop0 ]
[ "$(stat -c '%t:%T' /dev/loop0)" = 7:0 ]
boot=$(cat /proc/sys/kernel/random/boot_id)
[ "$EUID" = 0 ]
[ "$(readlink /proc/1/exe)" = /usr/lib/systemd/systemd ]
[ "$(readlink /proc/self/ns/mnt)" = "$(readlink /proc/1/ns/mnt)" ]
stat_identity() {
 local raw tail; local -a fields=()
 ID_START= ID_PARENT=
 [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1
 IFS= read -r -n 8192 raw < "/proc/$1/stat" || return 1
 [[ $raw == "$1 ("*") "* ]] || return 1
 tail=${raw##*) }; read -r -a fields <<< "$tail"
 [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[1-9][0-9]*$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1
 ID_START=${fields[19]}; ID_PARENT=${fields[1]}
}
broker_rc_identity() {
 local process pid count=0 visited=0
 CURRENT_BROKER=$(timeout 2 systemctl show -p MainPID --value leon-asus-broker.service)
 [[ $CURRENT_BROKER =~ ^[1-9][0-9]*$ && /proc/$CURRENT_BROKER/exe -ef /usr/libexec/asus/rc-broker ]]
 [ "$(timeout 2 systemctl is-active leon-asus-broker.service)" = active ]
 [ "$(timeout 2 sha256sum /proc/$CURRENT_BROKER/exe | cut -d' ' -f1)" = c2cdb625f59d1b2b4c187fe46a9b8df12750e9d0a478c6f82f3aee2f7a5d85fd ]
 stat_identity "$CURRENT_BROKER"; CURRENT_BROKER_START=$ID_START
 [ "$ID_PARENT" = 1 ]; [ "$(timeout 2 stat -c %u /proc/$CURRENT_BROKER)" = 0 ]
 [ "$(readlink /proc/$CURRENT_BROKER/ns/mnt)" = "$(readlink /proc/1/ns/mnt)" ]
 # kernel4.19 lacks the optional per-task children file; use the existing
 # bounded canonical-executable/PPID scan without reading argv/environment.
 for process in /proc/[0-9]*; do
  ((visited+=1)); ((visited<=512))
  pid=${process##*/}
  if [[ /proc/$pid/exe -ef /usr/libexec/asus/rc ]] && stat_identity "$pid" && [[ $ID_PARENT == "$CURRENT_BROKER" ]]; then
   ((count+=1)); CURRENT_RC=$pid; CURRENT_RC_START=$ID_START
  fi
 done
 [ "$count" = 1 ]
 [ "$(timeout 2 sha256sum /proc/$CURRENT_RC/exe | cut -d' ' -f1)" = ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 ]
 [ "$(timeout 2 stat -c %u /proc/$CURRENT_RC)" = 0 ]
 stat_identity "$CURRENT_RC"; [ "$ID_START" = "$CURRENT_RC_START" ]; [ "$ID_PARENT" = "$CURRENT_BROKER" ]
 stat_identity "$CURRENT_BROKER"; [ "$ID_START" = "$CURRENT_BROKER_START" ]
 [[ /proc/$CURRENT_RC/exe -ef /usr/libexec/asus/rc && /proc/$CURRENT_BROKER/exe -ef /usr/libexec/asus/rc-broker ]]
 CURRENT_RC_NS=$(readlink "/proc/$CURRENT_RC/ns/mnt")
 [[ $CURRENT_RC_NS =~ ^mnt:\[[0-9]+\]$ ]]
 [ "$CURRENT_RC_NS" != "$(readlink /proc/1/ns/mnt)" ]
}
ethernet_and_modules() {
 [[ /sys/class/net/eth0/master -ef /sys/class/net/br0 ]]
 [ "$(cat /sys/class/net/eth0/carrier)" = 1 ]
 [ "$(cat /sys/class/net/eth0/speed)" = 10000 ]
 [ "$(cat /sys/class/net/eth0/brport/state)" = 3 ]
 for module in dhd hnd; do [ -d "/sys/module/$module" ]; done
}
broker_rc_identity; ethernet_and_modules
asus_pid=$CURRENT_BROKER; asus_start=$CURRENT_BROKER_START
rc_pid=$CURRENT_RC; rc_start=$CURRENT_RC_START; rc_ns=$CURRENT_RC_NS
printf 'ASUS_SMOKE_IDENTITY_BEFORE broker=%s start=%s rc=%s start=%s same_private_namespace=true carrier=1 speed=10000 forwarding=3 modules=dhd,hnd\n' "$asus_pid" "$asus_start" "$rc_pid" "$rc_start"
docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}} Cgroups={{.CgroupDriver}}/{{.CgroupVersion}}'
[ "$(docker info --format '{{.CgroupDriver}}/{{.CgroupVersion}}')" = systemd/2 ]
[ "$(docker image inspect busybox:1.37.0 --format '{{index .RepoDigests 0}}')" = busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e ]
cleanup() {
 for name in leon-docker-smoke-v3 leon-docker-deny-v3 leon-docker-allow-v3; do
  docker rm -f "$name" >/dev/null 2>&1 || true
 done
}
for name in leon-docker-smoke-v3 leon-docker-deny-v3 leon-docker-allow-v3; do
 if docker container inspect "$name" >/dev/null 2>&1; then exit 65; fi
 done
trap cleanup EXIT
docker run --rm --pull=never --name leon-docker-smoke-v3 --network bridge --memory 64m --cpus .25 --pids-limit 32 busybox:1.37.0 sh -eu -c 'echo CONTAINER_EXEC_OK; test "$(cat /sys/fs/cgroup/memory.max)" = 67108864; test "$(cat /sys/fs/cgroup/cpu.max)" = "25000 100000"; test "$(cat /sys/fs/cgroup/pids.max)" = 32; cat /proc/self/cgroup; nslookup example.com; wget -T 10 -q -O /dev/null http://example.com; echo CONTAINER_NETWORK_AND_LIMITS_OK'
for mode in deny allow; do
 args=(--mount "type=bind,src=$work/device-probe,dst=/device-probe,readonly")
 if [ "$mode" = deny ]; then args+=(--mount type=bind,src=/dev/loop0,dst=/probe-device,readonly); else args+=(--device /dev/loop0:/probe-device:r); fi
 docker run --rm --pull=never --name "leon-docker-$mode-v3" --network none --cap-drop ALL --security-opt no-new-privileges "${args[@]}" busybox:1.37.0 /device-probe "$mode"
 done
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
broker_rc_identity; ethernet_and_modules
[ "$CURRENT_BROKER" = "$asus_pid" ]; [ "$CURRENT_BROKER_START" = "$asus_start" ]
[ "$CURRENT_RC" = "$rc_pid" ]; [ "$CURRENT_RC_START" = "$rc_start" ]; [ "$CURRENT_RC_NS" = "$rc_ns" ]
printf 'ASUS_SMOKE_IDENTITY_AFTER broker=%s start=%s rc=%s start=%s same_private_namespace=true carrier=1 speed=10000 forwarding=3 modules=dhd,hnd\n' "$asus_pid" "$asus_start" "$rc_pid" "$rc_start"
iptables-legacy -S FORWARD | grep -x -- '-P FORWARD ACCEPT'
ip6tables-legacy -S FORWARD | grep -x -- '-P FORWARD ACCEPT'
printf 'DOCKER_CONTAINER_CGROUP2_NETWORK_DEVICE_FILTER_PASSED boot=%s\n' "$boot"
