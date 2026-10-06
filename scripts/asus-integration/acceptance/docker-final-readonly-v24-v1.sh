#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
boot=00000000-0000-4000-8000-000000000025
[ "$EUID" = 0 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$boot" ]
[ "$(uname -v)" = '#11 SMP PREEMPT Sat Oct 3 12:00:00 UTC 2026' ]
[ "$(sha256sum /sys/kernel/notes | cut -d' ' -f1)" = bb2994742f8f681f7046672cdf59b38e2e259480b59d368134c2fbd25e67721c ]
[ "$(findmnt -n -o UUID /)" = ea8e47b8-c606-406c-b931-d2244d26ec55 ]
[ "$(/usr/libexec/leon-boot/trial-accept --status --expected-boot-id "$boot")" = "LEON_ACCEPT_STATUS boot_id=$boot accepted_this_boot=1 metadata_committed=2" ]
for unit in docker.service containerd.service leon-asus-broker.service; do
 [ "$(systemctl is-active "$unit")" = active ]
 printf '%s enabled=%s pid=%s\n' "$unit" "$(systemctl is-enabled "$unit" || true)" "$(systemctl show -p MainPID --value "$unit")"
done
[ "$(systemctl show -p MainPID --value leon-asus-broker.service)" = 328 ]
[ "$(awk '{print $22}' /proc/328/stat)" = 990 ]
[ "$(awk '{print $22}' /proc/329/stat)" = 991 ]
[ "$(cat /sys/class/net/eth0/carrier)" = 1 ]
[ "$(cat /sys/class/net/eth0/speed)" = 10000 ]
[ "$(cat /sys/class/net/eth0/brport/state)" = 3 ]
for name in leon-docker-smoke-v3 leon-docker-deny-v3 leon-docker-allow-v3; do
 if docker container inspect "$name" >/dev/null 2>&1; then exit 65; fi
done
printf 'DOCKER_FINAL_READONLY_PASS boot=%s external_ACK_stopped=true accepted_this_boot=1 permanent_slot=2\n' "$boot"
