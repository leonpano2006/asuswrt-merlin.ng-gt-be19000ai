#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
boot=${1:?}
[[ $EUID == 0 && $(cat /proc/sys/kernel/random/boot_id) == "$boot" && $(readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" && $(findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /) == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || exit 125
printf 'BOOT=%s\n' "$boot"
/usr/libexec/leon-boot/trial-accept --status --expected-boot-id "$boot"
printf 'PID1_STAT='; head -c 4096 /proc/1/stat
printf 'PID1_OWNER='; stat --format='%u' /proc/1
printf 'PID1_EXE='; stat -L --format='%F %u %g %a' /proc/1/exe
for path in / /data /jffs; do
 printf 'CORE_VOLUME_META '; stat --format='%n type=%F uid=%u dev=%d' "$path"
 printf 'CORE_VOLUME_FS '; stat -f --format='%n fshex=%t' "$path"
 printf 'CORE_VOLUME_MOUNT '; findmnt -rn -o TARGET,FSTYPE,MAJ:MIN,OPTIONS --mountpoint "$path"
done
[[ $(stat --format='%F %u %g %a %h %s' /etc/leon/boot-diagnostics) == 'regular file 0 0 600 1 16384' && ! -L /etc/leon/boot-diagnostics ]] || exit 125
printf 'DIAGNOSTIC_BASE64='; timeout -k 1s 2s base64 --wrap=0 /etc/leon/boot-diagnostics
printf '\n'
[[ $(cat /proc/sys/kernel/random/boot_id) == "$boot" ]] || exit 125
printf 'ACCEPT_DIAG_END same_boot=true read_only=true no_accept=true no_ack=true\n'
