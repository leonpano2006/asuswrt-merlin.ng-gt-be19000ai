#!/bin/bash
# Read-only accepted-current-boot point snapshot; never opens/writes the WDT.
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
boot=${1:?}; phase=${2:?}; SECONDS=0
[[ $phase == before || $phase == after ]] || exit 125
get() { ((SECONDS<45)) && /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" </dev/null | /usr/bin/head -c 8192; }
[[ $EUID == 0 && $boot =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $(get /usr/bin/cat /proc/sys/kernel/random/boot_id) == "$boot" && $(get /usr/bin/readlink /proc/1/exe) == /usr/lib/systemd/systemd ]] || exit 125
hostns=$(get /usr/bin/readlink /proc/1/ns/mnt)
[[ $(get /usr/bin/readlink /proc/self/ns/mnt) == "$hostns" && $(get /usr/bin/findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /) == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || exit 125
[[ $(get /usr/bin/uname -r) == 4.19.294 && $(get /usr/bin/uname -v) == '#10 '* ]] || exit 125
client=/usr/libexec/leon-boot/trial-accept; guard=/mnt/leon-vendor-root/usr/libexec/leon-boot/trial-guardian
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$client") == 'regular file 0 0 755 1' ]] || exit 125
printf '%s  %s\n' 0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3 "$client" | /usr/bin/sha256sum -c -
[[ $(get /usr/bin/findmnt -rn -o FSTYPE,OPTIONS -T "$guard") == 'squashfs ro,'* ]] || exit 125
stat_identity() { local raw tail; local -a fields=(); ID_START= ID_PARENT=; [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1; IFS= read -r -n 8192 raw 2>/dev/null < "/proc/$1/stat" || return 1; [[ $raw == "$1 ("*") "* ]] || return 1; tail=${raw##*) }; read -r -a fields <<< "$tail"; [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[1-9][0-9]*$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1; ID_START=${fields[19]}; ID_PARENT=${fields[1]}; }
guardian=; matches=0; scanned=0
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<45)) || exit 125
 pid=${proc##*/}
 if [[ $proc/exe -ef $guard ]] && stat_identity "$pid" && [[ $ID_PARENT == 1 ]]; then guardian=$pid; ((matches+=1)); fi
done
[[ $matches == 1 ]] || exit 125
stat_identity "$guardian"; start=$ID_START
[[ $(get /usr/bin/stat --format=%u "/proc/$guardian") == 0 && $(get /usr/bin/readlink "/proc/$guardian/ns/mnt") == "$hostns" ]] || exit 125
printf '%s  %s\n' 4596ee61c2d497b41b924df713e25d8ddbc75ae851e1edb3c4711e4acd16ec89 "/proc/$guardian/exe" | /usr/bin/sha256sum -c -
wd_fd=; wd_matches=0; scanned=0
[[ -c /dev/watchdog0 && ! -L /dev/watchdog0 ]] || exit 125
for fd in /proc/$guardian/fd/[0-9]*; do
 ((scanned+=1)); ((scanned<=64 && SECONDS<45)) || exit 125
 if [[ $fd -ef /dev/watchdog0 ]]; then wd_fd=${fd##*/}; ((wd_matches+=1)); fi
done
[[ $wd_matches == 1 && $wd_fd =~ ^[0-9]+$ ]] || exit 125
wd_identity=$(get /usr/bin/stat -L --format=%d:%i:%t:%T "/proc/$guardian/fd/$wd_fd")
[[ $wd_identity =~ ^[0-9]+:[0-9]+:[0-9a-f]+:[0-9a-f]+$ ]] || exit 125
live() { stat_identity "$guardian" && [[ $ID_START == "$start" && $ID_PARENT == 1 && /proc/$guardian/exe -ef $guard && $(get /usr/bin/stat --format=%u "/proc/$guardian") == 0 && $(get /usr/bin/readlink "/proc/$guardian/ns/mnt") == "$hostns" && /proc/$guardian/fd/$wd_fd -ef /dev/watchdog0 && $(get /usr/bin/stat -L --format=%d:%i:%t:%T "/proc/$guardian/fd/$wd_fd") == "$wd_identity" ]]; }
live || exit 125
status=$(get "$client" --status --expected-boot-id "$boot")
[[ $status == "LEON_ACCEPT_STATUS boot_id=$boot accepted_this_boot=1 metadata_committed=2" ]] || exit 125
# Hold the existing regular diagnostic file only, never a WDT FD or device.
diag=/etc/leon/boot-diagnostics
[[ -f $diag && ! -L $diag && -d /etc/leon && ! -L /etc/leon && $(get /usr/bin/stat '--format=%F %u %g %a %h %s' "$diag") == 'regular file 0 0 600 1 16384' ]] || exit 125
diag_identity=$(get /usr/bin/stat --format=%d:%i "$diag")
[[ $(get /usr/bin/stat --format=%d "$diag") == "$(get /usr/bin/stat --format=%d /)" ]] || exit 125
exec {DIAG_FD}< "$diag"
[[ "$diag" -ef /proc/self/fd/$DIAG_FD && $(get /usr/bin/stat -L '--format=%F %u %g %a %h %s' "/proc/self/fd/$DIAG_FD") == 'regular file 0 0 600 1 16384' ]] || exit 125
raw=$(/usr/bin/timeout --signal=TERM --kill-after=1s 2s /usr/bin/base64 --wrap=0 "/proc/self/fd/$DIAG_FD" </dev/null | /usr/bin/head -c 32768)
[[ ${#raw} == 21848 && $raw =~ ^[A-Za-z0-9+/]+={2}$ ]] || exit 125
[[ "$diag" -ef /proc/self/fd/$DIAG_FD && $(get /usr/bin/stat --format=%d:%i "$diag") == "$diag_identity" && $(get /usr/bin/stat -L '--format=%F %u %g %a %h %s' "/proc/self/fd/$DIAG_FD") == 'regular file 0 0 600 1 16384' ]] || exit 125
exec {DIAG_FD}<&-
live || exit 125
status=$(get "$client" --status --expected-boot-id "$boot")
[[ $status == "LEON_ACCEPT_STATUS boot_id=$boot accepted_this_boot=1 metadata_committed=2" && $(get /usr/bin/cat /proc/sys/kernel/random/boot_id) == "$boot" ]] || exit 125
# /proc/uptime is CLOCK_BOOTTIME, the same clock used by production.c clock_ms.
IFS=' ' read -r uptime idle < /proc/uptime
[[ $uptime =~ ^[0-9]+\.[0-9]+$ ]] || exit 125
sec=${uptime%%.*}; frac=${uptime#*.}; frac=${frac}000; frac=${frac:0:3}; now=$((10#$sec*1000+10#$frac))
((SECONDS<45)) || exit 125
printf 'SURVIVAL_BEGIN phase=%s boot_id=%s\nGUARDIAN_PID=%s\nGUARDIAN_STARTTIME=%s\nWATCHDOG_FD=%s\nWATCHDOG_ID=%s\nDIAGNOSTIC_ID=%s\nCURRENT_BOOTTIME_MS=%s\n%s\nDIAGNOSTIC_BASE64=%s\n' "$phase" "$boot" "$guardian" "$start" "$wd_fd" "$wd_identity" "$diag_identity" "$now" "$status" "$raw"
printf 'ACCEPTED_SURVIVAL_END same_boot=true accepted_this_boot=true same_guardian=true same_watchdog_fd=true read_only=true no_ack=true\n'
