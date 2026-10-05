#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
[[ $EUID == 0 && ${1:?} == 00000000-0000-4000-8000-000000000029 && $(cat /proc/sys/kernel/random/boot_id) == "$1" && $(readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || exit 125
[[ /proc/315/exe -ef /usr/libexec/asus/rc && $(readlink /proc/315/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]] || exit 125
rc_start=$(awk '{print $22}' /proc/315/stat)
printf 'BOOT=%s\n' "$1"
printf 'PACKAGE='; dpkg-query -W -f='${Status} ${Version}\n' leon-asus-telemetry
printf 'UNITS\n'; systemctl show leon-asus-telemetry-history.service leon-asus-telemetry-ccr.service -p Id -p ActiveState -p SubState -p MainPID -p Result -p ExecMainStatus -p NRestarts
for u in history ccr; do
 unit=leon-asus-telemetry-$u.service
 [[ $(systemctl is-active "$unit") == active ]] || exit 125
 pid=$(systemctl show "$unit" -p MainPID --value)
 [[ $pid =~ ^[1-9][0-9]*$ && $(readlink "/proc/$pid/ns/mnt") == "$(readlink /proc/315/ns/mnt)" ]] || exit 125
 printf 'PRIVATE_SERVICE %s pid=%s namespace=%s\n' "$u" "$pid" "$(readlink "/proc/$pid/ns/mnt")"
done
for db in node_stats ccr_status; do
 path=/proc/315/root/tmp/.diag/$db.db
 [[ $(stat --format='%F %u %g %a %h' "$path") == 'regular file 0 0 600 1' ]] || exit 125
 printf 'DB_META '; stat --format='%n bytes=%s mode=%a uid=%u' "$path"
 printf 'DB_AGGREGATE %s=' "$db"
 timeout -k 1s 3s /usr/bin/nsenter -t 315 -m -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/sqlite3 -readonly "/tmp/.diag/$db.db" "SELECT COUNT(*),COALESCE(MAX(data_time),0),CAST(strftime('%s','now') AS INTEGER)-COALESCE(MAX(data_time),0) FROM DATA_INFO;"
done
printf 'CCR_SUMMARY='
timeout -k 1s 2s /usr/bin/nsenter -t 315 -m -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/jq -c '{schema,status,seen,attempt,errors}' /tmp/ccr-status/result.json
printf 'HISTORY_ERROR_BYTES='; stat --format='%s' /proc/315/root/tmp/node-history/error
[[ /proc/315/exe -ef /usr/libexec/asus/rc && $(awk '{print $22}' /proc/315/stat) == "$rc_start" && $(cat /proc/sys/kernel/random/boot_id) == "$1" ]] || exit 125
printf 'TELEMETRY_CHECK_END same_boot=true same_rc=true private_services_active=true database_metadata_only=true\n'
