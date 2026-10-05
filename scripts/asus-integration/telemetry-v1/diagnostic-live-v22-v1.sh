#!/bin/bash
# Bounded same-boot telemetry diagnosis; no service actions, argv/env or clients.
set +x
set -u -o pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
EXPECTED_BOOT=${1:?}; FAILURES=0; COMMAND_ERRORS=0; SECONDS=0
check() { if [[ $2 == "$3" ]]; then printf 'CHECK %s PASS\n' "$1"; else printf 'CHECK %s FAIL\n' "$1"; ((FAILURES+=1)); fi; }
get() { ((SECONDS<60)) && /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" </dev/null 2>/dev/null | /usr/bin/head -c 8192; }
trap 'printf "READONLY_INCOMPLETE reason=signal\n"; exit 143' TERM INT HUP
boot=$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)
[[ $EUID == 0 && $EXPECTED_BOOT =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $boot == "$EXPECTED_BOOT" && $boot != 00000000-0000-4000-8000-000000000035 ]] || { printf 'REFUSED uid_or_boot\n'; exit 125; }
hostns=$(get /usr/bin/readlink /proc/1/ns/mnt)
[[ $(get /usr/bin/readlink /proc/self/ns/mnt) == "$hostns" && $(get /usr/bin/readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(get /usr/bin/findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /) == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || { printf 'REFUSED native_namespace_or_root\n'; exit 125; }
stat_identity() { local raw tail; local -a fields=(); ID_START= ID_PARENT=; [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1; IFS= read -r -n 8192 raw 2>/dev/null < "/proc/$1/stat" || return 1; [[ $raw == "$1 ("*") "* ]] || return 1; tail=${raw##*) }; read -r -a fields <<< "$tail"; [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[0-9]+$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1; ID_START=${fields[19]}; ID_PARENT=${fields[1]}; }
broker=$(get /usr/bin/systemctl show leon-asus-broker.service -p MainPID --value)
[[ $(get /usr/bin/systemctl is-active leon-asus-broker.service) == active && $broker =~ ^[1-9][0-9]*$ && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] || { printf 'REFUSED active_canonical_broker\n'; exit 125; }
stat_identity "$broker" || exit 125; BROKER_START=$ID_START
RC=; matches=0; scanned=0
rc_identity() { [[ /proc/$1/exe -ef /usr/libexec/asus/rc ]] && stat_identity "$1"; }
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || { printf 'REFUSED rc_scan_incomplete\n'; exit 125; }
 pid=${proc##*/}; if rc_identity "$pid" && [[ $ID_PARENT == "$broker" ]]; then RC=$pid; ((matches+=1)); fi
done
[[ $matches == 1 ]] || { printf 'REFUSED unique_direct_rc\n'; exit 125; }
rc_identity "$RC" || exit 125; RC_START=$ID_START; RC_NS=$(get /usr/bin/readlink "/proc/$RC/ns/mnt")
[[ -n $RC_NS && $RC_NS != "$hostns" ]] || { printf 'REFUSED no_private_rc_namespace\n'; exit 125; }
exec {RC_NS_FD}< "/proc/$RC/ns/mnt"
private_ok() { stat_identity "$broker" && [[ $ID_START == "$BROKER_START" && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] && rc_identity "$RC" && [[ $ID_START == "$RC_START" && $ID_PARENT == "$broker" && $(get /usr/bin/readlink "/proc/$RC/ns/mnt") == "$RC_NS" && $(get /usr/bin/readlink "/proc/self/fd/$RC_NS_FD") == "$RC_NS" ]]; }
private_ok || { printf 'REFUSED private_namespace_lifetime\n'; exit 125; }
marker=/proc/$RC/root/etc/.asus-private-etc
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$marker") == 'regular file 0 0 600 1' && ! /proc/$RC/root/etc -ef /etc ]] || { printf 'REFUSED private_etc_metadata\n'; exit 125; }
printf 'TELEMETRY_DIAGNOSTIC_BEGIN boot=%s rc_pid=%s rc_starttime=%s host_ns=%s rc_ns=%s\n' "$boot" "$RC" "$RC_START" "$hostns" "$RC_NS"
# Fixed public code hashes, never credential files or process arguments.
for row in 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 /usr/libexec/asus/rc' 'c2cdb625f59d1b2b4c187fe46a9b8df12750e9d0a478c6f82f3aee2f7a5d85fd /usr/libexec/asus/rc-broker' '9ef57c1e25b49471e581e35994603fd7ac8b8096d0862f9e7cc0dcc9012df80a /usr/libexec/asus/ash' '686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6 /usr/libexec/asus/busybox' '7874838efde5bdf16a21554b0e51f2da200f2a560e63a699ecbb7fd95e99180c /usr/libexec/leon-asus/telemetry-namespace-exec' 'b0bf8ee66fdd11544be62edf5e54e5f0337b4470e920929247ef6d0d5e4ccb2b /usr/share/asus/integration/rc.sha256' '8e80168e546acf5bffe65e495ee83d2c13c872efa54f7801372cd1fd75314f2d /usr/libexec/node-history/history.sh' 'a787177b02f80429fbe2e79d23f269ca151c030680bafff2681f663951e48cf2 /usr/libexec/ccr-status/collect.sh'; do
 read -r hash path <<< "$row"; value=$(get /usr/bin/sha256sum "$path"); check "code_hash_$path" "${value%% *}" "$hash"
done
value=$(get /usr/bin/sha256sum "$marker"); check private_etc_marker "${value%% *}" 1c205578ec70bd60cdc74beed8f3d0deef1f045780eac31b91148ed8b3c55bec
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h %s' /usr/libexec/asus/ash) == 'regular file 0 0 755 1 76096' ]] || { printf 'REFUSED ash_entry_metadata\n'; exit 125; }
((FAILURES==0)) || { printf 'REFUSED pinned_code_identity\n'; exit 125; }
vendor() { private_ok || return 125; get /usr/bin/nsenter --mount="/proc/self/fd/$RC_NS_FD" -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' "$@"; local code=$?; private_ok || return 125; return "$code"; }
for role in history ccr; do
 unit=leon-asus-telemetry-$role.service
 properties=$(get /usr/bin/systemctl show "$unit" -p Id -p ActiveState -p SubState -p MainPID -p Result -p ExecMainCode -p ExecMainStatus -p NRestarts); code=$?
 check "${role}_unit_status_query" "$code" 0
 while IFS='=' read -r key value; do
  case $key in Id) [[ $value == "$unit" ]] || continue;; ActiveState|SubState|Result) [[ $value =~ ^[a-zA-Z0-9_.-]{1,40}$ ]] || continue;; MainPID|ExecMainCode|ExecMainStatus|NRestarts) [[ $value =~ ^[0-9]+$ ]] || continue;; *) continue;; esac
  printf 'UNIT role=%s %s=%s\n' "$role" "$key" "$value"
 done <<< "$properties"
 check "${role}_enabled" "$(get /usr/bin/systemctl is-enabled "$unit")" enabled
 check "${role}_active" "$(get /usr/bin/systemctl is-active "$unit")" active
 pid=$(get /usr/bin/systemctl show "$unit" -p MainPID --value)
 if [[ $pid =~ ^[1-9][0-9]*$ ]] && stat_identity "$pid"; then
  start=$ID_START; parent=$ID_PARENT; exe_class=unknown; canonical=unknown
  for row in 'busybox /usr/libexec/asus/busybox' 'ash-entry /usr/libexec/asus/ash' 'native-bash /usr/bin/bash' 'native-nsenter /usr/bin/nsenter'; do
   read -r label path <<< "$row"; if [[ /proc/$pid/exe -ef $path ]]; then exe_class=$label; canonical=$path; break; fi
  done
  ns=$(get /usr/bin/readlink "/proc/$pid/ns/mnt"); ns_class=other
  [[ $ns == "$hostns" ]] && ns_class=native; [[ $ns == "$RC_NS" ]] && ns_class=private_rc
  [[ $ns =~ ^mnt:\[[0-9]+\]$ ]] || ns=unavailable
  printf 'MAINPID role=%s pid=%s parent=%s starttime=%s exe_class=%s canonical=%s namespace=%s namespace_class=%s\n' "$role" "$pid" "$parent" "$start" "$exe_class" "$canonical" "$ns" "$ns_class"
  value=$(get /usr/bin/sha256sum "/proc/$pid/exe"); actual=${value%% *}; [[ $actual =~ ^[a-f0-9]{64}$ ]] && printf 'MAINPID_CODE role=%s sha256=%s\n' "$role" "$actual"
  check "${role}_steady_busybox" "$exe_class" busybox
  check "${role}_running_busybox_hash" "$actual" 686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6
  check "${role}_root_process" "$(get /usr/bin/stat --format=%u "/proc/$pid")" 0
  check "${role}_private_namespace" "$ns_class" private_rc
  stat_identity "$pid" && [[ $ID_START == "$start" && /proc/$pid/exe -ef /usr/libexec/asus/busybox && $(get /usr/bin/readlink "/proc/$pid/ns/mnt") == "$RC_NS" && $(get /usr/bin/systemctl show "$unit" -p MainPID --value) == "$pid" ]]; check "${role}_lifetime_at_end" "$?" 0
 else
  printf 'MAINPID role=%s unavailable=true\n' "$role"; check "${role}_running_mainpid" 0 1
 fi
 # Public journal structure only: explicitly exclude MESSAGE, argv and env.
 journal=$(get /usr/bin/journalctl --boot="$boot" --unit="$unit" --no-pager --lines=8 --output=json --output-fields=_PID,_UID,_SYSTEMD_UNIT,_BOOT_ID,__MONOTONIC_TIMESTAMP,PRIORITY); code=$?
 check "${role}_journal_metadata_query" "$code" 0
 printf 'JOURNAL_METADATA role=%s message_excluded=true\n%s\n' "$role" "$journal"
done
for db in node_stats ccr_status; do
 path=/proc/$RC/root/tmp/.diag/$db.db
 meta=$(get /usr/bin/stat '--format=%F %u %g %a %h %s' "$path"); code=$?
 if [[ $code != 0 ]]; then printf 'DB_METADATA db=%s unavailable=true\n' "$db"; check "${db}_present" 0 1; continue; fi
 [[ $meta =~ ^regular\ file\ 0\ 0\ 600\ 1\ [0-9]+$ ]] || { printf 'REFUSED collector_db_metadata\n'; exit 125; }
 printf 'DB_METADATA db=%s %s\n' "$db" "$meta"
 aggregate=$(vendor /usr/libexec/asus/collector-tools/sqlite3 -readonly "/tmp/.diag/$db.db" "SELECT COUNT(*),COALESCE(MAX(data_time),0),CAST(strftime('%s','now') AS INTEGER)-COALESCE(MAX(data_time),0) FROM DATA_INFO;"); code=$?
 check "${db}_readonly_query" "$code" 0
 IFS='|' read -r count latest age extra <<< "$aggregate"
 check "${db}_fresh_rows" "$([[ $count =~ ^[1-9][0-9]*$ && $latest =~ ^[1-9][0-9]*$ && $age =~ ^[0-9]+$ && -z $extra && $aggregate != *$'\n'* ]] && ((10#$age<=60)) && printf 1 || printf 0)" 1
 [[ $count =~ ^[0-9]+$ && $latest =~ ^[0-9]+$ && $age =~ ^[0-9]+$ && -z $extra ]] && printf 'DB_AGGREGATE %s rows=%s latest=%s age_seconds=%s\n' "$db" "$count" "$latest" "$age"
done
summary=$(vendor /usr/libexec/asus/collector-tools/jq -r 'if .schema==1 and .status=="ok" and (.errors|type)=="array" and (.errors|length)==0 and (.seen|type)=="number" and (.attempt|type)=="number" then [1,"ok",(.seen|floor),(.attempt|floor),(now|floor)-(.seen|floor),0]|@tsv else "INVALID" end' /tmp/ccr-status/result.json); code=$?
check ccr_summary_readonly "$code" 0
IFS=$'\t' read -r schema status seen attempt age errors extra <<< "$summary"
check ccr_status_ok_fresh "$([[ $schema == 1 && $status == ok && $seen =~ ^[1-9][0-9]*$ && $attempt =~ ^[1-9][0-9]*$ && $age =~ ^[0-9]+$ && $errors == 0 && -z $extra && $summary != *$'\n'* ]] && ((10#$age<=60)) && printf 1 || printf 0)" 1
[[ $status == ok && $age =~ ^[0-9]+$ && $errors == 0 ]] && printf 'CCR_SUMMARY status=ok age_seconds=%s error_count=0\n' "$age"
check history_error_empty "$(get /usr/bin/stat --format=%s "/proc/$RC/root/tmp/node-history/error")" 0
private_ok; check same_rc_lifetime_and_namespace_at_end "$?" 0
check same_boot_at_end "$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)" "$boot"
printf 'UNPROVEN=continuous_survival,collector_client_records,HTTPS_retest,accepted_runtime,permanent_boot;no_argv_env_or_credentials_read=true\n'
((SECONDS<60)) || { printf 'READONLY_INCOMPLETE reason=internal_deadline\n'; ((COMMAND_ERRORS+=1)); }
printf 'READONLY_END failures=%s command_errors=%s SL_accounts_containers_unmodified_by_this_script=true\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
