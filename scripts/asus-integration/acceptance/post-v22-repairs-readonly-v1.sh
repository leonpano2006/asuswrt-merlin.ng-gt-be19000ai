#!/bin/bash
# SOURCE ONLY. Both authenticated V22 logins must pass before root runs this.
# Bounded point snapshot; no service actions, ACK, acceptance or web login.
set +x
set -u -o pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
EXPECTED_BOOT=${1:?actual native boot UUID required}; FAILURES=0; COMMAND_ERRORS=0; SECONDS=0
check() { if [[ $2 == "$3" ]]; then printf 'CHECK %s PASS\n' "$1"; else printf 'CHECK %s FAIL\n' "$1"; ((FAILURES+=1)); fi; }
get() { ((SECONDS<60)) && /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" </dev/null 2>/dev/null | /usr/bin/head -c 8192; }
trap 'printf "READONLY_INCOMPLETE reason=signal\n"; exit 143' TERM INT HUP
boot=$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)
[[ $EUID == 0 && $EXPECTED_BOOT =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $boot == "$EXPECTED_BOOT" && $boot != 00000000-0000-4000-8000-000000000035 ]] || { printf 'REFUSED uid_or_boot\n'; exit 125; }
hostns=$(get /usr/bin/readlink /proc/1/ns/mnt)
[[ $(get /usr/bin/readlink /proc/self/ns/mnt) == "$hostns" && $(get /usr/bin/readlink /proc/1/exe) == /usr/lib/systemd/systemd ]] || { printf 'REFUSED native_namespace_or_pid1\n'; exit 125; }
root=$(get /usr/bin/findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /)
[[ $root == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || { printf 'REFUSED native_root_uuid_rw\n'; exit 125; }
[[ $(get /usr/bin/uname -r) == 4.19.294 && $(get /usr/bin/uname -v) == '#10 '* ]] || { printf 'REFUSED native_kernel_identity\n'; exit 125; }
printf 'READONLY_BEGIN revision=v22-repairs scope=bounded_point_snapshot no_ack=true no_accept=true\n'
stat_identity() { local raw tail; local -a fields=(); ID_START= ID_PARENT=; [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1; IFS= read -r -n 8192 raw 2>/dev/null < "/proc/$1/stat" || return 1; [[ $raw == "$1 ("*") "* ]] || return 1; tail=${raw##*) }; read -r -a fields <<< "$tail"; [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[0-9]+$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1; ID_START=${fields[19]}; ID_PARENT=${fields[1]}; }
GUARD=/mnt/leon-vendor-root/usr/libexec/leon-boot/trial-guardian
broker=$(get /usr/bin/systemctl show leon-asus-broker.service -p MainPID --value)
[[ $(get /usr/bin/systemctl is-active leon-asus-broker.service) == active && $broker =~ ^[1-9][0-9]*$ && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] || { printf 'REFUSED active_canonical_broker\n'; exit 125; }
stat_identity "$broker" || exit 125; BROKER_START=$ID_START
RC=; GUARDIAN=; rc_matches=0; guardian_matches=0; scanned=0
rc_identity() { [[ /proc/$1/exe -ef /usr/libexec/asus/rc ]] && stat_identity "$1"; }
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || { printf 'REFUSED identity_scan_incomplete\n'; exit 125; }
 pid=${proc##*/}
 if rc_identity "$pid" && [[ $ID_PARENT == "$broker" ]]; then RC=$pid; ((rc_matches+=1)); fi
 if [[ $proc/exe -ef $GUARD ]] && stat_identity "$pid" && [[ $ID_PARENT == 1 ]]; then GUARDIAN=$pid; ((guardian_matches+=1)); fi
done
[[ $rc_matches == 1 && $guardian_matches == 1 ]] || { printf 'REFUSED unique_direct_rc_or_immutable_guardian\n'; exit 125; }
rc_identity "$RC" || exit 125; RC_START=$ID_START; RC_NS=$(get /usr/bin/readlink "/proc/$RC/ns/mnt")
[[ -n $RC_NS && $RC_NS != "$hostns" ]] || { printf 'REFUSED no_private_rc_namespace\n'; exit 125; }
exec {RC_NS_FD}< "/proc/$RC/ns/mnt"
private_ok() { local start; stat_identity "$broker" && [[ $ID_START == "$BROKER_START" && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] && rc_identity "$RC" && [[ $ID_START == "$RC_START" && $ID_PARENT == "$broker" && $(get /usr/bin/readlink "/proc/$RC/ns/mnt") == "$RC_NS" && $(get /usr/bin/readlink "/proc/self/fd/$RC_NS_FD") == "$RC_NS" ]]; }
private_ok || { printf 'REFUSED private_namespace_lifetime\n'; exit 125; }
stat_identity "$GUARDIAN" || exit 125; GUARDIAN_START=$ID_START
[[ $(get /usr/bin/stat --format=%u "/proc/$GUARDIAN") == 0 && $(get /usr/bin/readlink "/proc/$GUARDIAN/ns/mnt") == "$hostns" ]] || { printf 'REFUSED guardian_owner_or_namespace\n'; exit 125; }
guard_mount=$(get /usr/bin/findmnt -rn -o FSTYPE,OPTIONS -T "$GUARD")
[[ $guard_mount == 'squashfs ro,'* ]] || { printf 'REFUSED guardian_not_immutable_squashfs\n'; exit 125; }
for row in "4596ee61c2d497b41b924df713e25d8ddbc75ae851e1edb3c4711e4acd16ec89 /proc/$GUARDIAN/exe" "ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 /proc/$RC/exe" "c2cdb625f59d1b2b4c187fe46a9b8df12750e9d0a478c6f82f3aee2f7a5d85fd /proc/$broker/exe"; do
 read -r hash path <<< "$row"; value=$(get /usr/bin/sha256sum "$path"); check "running_hash_${path%/exe}" "${value%% *}" "$hash"
done
check private_sh "$(get /usr/bin/readlink "/proc/$RC/root/usr/sbin/sh")" /usr/libexec/asus/ash
marker="/proc/$RC/root/etc/.asus-private-etc"
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$marker") == 'regular file 0 0 600 1' && ! /proc/$RC/root/etc -ef /etc ]] || { printf 'REFUSED private_etc_metadata\n'; exit 125; }
value=$(get /usr/bin/sha256sum "$marker"); check private_etc_marker "${value%% *}" 1c205578ec70bd60cdc74beed8f3d0deef1f045780eac31b91148ed8b3c55bec
((FAILURES==0)) || { printf 'REFUSED native_or_private_identity\n'; exit 125; }
vendor() { private_ok || return 125; get /usr/bin/nsenter --mount="/proc/self/fd/$RC_NS_FD" -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' "$@"; local code=$?; private_ok || return 125; return "$code"; }
# Verify the byte-exact helper/alias without running certificate generation.
helper=/usr/libexec/asus/scripts/gencert.sh
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h %s' "$helper") == 'regular file 0 0 755 1 10430' ]] || { printf 'REFUSED gencert_file_metadata\n'; exit 125; }
value=$(get /usr/bin/sha256sum "$helper"); check gencert_exact_stock_bytes "${value%% *}" a52a57a1af92407bbf57c6e624a2c5c2f67f59163c9fab0d751d7693514ee517
check gencert_private_alias "$(get /usr/bin/readlink "/proc/$RC/root/usr/sbin/gencert.sh")" "$helper"
[[ /proc/$RC/root/usr/sbin/gencert.sh -ef $helper ]] || { printf 'REFUSED gencert_private_target\n'; exit 125; }
# Only daemon comm/executable/lifetime/namespace, never argv/environment/clients.
aimesh=0; lldp=0; httpd=0; matched=0; scanned=0
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || { printf 'REFUSED daemon_scan_incomplete\n'; exit 125; }
 IFS= read -r -n 16 comm < "$proc/comm" 2>/dev/null || continue
 case $comm in amas_bhctrl|amas_status|amas_lanctrl|amas_misc|amas_wlcconnect) expected=/usr/libexec/asus/rc;; lldpd) expected=/usr/libexec/asus/vendor/usr/sbin/lldpd;; httpd) expected=/usr/libexec/asus/vendor/usr/sbin/httpd;; *) continue;; esac
 pid=${proc##*/}; [[ $proc/exe -ef $expected ]] && stat_identity "$pid" || continue; start=$ID_START
 [[ $(get /usr/bin/readlink "$proc/ns/mnt") == "$RC_NS" ]] || continue
 stat_identity "$pid" && [[ $ID_START == "$start" && $proc/exe -ef $expected && $(get /usr/bin/head -c 16 "$proc/comm") == "$comm" ]] || continue
 ((matched+=1)); ((matched<=16)) || { printf 'REFUSED daemon_match_cap\n'; exit 125; }
 case $comm in amas_*) ((aimesh+=1));; lldpd) ((lldp+=1));; httpd) ((httpd+=1));; esac
 printf 'PROCESS pid=%s comm=%s canonical_exe=%s\n' "$pid" "$comm" "$expected"
done
check genuine_aimesh_observed "$((aimesh>0))" 1; check genuine_lldpd_observed "$((lldp>0))" 1; check genuine_httpd_observed "$((httpd>0))" 1
listeners=$(get /usr/bin/ss -H -lnt 'sport = :8443'); check https_8443_listener "$([[ -n $listeners ]] && printf 1 || printf 0)" 1
# Stock curl only requests unauthenticated HEAD; suppress all headers/body/cookies.
# Self-signed certificate trust is not claimed by this reachability probe.
curl=/usr/libexec/asus/vendor/usr/sbin/curl
value=$(get /usr/bin/sha256sum "$curl"); check fixed_vendor_curl "${value%% *}" 834f615b5f046909e3ab6a5bb318b799c35ea78c4cdaec305d6f2ffcbe86b183
((FAILURES==0)) || { printf 'REFUSED https_identity_or_alias\n'; exit 125; }
http_code=$(vendor "$curl" --silent --insecure --head --connect-timeout 1 --max-time 2 --output /dev/null --write-out '%{http_code}\n' https://192.168.100.15:8443/); code=$?
check https_head_command "$code" 0
check https_http_response "$([[ $http_code =~ ^(200|301|302|303|307|308|401|403)$ ]] && printf 1 || printf 0)" 1
[[ $http_code =~ ^[1-5][0-9][0-9]$ ]] && printf 'HTTPS_RESPONSE status=%s certificate_trust_unproven=true no_login=true\n' "$http_code"
# Reuse V21 aggregate-only queries, now with dynamic PID and held mount FD.
for role in history ccr; do
 unit=leon-asus-telemetry-$role.service
 check "${role}_autostart" "$(get /usr/bin/systemctl is-enabled "$unit")" enabled
 check "${role}_active" "$(get /usr/bin/systemctl is-active "$unit")" active
 pid=$(get /usr/bin/systemctl show "$unit" -p MainPID --value)
 [[ $pid =~ ^[1-9][0-9]*$ ]] && stat_identity "$pid" || { printf 'REFUSED telemetry_pid\n'; exit 125; }; start=$ID_START
 [[ /proc/$pid/exe -ef /usr/libexec/asus/ash && $(get /usr/bin/readlink "/proc/$pid/ns/mnt") == "$RC_NS" ]] || { printf 'REFUSED telemetry_exe_or_namespace\n'; exit 125; }
 stat_identity "$pid" && [[ $ID_START == "$start" ]] || { printf 'REFUSED telemetry_lifetime\n'; exit 125; }
 printf 'PRIVATE_SERVICE role=%s pid=%s same_rc_namespace=true\n' "$role" "$pid"
done
for db in node_stats ccr_status; do
 path=/proc/$RC/root/tmp/.diag/$db.db
 [[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$path") == 'regular file 0 0 600 1' ]] || { printf 'REFUSED collector_db_metadata\n'; exit 125; }
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
stat_identity "$GUARDIAN" && [[ $ID_START == "$GUARDIAN_START" && $ID_PARENT == 1 && /proc/$GUARDIAN/exe -ef $GUARD ]]; check same_guardian_lifetime_at_end "$?" 0
check same_boot_at_end "$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)" "$boot"
printf 'UNPROVEN=browser_rendering,certificate_trust,privacy_terms,WiFi_client_auth_roaming,physical_RGB,AI_container_operation,USB_CAN,SL_application_state,accepted_runtime,permanent_boot;kernel10_provenance_reused;root_rw_flag_only\n'
((SECONDS<60)) || { printf 'READONLY_INCOMPLETE reason=internal_deadline\n'; ((COMMAND_ERRORS+=1)); }
printf 'READONLY_END failures=%s command_errors=%s SL_accounts_containers_unmodified_by_this_script=true\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
