#!/bin/bash
# Fixed, bounded missing-function snapshot. No setters, service actions or ACK.
# Transport must first bind both authenticated logins to this exact V23 boot.
set +x
set -u -o pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
EXPECTED_BOOT=${1:?exact native boot UUID required}; FAILURES=0; COMMAND_ERRORS=0; SECONDS=0
check() { if [[ $2 == "$3" ]]; then printf 'CHECK %s PASS\n' "$1"; else printf 'CHECK %s FAIL\n' "$1"; ((FAILURES+=1)); fi; }
get() { ((SECONDS<60)) && /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" </dev/null 2>/dev/null | /usr/bin/head -c 8192; }
trap 'printf "WIFI_VIF_INCOMPLETE reason=signal\n"; exit 143' TERM INT HUP
boot=$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)
[[ $EUID == 0 && $EXPECTED_BOOT =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $boot == "$EXPECTED_BOOT" && $boot == 00000000-0000-4000-8000-000000000008 ]] || { printf 'REFUSED uid_or_v23_boot\n'; exit 125; }
hostns=$(get /usr/bin/readlink /proc/1/ns/mnt)
[[ $(get /usr/bin/readlink /proc/self/ns/mnt) == "$hostns" && $(get /usr/bin/readlink /proc/1/exe) == /usr/lib/systemd/systemd ]] || { printf 'REFUSED native_namespace_or_pid1\n'; exit 125; }
root=$(get /usr/bin/findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /)
[[ $root == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || { printf 'REFUSED native_root_uuid_rw\n'; exit 125; }
stat_identity() { local raw tail; local -a fields=(); ID_START= ID_PARENT=; [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1; IFS= read -r -n 8192 raw 2>/dev/null < "/proc/$1/stat" || return 1; [[ $raw == "$1 ("*") "* ]] || return 1; tail=${raw##*) }; read -r -a fields <<< "$tail"; [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[0-9]+$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1; ID_START=${fields[19]}; ID_PARENT=${fields[1]}; }
broker=$(get /usr/bin/systemctl show leon-asus-broker.service -p MainPID --value)
[[ $broker =~ ^[1-9][0-9]*$ && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] && stat_identity "$broker" || { printf 'REFUSED canonical_broker\n'; exit 125; }; BROKER_START=$ID_START
RC=; matches=0; scanned=0
rc_identity() { [[ /proc/$1/exe -ef /usr/libexec/asus/rc ]] && stat_identity "$1"; }
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || { printf 'REFUSED rc_scan_cap\n'; exit 125; }
 if rc_identity "${proc##*/}" && [[ $ID_PARENT == "$broker" ]]; then RC=${proc##*/}; ((matches+=1)); fi
done
[[ $matches == 1 ]] && rc_identity "$RC" || { printf 'REFUSED unique_direct_rc\n'; exit 125; }; RC_START=$ID_START
RC_NS=$(get /usr/bin/readlink "/proc/$RC/ns/mnt")
[[ -n $RC_NS && $RC_NS != "$hostns" ]] || { printf 'REFUSED no_private_rc_namespace\n'; exit 125; }
exec {RC_NS_FD}< "/proc/$RC/ns/mnt"
private_ok() { stat_identity "$broker" && [[ $ID_START == "$BROKER_START" && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] && rc_identity "$RC" && [[ $ID_START == "$RC_START" && $ID_PARENT == "$broker" && $(get /usr/bin/readlink "/proc/$RC/ns/mnt") == "$RC_NS" && $(get /usr/bin/readlink "/proc/self/fd/$RC_NS_FD") == "$RC_NS" ]]; }
private_ok || { printf 'REFUSED private_namespace_lifetime\n'; exit 125; }
marker="/proc/$RC/root/etc/.asus-private-etc"
[[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$marker") == 'regular file 0 0 600 1' && ! /proc/$RC/root/etc -ef /etc ]] || { printf 'REFUSED private_etc_metadata\n'; exit 125; }
value=$(get /usr/bin/sha256sum "$marker"); [[ ${value%% *} == 1c205578ec70bd60cdc74beed8f3d0deef1f045780eac31b91148ed8b3c55bec ]] || { printf 'REFUSED private_etc_marker\n'; exit 125; }
for row in 'ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 /usr/libexec/asus/rc' '7ea7de4161b9b5e7ee27c3e7933467ce2bdb1b9374599b4c1953cfad87652e2f /usr/libexec/asus/vendor/bin/nvram' '049cec36c1954fec8bb23b74cf8d525304fa23b38938f183e0f2b362d33f1ca1 /usr/libexec/asus/vendor/usr/sbin/wl'; do
 read -r hash path <<< "$row"; value=$(get /usr/bin/sha256sum "$path"); [[ ${value%% *} == "$hash" ]] || { printf 'REFUSED vendor_read_command_identity\n'; exit 125; }
done
vendor() { private_ok || return 125; get /usr/bin/nsenter --mount="/proc/self/fd/$RC_NS_FD" -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' "$@"; local code=$?; private_ok || return 125; return "$code"; }
printf 'WIFI_VIF_BEGIN revision=v23 scope=existing_local_wifi_bss_readonly no_ack=true no_accept=true no_setters=true\n'
# Frozen wl SHA049cec36... command rows and ARM dispatch were read locally:
# ap/isup handler0x43234: argv[1]==NULL ->0x432d8 ->get wrapper0x57a24.
# bss handler0x9c7f4: no argument ->0x9c910 ->WLC_GET_VAR262 via0x57abc.
# bss up/down arguments take the distinct setter branch; never pass them here.
# Existing interfaces only; no scan, BSSID/SSID/PSK getter or client identifiers.
mac_count() { /usr/bin/awk -v prefix="$1" 'BEGIN{n=0;bad=0} NF{first=1;if($1==prefix)first=2;for(i=first;i<=NF;i++){if($i~/^[[:xdigit:]][[:xdigit:]](:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])$/){m=tolower($i);if(!(m in seen)){seen[m]=1;n++}}else bad=1}} END{if(bad||n>512)print "INVALID";else print n}'; }
declare -A COUNTS=()
iface_count=0; cap_hit=0; operational_ap=0; associated_observations=0; authorized_observations=0; assoc_covered=0; autho_covered=0
for path in /sys/class/net/wl*; do
 [[ -e $path ]] || continue; iface=${path##*/}
 [[ $iface =~ ^wl[0-2](\.[1-9][0-9]?)?$ ]] || continue
 ((iface_count+=1)); ((iface_count<=24 && SECONDS<54)) || { cap_hit=1; printf 'UNPROVEN_WIFI_VIF=interface_cap_or_deadline\n'; break; }
 ifindex=$(get /usr/bin/cat "$path/ifindex")
 [[ $ifindex =~ ^[1-9][0-9]{0,8}$ ]] || { printf 'WIFI_VIF iface=%s unavailable_ifindex=true\n' "$iface"; ((COMMAND_ERRORS+=1)); continue; }
 ap=unavailable; isup=unavailable; bss=unavailable
 for query in ap isup bss; do
  value=$(vendor /usr/libexec/asus/vendor/usr/sbin/wl -i "$iface" "$query"); code=$?
  if [[ $code != 0 ]]; then printf 'WIFI_VIF iface=%s query=%s unavailable=true rc=%s\n' "$iface" "$query" "$code"; ((COMMAND_ERRORS+=1)); continue; fi
  if [[ ( $query == ap || $query == isup ) && $value =~ ^[01]$ ]]; then
   [[ $query == ap ]] && ap=$value || isup=$value
  elif [[ $query == bss && ( $value == up || $value == down ) ]]; then bss=$value
  else printf 'WIFI_VIF iface=%s query=%s suppressed_unexpected_shape=true\n' "$iface" "$query"; ((COMMAND_ERRORS+=1)); continue; fi
  printf 'WIFI_VIF iface=%s query=%s value=%s\n' "$iface" "$query" "$value"
 done
 if [[ $ap == 1 && $isup == 1 && $bss == up ]]; then
  ((operational_ap+=1)); printf 'WIFI_VIF iface=%s operational_ap_bss_observed=true point_sample_only=true\n' "$iface"
  for query in assoclist authe_sta_list autho_sta_list; do
   raw=$(vendor /usr/libexec/asus/vendor/usr/sbin/wl -i "$iface" "$query"); code=$?
   if [[ $code != 0 ]]; then printf 'WIFI_VIF_CLIENTS iface=%s query=%s unavailable=true rc=%s\n' "$iface" "$query" "$code"; ((COMMAND_ERRORS+=1)); continue; fi
   count=$(printf '%s\n' "$raw" | mac_count "$query"); unset raw
   [[ $count =~ ^[0-9]+$ ]] || { printf 'WIFI_VIF_CLIENTS iface=%s query=%s invalid_suppressed=true\n' "$iface" "$query"; ((COMMAND_ERRORS+=1)); continue; }
   COUNTS[$iface,$query]=$count
   printf 'WIFI_VIF_CLIENTS iface=%s query=%s count=%s no_client_identifiers=true\n' "$iface" "$query" "$count"
   if [[ $query == assoclist ]]; then ((associated_observations+=count)); ((assoc_covered+=1)); fi
   if [[ $query == autho_sta_list ]]; then ((authorized_observations+=count)); ((autho_covered+=1)); fi
  done
 else
  printf 'WIFI_VIF iface=%s client_queries_skipped=true ap=%s driver_up=%s bss=%s operational_ap_bss_unproven=true\n' "$iface" "$ap" "$isup" "$bss"
 fi
 current_ifindex=$(get /usr/bin/cat "$path/ifindex")
 [[ $current_ifindex == "$ifindex" ]] || { printf 'WIFI_VIF iface=%s changed_ifindex=true aggregate_unproven=true\n' "$iface"; ((FAILURES+=1)); }
done
((iface_count>0)) || { printf 'UNPROVEN_WIFI_VIF=no_valid_existing_interface\n'; ((FAILURES+=1)); }
((cap_hit==0)) || ((COMMAND_ERRORS+=1))
printf 'WIFI_VIF_COVERAGE existing_interfaces_observed=%s operational_ap_bsses=%s association_queries_observed=%s authorization_queries_observed=%s enumeration_capped=%s\n' "$((iface_count>24?24:iface_count))" "$operational_ap" "$assoc_covered" "$autho_covered" "$cap_hit"
if ((operational_ap>0 && assoc_covered==operational_ap && autho_covered==operational_ap && cap_hit==0 && COMMAND_ERRORS==0 && FAILURES==0)); then
 printf 'WIFI_VIF_AGGREGATE associated_interface_observations=%s authorized_interface_observations=%s unique_devices_unproven=true no_client_identifiers=true\n' "$associated_observations" "$authorized_observations"
else
 printf 'WIFI_VIF_AGGREGATE partial_associated_observations=%s partial_authorized_observations=%s total_unproven=true unique_devices_unproven=true\n' "$associated_observations" "$authorized_observations"
fi
private_ok; check wifi_vif_same_rc_lifetime_and_namespace_at_end "$?" 0
check wifi_vif_same_boot_at_end "$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)" "$boot"
printf 'UNPROVEN_WIFI=uncreated_or_unmatched_interfaces,new_client_join_roaming_per_SSID_data_path,unique_devices_MLO_deduplication,controller_membership,physical_RF_reception\n'
((SECONDS<60)) || { printf 'WIFI_VIF_INCOMPLETE reason=internal_deadline\n'; ((COMMAND_ERRORS+=1)); }
printf 'WIFI_VIF_END failures=%s command_errors=%s no_actions=true no_client_identifiers=true\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
