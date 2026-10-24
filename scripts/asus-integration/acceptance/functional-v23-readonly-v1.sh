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
trap 'printf "FUNCTIONAL_INCOMPLETE reason=signal\n"; exit 143' TERM INT HUP
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
printf 'FUNCTIONAL_BEGIN revision=v23 scope=missing_function_point_snapshot no_ack=true no_accept=true no_setters=true\n'
# Fixed NVRAM getters only. Never show/dump NVRAM or read SSID/PSK/accounts.
declare -A STATE=()
for key in sw_mode re_mode cfg_alive cfg_masterip amas_ethernet amas_bhmode amas_status_init amas_ready amas_bhctrl_service_ready amas_status_service_ready amas_lanctrl_service_ready re_upgrade wl0_ifname wl1_ifname wl2_ifname wl0_radio wl1_radio wl2_radio wl0_auth_mode_x wl1_auth_mode_x wl2_auth_mode_x ledg_led_enable ledg_scheme ai_sys_ip_address ai_app_prog_status; do
 value=$(vendor /usr/libexec/asus/vendor/bin/nvram get "$key"); code=$?
 if [[ $code != 0 || ! $value =~ ^[a-zA-Z0-9_.:-]{0,63}$ || $value == *$'\n'* ]]; then printf 'STATE %s unavailable_or_suppressed=true rc=%s\n' "$key" "$code"; ((COMMAND_ERRORS+=1)); continue; fi
 STATE[$key]=$value; printf 'STATE %s=%s\n' "$key" "$value"
done
printf 'MESH_SIGNAL_SCOPE=local_operational_flags_only controller_membership_and_selected_backhaul_unproven=true\n'
# Getter contract: frozen wl ELF help says BSSID getter, associated/authenticated/
# authorized MAC list getters. radio/chanspec are the existing no-argument getters
# used by reviewed post-v21-readonly-v4.sh:78. No scan/join/reassoc or radio setter.
mac_count() { /usr/bin/awk -v prefix="$1" 'BEGIN{n=0;bad=0} NF{first=1;if($1==prefix)first=2;for(i=first;i<=NF;i++){if($i~/^[[:xdigit:]][[:xdigit:]](:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])(:[[:xdigit:]][[:xdigit:]])$/){m=tolower($i);if(!(m in seen)){seen[m]=1;n++}}else bad=1}} END{if(bad||n>512)print "INVALID";else print n}'; }
authorized_total=0; authorized_observed=0
for index in 0 1 2; do
 iface=${STATE[wl${index}_ifname]:-}
 [[ $iface =~ ^(wl[0-2]|eth[0-9]{1,2})$ ]] || { printf 'RADIO index=%s iface_unproven=true\n' "$index"; continue; }
 for query in radio chanspec bssid; do
  value=$(vendor /usr/libexec/asus/vendor/usr/sbin/wl -i "$iface" "$query"); code=$?
  if [[ $code != 0 ]]; then printf 'RADIO index=%s query=%s unavailable=true rc=%s\n' "$index" "$query" "$code"; ((COMMAND_ERRORS+=1)); continue; fi
  if [[ $query == bssid ]]; then
   [[ $value =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || { printf 'RADIO index=%s bssid_suppressed_unexpected_shape=true\n' "$index"; ((COMMAND_ERRORS+=1)); continue; }
  else
   [[ $value =~ ^[a-zA-Z0-9xX[:space:]\(\)/:._+-]{1,128}$ && $value != *$'\n'* ]] || { printf 'RADIO index=%s query=%s suppressed_unexpected_shape=true\n' "$index" "$query"; ((COMMAND_ERRORS+=1)); continue; }
  fi
  printf 'RADIO index=%s iface=%s query=%s value=%s\n' "$index" "$iface" "$query" "$value"
 done
 for query in assoclist authe_sta_list autho_sta_list; do
  raw=$(vendor /usr/libexec/asus/vendor/usr/sbin/wl -i "$iface" "$query"); code=$?
  if [[ $code != 0 ]]; then printf 'CLIENT_AGGREGATE index=%s query=%s unavailable=true rc=%s\n' "$index" "$query" "$code"; ((COMMAND_ERRORS+=1)); continue; fi
  count=$(printf '%s\n' "$raw" | mac_count "$query"); unset raw
  if [[ ! $count =~ ^[0-9]+$ ]]; then printf 'CLIENT_AGGREGATE index=%s query=%s invalid_suppressed=true\n' "$index" "$query"; ((COMMAND_ERRORS+=1)); continue; fi
  printf 'CLIENT_AGGREGATE index=%s query=%s count=%s no_client_identifiers=true\n' "$index" "$query" "$count"
  if [[ $query == autho_sta_list ]]; then ((authorized_total+=count)); ((authorized_observed+=1)); fi
 done
done
if [[ $authorized_observed == 3 ]]; then
 printf 'WIFI_AUTHORIZED_CLIENTS total=%s observed_radios=3 point_sample_only=true\n' "$authorized_total"
 ((authorized_total>0)) || printf 'UNPROVEN_WIFI_ASSOCIATION=no_current_authorized_clients_observed\n'
elif ((authorized_observed>0)); then
 printf 'WIFI_AUTHORIZED_CLIENTS partial_total=%s observed_radios=%s total_unproven=true\n' "$authorized_total" "$authorized_observed"
else
 printf 'WIFI_AUTHORIZED_CLIENTS total=unavailable observed_radios=0\n'
fi
# Same-boot uplink was already physically used for both SSH paths. These are
# only the missing traffic counters and contemporaneous link/bridge context.
declare -A TRAFFIC=()
for phase in before after; do
 [[ $phase == after ]] && { ((SECONDS<57)) && /usr/bin/sleep 1 || { ((COMMAND_ERRORS+=1)); break; }; }
 for field in rx_bytes tx_bytes rx_packets tx_packets rx_errors tx_errors rx_dropped tx_dropped; do
  value=$(get /usr/bin/cat "/sys/class/net/eth0/statistics/$field")
  [[ $value =~ ^[0-9]{1,18}$ ]] || { printf 'TRAFFIC phase=%s field=%s unavailable=true\n' "$phase" "$field"; ((COMMAND_ERRORS+=1)); continue; }
  TRAFFIC[$phase,$field]=$value; printf 'TRAFFIC phase=%s field=%s value=%s\n' "$phase" "$field" "$value"
 done
done
for field in carrier speed operstate brport/state; do
 value=$(get /usr/bin/cat "/sys/class/net/eth0/$field"); [[ $value =~ ^[a-zA-Z0-9]{1,16}$ ]] && printf 'UPLINK eth0 field=%s value=%s\n' "$field" "$value" || { printf 'UPLINK eth0 field=%s unavailable=true\n' "$field"; ((COMMAND_ERRORS+=1)); }
done
value=$(get /usr/bin/readlink /sys/class/net/eth0/master); [[ $value == ../br0 ]] && printf 'UPLINK eth0 master=br0\n' || { printf 'UPLINK eth0 expected_bridge_missing=true\n'; ((FAILURES+=1)); }
# AI board internal state is out of scope; no login, container query or ICMP.
for field in carrier operstate; do value=$(get /usr/bin/cat "/sys/class/net/eth.ai/$field"); [[ $value =~ ^[a-zA-Z0-9]{1,16}$ ]] && printf 'AI_LINK eth.ai field=%s value=%s\n' "$field" "$value" || printf 'AI_LINK eth.ai field=%s unavailable=true\n' "$field"; done
neighbor=$(get /usr/bin/ip -o -4 neigh show to 192.168.100.39)
state=$(printf '%s\n' "$neighbor" | /usr/bin/awk 'NF && $1=="192.168.100.39" && $2=="dev" && ($3=="eth.ai"||$3=="br0") {print $3":"$NF}')
[[ $state =~ ^(eth.ai|br0):(REACHABLE|STALE|DELAY|PROBE|PERMANENT|FAILED|INCOMPLETE)$ ]] && printf 'AI_LINK known_peer=192.168.100.39 neighbor_device_state=%s no_peer_mac=true\n' "$state" || printf 'AI_LINK known_peer=192.168.100.39 neighbor_unproven=true\n'
# Read only advertised LED class values; without an enrolled color map do not
# call generic led_gpio_* channels red/green/blue or claim physical illumination.
led_count=0
for path in /sys/class/leds/*/brightness; do
 [[ -r $path ]] || continue; ((led_count+=1)); ((led_count<=16 && SECONDS<60)) || { printf 'UNPROVEN_RGB=led_enumeration_cap\n'; break; }
 name=${path%/brightness}; name=${name##*/}; value=$(get /usr/bin/cat "$path")
 [[ $name =~ ^[a-zA-Z0-9_:.-]{1,64}$ && $value =~ ^[0-9]{1,9}$ ]] && printf 'LED_DRIVER name=%s brightness=%s color_mapping_unproven=true\n' "$name" "$value" || printf 'LED_DRIVER value_unavailable=true\n'
done
ledg=0; scanned=0
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || { ((COMMAND_ERRORS+=1)); break; }; IFS= read -r -n 16 comm < "$proc/comm" 2>/dev/null || continue
 [[ $comm == ledg && $proc/exe -ef /usr/libexec/asus/rc ]] || continue
 pid=${proc##*/}; stat_identity "$pid" || continue; start=$ID_START
 [[ $(get /usr/bin/readlink "$proc/ns/mnt") == "$RC_NS" ]] || continue
 stat_identity "$pid" && [[ $ID_START == "$start" && $proc/exe -ef /usr/libexec/asus/rc ]] || continue
 ((ledg+=1)); printf 'RGB_PROCESS pid=%s patched_rc=true private_namespace=true\n' "$pid"
done
printf 'RGB_PROCESS count=%s physical_cycle_unproven=true\n' "$ledg"
# USB device descriptors only; no serial, manufacturer, product, content/mount.
usb_count=0
for path in /sys/bus/usb/devices/*/idVendor; do
 [[ -r $path ]] || continue; ((usb_count+=1)); ((usb_count<=32 && SECONDS<60)) || { printf 'UNPROVEN_USB=device_enumeration_cap\n'; break; }
 device=${path%/idVendor}; vendor_id=$(get /usr/bin/cat "$path"); product_id=$(get /usr/bin/cat "$device/idProduct"); class=$(get /usr/bin/cat "$device/bDeviceClass"); speed=$(get /usr/bin/cat "$device/speed")
 if [[ $vendor_id =~ ^[[:xdigit:]]{4}$ && $product_id =~ ^[[:xdigit:]]{4}$ && $class =~ ^[[:xdigit:]]{2}$ && $speed =~ ^[0-9.]{1,12}$ ]]; then printf 'USB_DESCRIPTOR vendor=%s product=%s class=%s speed=%s\n' "$vendor_id" "$product_id" "$class" "$speed"; else printf 'USB_DESCRIPTOR unavailable_or_suppressed=true\n'; fi
done
printf 'USB_DESCRIPTOR_COUNT count=%s roots_included=true application_mount_unproven=true\n' "$usb_count"
private_ok; check same_rc_lifetime_and_namespace_at_end "$?" 0
check same_boot_at_end "$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)" "$boot"
printf 'UNPROVEN=WiFi_new_join_roaming_per_SSID_data_path,AiMesh_controller_membership_and_selected_backhaul,all_physical_port_mapping_LACP_acceleration,physical_RGB_color_cycle,AI_application_or_containers,USB_application_mount_CAN,browser_authenticated_management_rendering_language_forms,settings_persistence_service_restart_orderly_shutdown,permanent_boot\n'
((SECONDS<60)) || { printf 'FUNCTIONAL_INCOMPLETE reason=internal_deadline\n'; ((COMMAND_ERRORS+=1)); }
printf 'FUNCTIONAL_END failures=%s command_errors=%s no_actions=true no_client_identifiers=true\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
