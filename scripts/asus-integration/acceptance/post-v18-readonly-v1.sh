#!/bin/bash
# SOURCE ONLY. Root review and both physical logins must pass before use.
# Run in PID1 mount namespace under timeout -k1s 65s; no ACK or acceptance.
set +x
set -u -o pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
EXPECTED_BOOT=${1:?actual native boot UUID required}; FAILURES=0; COMMAND_ERRORS=0; SECONDS=0
check() { if [[ $2 == "$3" ]]; then printf 'CHECK %s PASS\n' "$1"; else printf 'CHECK %s FAIL\n' "$1"; ((FAILURES+=1)); fi; }
get() { ((SECONDS<60)) && /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" </dev/null 2>/dev/null | /usr/bin/head -c 8192; }
run() { local label=$1 code; shift; printf 'BEGIN %s\n' "$label"; get "$@"; code=$?; printf '\nEND %s rc=%s\n' "$label" "$code"; ((code==0)) || ((COMMAND_ERRORS+=1)); return 0; }
trap 'printf "READONLY_INCOMPLETE reason=signal\n"; exit 143' TERM INT HUP
boot=$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)
[[ $EUID == 0 && $EXPECTED_BOOT =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $boot == "$EXPECTED_BOOT" && $boot != 00000000-0000-4000-8000-000000000032 ]] || { printf 'REFUSED uid_or_boot\n'; exit 125; }
hostns=$(get /usr/bin/readlink /proc/1/ns/mnt)
[[ $(get /usr/bin/readlink /proc/self/ns/mnt) == "$hostns" && $(get /usr/bin/readlink /proc/1/exe) == /usr/lib/systemd/systemd ]] || { printf 'REFUSED native_namespace_or_pid1\n'; exit 125; }
printf 'READONLY_BEGIN revision=v18 scope=bounded_point_snapshot no_ack=true no_accept=true\n'
check kernel_release "$(get /usr/bin/uname -r)" 4.19.294
root=$(get /usr/bin/findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /)
check native_root_rw "$([[ $root == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] && printf 1 || printf 0)" 1
versions=$(get /usr/bin/dpkg-query -W '-f=${binary:Package} ${Version}\n' systemd libc6:arm64); printf '%s\n' "$versions"
check native_versions "$([[ $versions == *'systemd 259.5-0ubuntu3.4+leonb53.2'* && $versions == *'libc6:arm64 2.44-1ubuntu1+leonb53.1'* ]] && printf 1 || printf 0)" 1
while read -r hash path; do value=$(get /usr/bin/sha256sum "$path"); check "hash_${path##*/}" "${value%% *}" "$hash"; done <<'HASHES'
ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 /usr/libexec/asus/rc
69994d0dbaf4db84c3ea9207ec3d03ff27a3c2d05edaf2571a23f30a76b9c6d7 /usr/libexec/asus/startup-prepare
bc4a5a7cdc368dafebd0ac172abed57bd3352436def9303bba656ed6f7a3a590 /usr/libexec/leon-asus/rescue-link
9ef57c1e25b49471e581e35994603fd7ac8b8096d0862f9e7cc0dcc9012df80a /usr/libexec/asus/ash
7ea7de4161b9b5e7ee27c3e7933467ce2bdb1b9374599b4c1953cfad87652e2f /usr/libexec/asus/vendor/bin/nvram
049cec36c1954fec8bb23b74cf8d525304fa23b38938f183e0f2b362d33f1ca1 /usr/libexec/asus/vendor/usr/sbin/wl
c85a35269e1126610a289f4610b6cae1fab4b94d2ab63fb96f15385567c18143 /usr/libexec/asus/vendor/usr/sbin/lldpd
HASHES
((FAILURES==0)) || { printf 'REFUSED native_identity_or_artifact_hash\n'; exit 125; }
run units /usr/bin/systemctl show --no-pager -p Id -p ActiveState -p SubState -p Result -p MainPID -p ExecMainStatus leon-asus-prepare.service leon-asus-broker.service leon-asus-rescue-link.service leon-asus-ssh-uplink-rescue.socket ssh.service docker.service docker.socket
check broker_active "$(get /usr/bin/systemctl is-active leon-asus-broker.service)" active
check prepare_success "$(get /usr/bin/systemctl show leon-asus-prepare.service -p Result --value)" success
stages=$(get /usr/bin/journalctl -b -u leon-asus-prepare.service -o cat --no-pager | /usr/bin/awk '/^ASUS_NATIVE_PREPARE stage=(overlay-module|native-device-nodes|udev-reload|udev-alias-refresh-scoped|storage-owner) status=/{print}')
printf '%s\n' "$stages"
for stage in overlay-module native-device-nodes udev-reload udev-alias-refresh-scoped storage-owner; do check "prepare_$stage" "$([[ $stages == *"stage=$stage status=0"* ]] && printf 1 || printf 0)" 1; done
broker=$(get /usr/bin/systemctl show leon-asus-broker.service -p MainPID --value); RC=; matches=0; scanned=0
stat_identity() { local raw tail; local -a fields=(); ID_START= ID_PARENT=; [[ $1 =~ ^[1-9][0-9]*$ ]] || return 1; IFS= read -r -n 8192 raw 2>/dev/null < "/proc/$1/stat" || return 1; [[ $raw == "$1 ("*") "* ]] || return 1; tail=${raw##*) }; read -r -a fields <<< "$tail"; [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[0-9]+$ && ${fields[1]} =~ ^[0-9]+$ ]] || return 1; ID_START=${fields[19]}; ID_PARENT=${fields[1]}; }
rc_identity() { [[ /proc/$1/exe -ef /usr/libexec/asus/rc ]] && stat_identity "$1"; }
if [[ $broker =~ ^[1-9][0-9]*$ && $(get /usr/bin/readlink "/proc/$broker/exe") == /usr/libexec/asus/rc-broker ]]; then
 for proc in /proc/[0-9]*; do ((scanned+=1)); ((scanned<=512 && SECONDS<60)) || break; if rc_identity "${proc##*/}" && [[ $ID_PARENT == "$broker" ]]; then RC=${proc##*/}; ((matches+=1)); fi; done
fi
check unique_direct_rc "$matches" 1
((scanned<=512 && SECONDS<60)) || { printf 'REFUSED rc_scan_incomplete\n'; exit 125; }
if [[ $matches != 1 ]]; then printf 'REFUSED vendor_reads_without_unique_rc\n'; exit 125; fi
rc_identity "$RC" || exit 125; RC_START=$ID_START; RC_NS=$(get /usr/bin/readlink "/proc/$RC/ns/mnt")
[[ -n $RC_NS && $RC_NS != "$hostns" ]] || { printf 'REFUSED no_private_rc_namespace\n'; exit 125; }
private_ok() { rc_identity "$RC" && [[ $ID_START == "$RC_START" && $ID_PARENT == "$broker" && $(get /usr/bin/readlink "/proc/$RC/ns/mnt") == "$RC_NS" ]]; }
check private_sh "$(get /usr/bin/readlink "/proc/$RC/root/usr/bin/sh")" /usr/libexec/asus/ash
marker="/proc/$RC/root/etc/.asus-private-etc"; [[ $(get /usr/bin/stat '--format=%F %u %g %a %h' "$marker") == 'regular file 0 0 600 1' && ! /proc/$RC/root/etc -ef /etc ]] || { printf 'REFUSED private_etc_metadata\n'; exit 125; }
value=$(get /usr/bin/sha256sum "$marker"); check private_etc_marker "${value%% *}" 1c205578ec70bd60cdc74beed8f3d0deef1f045780eac31b91148ed8b3c55bec
check nvram_alias "$(get /usr/bin/readlink /usr/libexec/asus/collector-tools/nvram)" ../vendor/bin/nvram
check wl_alias "$(get /usr/bin/readlink /usr/libexec/asus/collector-tools/wl)" ../vendor/usr/sbin/wl
((FAILURES==0)) || { printf 'REFUSED private_vendor_projection\n'; exit 125; }
check eth0_master "$(get /usr/bin/readlink /sys/class/net/eth0/master)" ../br0
check eth0_speed "$(get /usr/bin/cat /sys/class/net/eth0/speed)" 10000
check eth0_carrier "$(get /usr/bin/cat /sys/class/net/eth0/carrier)" 1
check eth0_forwarding "$(get /usr/bin/cat /sys/class/net/eth0/brport/state)" 3
addresses=$(get /usr/bin/ip -o -4 address show dev br0); printf '%s\n' "$addresses"
check primary_ipv4 "$([[ $addresses == *'inet 192.168.100.15/24 '* ]] && printf 1 || printf 0)" 1
alias=$(printf '%s\n' "$addresses" | /usr/bin/awk '$4=="169.254.190.15/32" {print}')
check rescue_alias "$([[ -n $alias && $alias != *$'\n'* && $alias == *'scope link'* && $alias == *'noprefixroute'* && $alias == *'br0:lr'* ]] && printf 1 || printf 0)" 1
default=$(get /usr/bin/ip -o -4 route show default); printf '%s\n' "$default"
check default_ccr "$([[ $default == 'default via 192.168.100.1 dev br0 '* || $default == 'default via 192.168.100.1 dev br0' ]] && printf 1 || printf 0)" 1
peer=$(get /usr/bin/ip -o -4 route show table main exact 169.254.190.51/32); printf '%s\n' "$peer"
check rescue_peer_route "$([[ $peer == '169.254.190.51 dev br0 '* && $peer == *'scope link'* && $peer == *'src 169.254.190.15'* && $peer == *'metric 42760'* ]] && printf 1 || printf 0)" 1
check rescue_active "$(get /usr/bin/systemctl is-active leon-asus-rescue-link.service)" active
check rescue_socket_active "$(get /usr/bin/systemctl is-active leon-asus-ssh-uplink-rescue.socket)" active
run listeners /usr/bin/ss -H -lnt '( sport = :22 or sport = :80 or sport = :443 or sport = :2223 )'
# No SSID, PSK, credential, client list or arbitrary key is ever queried/emitted.
for key in wl0_radio wl1_radio wl2_radio wl0_auth_mode_x wl1_auth_mode_x wl2_auth_mode_x ledg_led_enable ledg_scheme ai_app_prog_status; do
 private_ok || break
 value=$(/usr/bin/timeout --signal=TERM --kill-after=1s 2s /usr/bin/nsenter -t "$RC" -m -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/nvram get "$key" </dev/null 2>/dev/null | /usr/bin/head -c 64); nvrc=$?; ((nvrc==0)) || ((COMMAND_ERRORS+=1))
 private_ok || { printf 'DISCARDED vendor_values_rc_raced\n'; break; }; [[ $value =~ ^[a-zA-Z0-9_-]{0,63}$ ]] && printf 'PUBLIC_STATE %s=%s rc=%s\n' "$key" "$value" "$nvrc" || printf 'PUBLIC_STATE %s=unexpected_suppressed rc=%s\n' "$key" "$nvrc"
done
for iface in wl0 wl1 wl2; do run "${iface}_link" /usr/bin/ip -brief link show dev "$iface"; for query in radio chanspec; do private_ok && run "${iface}_$query" /usr/bin/nsenter -t "$RC" -m -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/collector-tools/wl -i "$iface" "$query"; done; done
matched=0; scanned=0; aimesh=0; lldp=0
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512 && matched<16 && SECONDS<60)) || break; IFS= read -r -n 16 comm < "$proc/comm" 2>/dev/null || continue
 case $comm in amas_bhctrl|amas_status|amas_lanctrl|amas_misc|amas_wlcconnect|ledg) expected=/usr/libexec/asus/rc;; lldpd) expected=/usr/libexec/asus/vendor/usr/sbin/lldpd;; httpd) expected=/usr/libexec/asus/vendor/usr/sbin/httpd;; *) continue;; esac
 pid=${proc##*/}; stat_identity "$pid" || continue; start=$ID_START; exe=$(get /usr/bin/readlink "$proc/exe"); [[ $exe == "$expected" ]] || continue
 stat_identity "$pid" && [[ $ID_START == "$start" && $(get /usr/bin/readlink "$proc/exe") == "$expected" && $(get /usr/bin/head -c 16 "$proc/comm") == "$comm" ]] || continue; ((matched+=1)); case $comm in amas_*) ((aimesh+=1));; lldpd) ((lldp+=1));; esac; printf 'PROCESS pid=%s comm=%s canonical_exe=%s\n' "$pid" "$comm" "$expected"
done
printf 'PROCESS_SCOPE matched=%s scanned=%s cap=16 point_sample_only=true\n' "$matched" "$scanned"
check genuine_aimesh_observed "$((aimesh>0))" 1; check genuine_lldpd_observed "$((lldp>0))" 1
run ai_mount /usr/bin/findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS,UUID --mountpoint /ai
run ai_interface /usr/bin/ip -brief link show dev eth.ai
run panel_and_collector_metadata /usr/bin/stat -L '--format=%n type=%F bytes=%s mtime=%Y uid=%u mode=%a' "/proc/$RC/root/www/pages/aiboard.html" "/proc/$RC/root/tmp/.diag/node_stats.db" "/proc/$RC/root/tmp/.diag/ccr_status.db"
count=0; for led in /sys/class/leds/*/brightness; do [[ -r $led ]] || continue; ((count+=1)); ((count<=8)) || break; run "led_brightness_$count" /usr/bin/head -c 16 "$led"; done
private_ok; check rc_identity_at_end "$?" 0
check same_boot_at_end "$(get /usr/bin/cat /proc/sys/kernel/random/boot_id)" "$boot"
printf 'UNPROVEN=client_HTTP_TLS_terms,WiFi_client_auth_roaming,physical_RGB,collector_rows_freshness,AI_container_operation,USB_CAN,SL_application_state;kernel10_provenance_reused;root_rw_flag_only\n'
((SECONDS<60)) || { printf 'READONLY_INCOMPLETE reason=internal_deadline\n'; ((COMMAND_ERRORS+=1)); }
printf 'READONLY_END failures=%s command_errors=%s SL_accounts_containers_unmodified_by_this_script=true\n' "$FAILURES" "$COMMAND_ERRORS"
[[ $FAILURES == 0 && $COMMAND_ERRORS == 0 ]]
