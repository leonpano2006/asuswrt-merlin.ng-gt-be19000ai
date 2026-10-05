#!/bin/bash
# Native entry; joins only the verified direct ASUS rc child's mount namespace.
# Fixed read-only collectors; no stock overlays, NVRAM setters or power commands.
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
[[ $EUID == 0 && $# == 1 ]] || exit 125
case $1 in
 history) target=/usr/libexec/node-history/history.sh; digest=8e80168e546acf5bffe65e495ee83d2c13c872efa54f7801372cd1fd75314f2d;;
 ccr) target=/usr/libexec/ccr-status/collect.sh; digest=a787177b02f80429fbe2e79d23f269ca151c030680bafff2681f663951e48cf2;;
 *) exit 125;;
esac
[[ $(readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || exit 125
broker=$(timeout -k 1s 2s systemctl show leon-asus-broker.service -p MainPID --value)
[[ $broker =~ ^[1-9][0-9]*$ && /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]] || exit 125
identity() {
 local raw tail; local -a fields
 [[ $1 =~ ^[1-9][0-9]*$ ]] && [[ /proc/$1/exe -ef /usr/libexec/asus/rc ]] || return 1
 IFS= read -r -n 8192 raw < "/proc/$1/stat" || return 1
 [[ $raw == "$1 ("*") "* ]] || return 1
 tail=${raw##*) }; read -r -a fields <<< "$tail"
 [[ ${#fields[@]} -ge 20 && ${fields[1]} == "$broker" && ${fields[19]} =~ ^[0-9]+$ ]] || return 1
 start=${fields[19]}
}
rc=; matches=0; scanned=0
for proc in /proc/[0-9]*; do
 ((scanned+=1)); ((scanned<=512)) || exit 125
 if identity "${proc##*/}"; then rc=${proc##*/}; saved_start=$start; ((matches+=1)); fi
done
[[ $matches == 1 && -n $rc ]] || exit 125
[[ $(readlink "/proc/$rc/ns/mnt") != "$(readlink /proc/1/ns/mnt)" ]] || exit 125
actual=$(timeout -k 1s 2s sha256sum /usr/libexec/asus/rc)
[[ ${actual%% *} == ddd02bc669cc1760cdca577178d9b4d9d4cd57d5674081d0fc20d7c4808955c2 ]] || exit 125
actual=$(timeout -k 1s 2s sha256sum "$target"); [[ ${actual%% *} == "$digest" ]] || exit 125
marker="/proc/$rc/root/etc/.asus-private-etc"
[[ $(timeout -k 1s 2s stat '--format=%F %u %g %a %h' "$marker") == 'regular file 0 0 600 1' ]] || exit 125
actual=$(timeout -k 1s 2s sha256sum "$marker"); [[ ${actual%% *} == 1c205578ec70bd60cdc74beed8f3d0deef1f045780eac31b91148ed8b3c55bec ]] || exit 125
# Hold the actual namespace open before checking the rc lifetime again.
exec {nsfd}< "/proc/$rc/ns/mnt"
identity "$rc" && [[ $start == "$saved_start" ]] || exit 125
printf 'LEON_TELEMETRY_START role=%s private_rc=%s\n' "$1" "$rc"
exec /usr/bin/nsenter --mount="/proc/self/fd/$nsfd" -- /usr/bin/env -i PATH=/usr/bin:/usr/sbin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/ash "$target" run
