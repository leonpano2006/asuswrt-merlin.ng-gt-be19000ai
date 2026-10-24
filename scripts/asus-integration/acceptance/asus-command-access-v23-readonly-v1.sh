#!/bin/bash
set -eu
printf 'BOOT='; cat /proc/sys/kernel/random/boot_id
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008 ]
export PATH=/usr/sbin:/usr/bin LC_ALL=C.UTF-8
printf 'LOCALES_ALL_STATUS\n'; dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev} ${Version}\n' locales locales-all 2>&1 || :
printf 'NATIVE_LOOKUP\n'
for name in nvram wl ethctl robocfg service rc rcctl asus asus-shell; do
 printf '%s: ' "$name"; command -v "$name" || :
done
printf 'VENDOR_ELF_READ_NATIVE\n'
/usr/bin/timeout -k 1s 3s /usr/libexec/asus/vendor/bin/nvram get productid 2>&1 || :
broker=$(systemctl show leon-asus-broker.service -p MainPID --value)
[ -n "$broker" ] && [ /proc/$broker/exe -ef /usr/libexec/asus/rc-broker ]
rc=; count=0
for path in /proc/[0-9]*; do
 p=${path##*/}
 if [ /proc/$p/exe -ef /usr/libexec/asus/rc ]; then
  parent=$(awk '/^PPid:/{print $2}' /proc/$p/status)
  if [ "$parent" = "$broker" ]; then rc=$p; count=$((count+1)); fi
 fi
done
[ "$count" = 1 ]
exec {nsfd}< /proc/$rc/ns/mnt
printf 'PRIVATE_LOOKUP\n'
/usr/bin/nsenter --mount=/proc/self/fd/$nsfd -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/ash -c 'for name in nvram wl ethctl robocfg service rc rcctl; do printf "%s: " "$name"; command -v "$name" || :; done'
printf 'PRIVATE_READ\n'
/usr/bin/timeout -k 1s 3s /usr/bin/nsenter --mount=/proc/self/fd/$nsfd -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/vendor/bin/nvram get productid
/usr/bin/timeout -k 1s 3s /usr/bin/nsenter --mount=/proc/self/fd/$nsfd -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C 'LD_LIBRARY_PATH=/usr/$LIB/asus' /usr/libexec/asus/vendor/usr/sbin/wl -i wl0 ver
printf 'ASUS_COMMAND_DIAG_END\n'
