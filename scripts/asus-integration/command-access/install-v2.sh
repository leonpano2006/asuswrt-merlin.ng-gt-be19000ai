#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin LC_ALL=C.UTF-8
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
[ "$EUID" = 0 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008 ]
[ "$(findmnt -rn -o FSTYPE,UUID --mountpoint /)" = 'ext4 ea8e47b8-c606-406c-b931-d2244d26ec55' ]
for path in /usr/bin/asus /usr/bin/nvram /usr/sbin/wl /usr/sbin/ethctl /usr/sbin/rc /usr/sbin/asus-service; do
 [ ! -e "$path" ] && [ ! -L "$path" ]
done
incoming=${1:?uploaded Deb}
case "$incoming" in /var/tmp/leon-command-access.r730S2gi/package.deb) ;; *) exit 125;; esac
private=$(mktemp -d /var/tmp/leon-command-access.XXXXXXXX)
install -o root -g root -m 0644 "$incoming" "$private/package.deb"
printf '%s  %s\n' 6511224e34f77440bac1ca1c07220d36ec0dc0b0ff009022952fe6d27d4d6dd2 "$private/package.deb" | sha256sum -c -
sha256sum /usr/sbin/service /usr/bin/dash /usr/lib/systemd/systemd > "$private/native.sha256"
namespace=$(readlink /proc/self/ns/mnt)
DEBIAN_FRONTEND=noninteractive dpkg -i "$private/package.deb"
printf 'CLI_LIST\n'
/usr/bin/asus --list > "$private/commands.txt"
grep -xE 'nvram|wl|service|ethctl|rc \(broker control\)' "$private/commands.txt"
printf 'CLI_PRODUCT\n'; /usr/bin/nvram get productid
printf 'CLI_WIRELESS_VERSION\n'; /usr/sbin/wl -i wl0 ver
printf 'CLI_BROKER_PING\n'; /usr/sbin/rc ping
printf 'CLI_SERVICE_USAGE\n'
set +e
/usr/bin/asus service > "$private/service-usage.txt" 2>&1
code=$?
set -e
cat "$private/service-usage.txt"
printf 'SERVICE_USAGE_RC=%s\n' "$code"
grep -q 'action_service' "$private/service-usage.txt"
printf 'CLI_BLOCKED_POWER_ALIAS\n'
set +e
/usr/bin/asus reboot > "$private/blocked.txt" 2>&1
code=$?
set -e
[ "$code" = 125 ]
cat "$private/blocked.txt"
sha256sum -c "$private/native.sha256"
[ "$(readlink /proc/self/ns/mnt)" = "$namespace" ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008 ]
dpkg --audit > "$private/dpkg-audit.txt"
[ ! -s "$private/dpkg-audit.txt" ]
printf 'ASUS_COMMAND_ACCESS_INSTALLED same_boot=true native_files_unchanged=true no_service_actions=true\n'
