#!/bin/bash
# Add terminal/locale support to the verified native Ubuntu root; no services.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
test "$EUID" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008
test "$(readlink /proc/1/exe)" = /usr/lib/systemd/systemd
test "$(findmnt -rn -o FSTYPE,UUID --mountpoint /)" = 'ext4 ea8e47b8-c606-406c-b931-d2244d26ec55'
for p in libc6:arm64 libc6:armel libc-bin; do
 test "$(dpkg-query -W -f='${Version}' "$p")" = '2.44-1ubuntu1+leonb53.1'
done
incoming=${1:?uploaded locales Deb}
case "$incoming" in /tmp/leon-terminal-*/locales.deb) ;; *) exit 125;; esac
test -f "$incoming" && test ! -L "$incoming"
private=$(mktemp -d /var/tmp/leon-terminal.XXXXXXXX)
install -o root -g root -m 0644 "$incoming" "$private/locales.deb"
printf '%s  %s\n' 040c83d8aa85e1cb459050a17d529365a40ecb0a1d8d8f15a13e120ba140f8a0 "$private/locales.deb" | sha256sum -c -
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
packages=(dialog=1.3-20260107-1 libdialog15=1.3-20260107-1 "$private/locales.deb")
apt-get -s --no-install-recommends --no-remove --no-upgrade install "${packages[@]}" > "$private/apt-plan.txt"
cat "$private/apt-plan.txt"
awk '/^Inst / { if ($2 != "dialog" && $2 != "libdialog15" && $2 != "locales") bad=1; n++ } END {exit(bad || n!=3)}' "$private/apt-plan.txt"
apt-get -y --no-install-recommends --no-remove --no-upgrade install "${packages[@]}"
locale-gen --keep-existing en_US.UTF-8 zh_TW.UTF-8
update-locale --locale-file /etc/locale.conf LANG=C.UTF-8
test /etc/default/locale -ef /etc/locale.conf
for loc in C.UTF-8 en_US.UTF-8 zh_TW.UTF-8; do
 value=$(LC_ALL="$loc" locale charmap 2> "$private/locale-error.txt")
 test "$value" = UTF-8 && test ! -s "$private/locale-error.txt"
 printf 'UTF8_PASS %s\n' "$loc"
done
for p in libc6:arm64 libc6:armel libc-bin; do
 test "$(dpkg-query -W -f='${Version}' "$p")" = '2.44-1ubuntu1+leonb53.1'
done
dpkg --audit > "$private/dpkg-audit.txt"
test ! -s "$private/dpkg-audit.txt"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' dialog libdialog15 locales
locale -a
test "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008
printf 'TERMINAL_SUPPORT_INSTALLED no_service_actions=true same_boot=true libc_unchanged=true\n'
