#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
[[ $EUID == 0 && ${1:?} =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $(cat /proc/sys/kernel/random/boot_id) == "$1" && $(readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || exit 125
[[ $(findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /) == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* && $(dpkg --print-architecture) == arm64 ]] || exit 125
pkg=${2:?}; dir=${pkg%/*}
[[ $pkg =~ ^/tmp/leon-accept-v22\.[A-Za-z0-9]{6}/payload\.deb$ && $(stat --format='%F %u %g %a %h' "$pkg") == 'regular file 1000 1000 600 1' && $(stat --format='%F %u %g %a' "$dir") == 'directory 1000 1000 700' ]] || exit 125
if dpkg-query -W -f='${Status}' leon-asus-current-boot-accept >/dev/null 2>&1; then exit 125; fi
# The native login owns the upload; root installs only its separate immutable copy.
umask 077
private=$(mktemp -d /run/leon-accept-client-v22.XXXXXX)
[[ $private =~ ^/run/leon-accept-client-v22\.[A-Za-z0-9]{6}$ && $(stat --format='%F %u %g %a' "$private") == 'directory 0 0 700' ]] || exit 125
rootpkg=$private/payload.deb
cp --no-preserve=all -- "$pkg" "$rootpkg"
[[ $(stat --format='%F %u %g %a %h %s' "$rootpkg") == 'regular file 0 0 600 1 342738' ]] || exit 125
printf '%s  %s\n' 4f96df1032387a12ce1cf8a428545d1f36320969f7f8d9bb32af37e9914f6b26 "$rootpkg" | sha256sum -c -
timeout -k 2s 30s dpkg --no-triggers --install "$rootpkg" </dev/null
rm -- "$rootpkg"
rmdir -- "$private"
printf '%s  %s\n' 0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3 /usr/libexec/leon-boot/trial-accept | sha256sum -c -
[[ $(stat --format='%F %u %g %a %h' /usr/libexec/leon-boot/trial-accept) == 'regular file 0 0 755 1' ]] || exit 125
printf 'PACKAGE='; dpkg-query -W -f='${Status} ${Version}\n' leon-asus-current-boot-accept
[[ $(cat /proc/sys/kernel/random/boot_id) == "$1" ]] || exit 125
printf 'ACCEPT_CLIENT_INSTALL_END same_boot=true package_configured=true no_acceptance=true no_services_changed=true\n'
