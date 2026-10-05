#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/usr/sbin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
boot=${1:?}
[[ $EUID == 0 && $boot =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ && $(cat /proc/sys/kernel/random/boot_id) == "$boot" && $(readlink /proc/1/exe) == /usr/lib/systemd/systemd && $(readlink /proc/self/ns/mnt) == "$(readlink /proc/1/ns/mnt)" ]] || exit 125
[[ $(findmnt -rn -o FSTYPE,MAJ:MIN,UUID,OPTIONS --mountpoint /) == 'ext4 179:11 ea8e47b8-c606-406c-b931-d2244d26ec55 rw,'* ]] || exit 125
client=/usr/libexec/leon-boot/trial-accept
[[ $(stat --format='%F %u %g %a %h' "$client") == 'regular file 0 0 755 1' ]] || exit 125
printf '%s  %s\n' 0ae4d35580e43297ba2a78978d12ce656aad8325ef2ad16d169d4525b7553fc3 "$client" | sha256sum -c -
printf '%s  %s\n' fb835e1fb8ea92504af809ecc9aee4ff0488f416c82d7f7ac5e6364266d6ba6e /mnt/leon-vendor-root/usr/libexec/leon-boot/trial-guardian | sha256sum -c -
prior=$("$client" --status --expected-boot-id "$boot")
printf '%s\n' "$prior"
[[ $prior == "LEON_ACCEPT_STATUS boot_id=$boot accepted_this_boot=0 metadata_committed=2" ]] || exit 125
# One explicit invocation. Its reviewed client performs only bounded EAGAIN retries.
"$client" --accept-this-boot --expected-boot-id "$boot"
status=$("$client" --status --expected-boot-id "$boot")
printf '%s\n' "$status"
[[ $status == "LEON_ACCEPT_STATUS boot_id=$boot accepted_this_boot=1 metadata_committed=2" && $(cat /proc/sys/kernel/random/boot_id) == "$boot" ]] || exit 125
printf 'CURRENT_BOOT_ACCEPT_END same_boot=true accepted_this_boot=true metadata_committed=2 permanent=false\n'
