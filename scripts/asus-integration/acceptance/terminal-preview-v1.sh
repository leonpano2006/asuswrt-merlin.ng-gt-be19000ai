#!/bin/bash
set -eu
export PATH=/usr/bin:/usr/sbin
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
boot=$(cat /proc/sys/kernel/random/boot_id)
pid1=$(cat /proc/1/comm)
root=$(findmnt -rn -o FSTYPE,UUID --mountpoint /)
printf 'CONTEXT boot=%s pid1=%s root=%s\n' "$boot" "$pid1" "$root"
test "$boot" = 00000000-0000-4000-8000-000000000008
test "$pid1" = systemd
test "$root" = 'ext4 ea8e47b8-c606-406c-b931-d2244d26ec55'

printf 'DIALOG_APT_PREVIEW\n'
LC_ALL=C apt-get -s --no-install-recommends --no-remove install dialog 2>&1
printf 'SSH_LOCALE_CONFIGURATION\n'
LC_ALL=C grep -hE '^[[:space:]]*(UsePAM|AcceptEnv|SendEnv)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || :
LC_ALL=C grep -n 'pam_env\|locale' /etc/pam.d/sshd /etc/profile /etc/bash.bashrc 2>/dev/null || :
printf 'LOCALE_DIALOG_READONLY_END\n'
