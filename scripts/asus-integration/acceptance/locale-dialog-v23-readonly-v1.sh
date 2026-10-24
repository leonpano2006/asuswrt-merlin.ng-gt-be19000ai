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
printf 'LOCALE_DIALOG_READONLY_BEGIN\n'
printf 'SESSION_ENV\n'
printenv | LC_ALL=C grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+|TERM|DEBIAN_FRONTEND)=' || :
printf 'LOCALE_CURRENT\n'
locale 2>&1 || :
printf 'AVAILABLE_LOCALES\n'
locale -a 2>&1 | head -80
printf 'PACKAGES\n'
LC_ALL=C dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' libc6 libc-bin locales locales-all dialog whiptail debconf ncurses-base ncurses-bin ncurses-term 2>&1 || :
printf 'FIXED_LOCALE_CONFIGS\n'
for f in /etc/default/locale /etc/locale.conf /etc/locale.gen; do
 printf 'FILE=%s\n' "$f"
 if test -f "$f"; then LC_ALL=C grep -Ev '^([[:space:]]*#|[[:space:]]*$)' "$f" | head -80 || :; else printf 'absent\n'; fi
done
printf 'C_UTF8_CHECK\n'
LC_ALL=C.UTF-8 locale charmap 2>&1 || :
printf 'EN_US_CHECK\n'
LC_ALL=en_US.UTF-8 locale charmap 2>&1 || :
printf 'ZH_TW_CHECK\n'
LC_ALL=zh_TW.UTF-8 locale charmap 2>&1 || :
printf 'TERMINFO_CHECK\n'
for t in xterm xterm-256color screen-256color tmux-256color; do
 if LC_ALL=C infocmp "$t" >/dev/null 2>&1; then printf '%s present\n' "$t"; else printf '%s missing\n' "$t"; fi
done
printf 'FREE_ROOT\n'
LC_ALL=C df -h /
printf 'LOCALE_DIALOG_READONLY_END\n'
