#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Bounded native-only evidence. Never dump NVRAM, config files or key material.
set +x
set -u -o pipefail
PATH=/usr/bin:/usr/sbin
export PATH
umask 077

capture() {
    local label=$1 result
    shift
    printf 'TRIAL_SNAPSHOT section=%s begin\n' "$label"
    /usr/bin/timeout --signal=TERM --kill-after=1s 2s "$@" 2>&1
    result=$?
    printf 'TRIAL_SNAPSHOT section=%s rc=%s end\n' "$label" "$result"
    return 0
}

printf 'TRIAL_SNAPSHOT_BEGIN schema=1\n'
capture boot /usr/bin/cat /proc/sys/kernel/random/boot_id /proc/uptime
capture bridge-address /usr/bin/ip -j address show dev br0
capture bridge-links /usr/bin/ip -j link show master br0
capture ipv4-routes /usr/bin/ip -j -4 route show
capture listeners /usr/bin/ss -lntp

properties=$(/usr/bin/timeout --signal=TERM --kill-after=1s 2s \
    /usr/bin/systemctl show ssh.service --no-pager \
    -p ActiveState -p SubState -p MainPID -p FragmentPath -p ExecStart 2>&1)
result=$?
printf 'TRIAL_SNAPSHOT section=ssh-unit rc=%s\n%s\n' "$result" "$properties"
pid=$(printf '%s\n' "$properties" | /usr/bin/awk -F= '$1=="MainPID" { print $2 }')
case "$pid" in
    ''|0|*[!0-9]*) printf 'TRIAL_SNAPSHOT ssh-master=unavailable\n' ;;
    *)
        executable=$(/usr/bin/readlink "/proc/$pid/exe" 2>/dev/null || true)
        printf 'TRIAL_SNAPSHOT ssh-master-pid=%s executable=%s\n' "$pid" "$executable"
        if [[ "$executable" == /usr/sbin/sshd ]]; then
            capture ssh-master-mount-namespace /usr/bin/readlink \
                /proc/1/ns/mnt "/proc/$pid/ns/mnt"
            capture ssh-master-cgroup /usr/bin/cat "/proc/$pid/cgroup"
            printf 'TRIAL_SNAPSHOT section=ssh-master-argv begin\n'
            /usr/bin/timeout --signal=TERM --kill-after=1s 2s \
                /usr/bin/cat "/proc/$pid/cmdline" 2>/dev/null | /usr/bin/tr '\0' ' '
            printf '\nTRIAL_SNAPSHOT section=ssh-master-argv end\n'
        fi
        ;;
esac

capture protected-config-metadata /usr/bin/stat -L \
    '--format=type=%F mode=%a uid=%u gid=%g size=%s' \
    /run/leon-asus-ssh/sshd_config
printf 'TRIAL_SNAPSHOT section=ssh-effective-policy begin\n'
/usr/bin/timeout --signal=TERM --kill-after=1s 2s \
    /usr/sbin/sshd -T -f /run/leon-asus-ssh/sshd_config \
    -C user=MastermixStudios,addr=192.168.100.35,host=local 2>/dev/null |
    /usr/bin/awk '$1=="port" || $1=="listenaddress" || $1=="allowusers" ||
        $1=="permitrootlogin" || $1=="passwordauthentication" ||
        $1=="pubkeyauthentication" || $1=="kbdinteractiveauthentication" ||
        $1=="usepam" || $1=="permitemptypasswords" ||
        $1=="allowtcpforwarding" || $1=="gatewayports" || $1=="permittunnel" ||
        $1=="x11forwarding" {print}'
result=$?
printf 'TRIAL_SNAPSHOT section=ssh-effective-policy rc=%s end\n' "$result"
printf 'TRIAL_SNAPSHOT_END schema=1\n'
exit 0
