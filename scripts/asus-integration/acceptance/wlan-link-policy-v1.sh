#!/bin/bash
# One local native udev policy-selection fixture. All devices are netns dummies.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV
root=${1:?fixed native root}
evidence=${2:?new evidence directory}
policies=${3:?fixture policy directory}
if [[ ${4:-} != inner ]]; then
    printf 'PHASE=private-mount-namespace\n'
    mount --make-rprivate /
    original_net=$(readlink /proc/self/ns/net)
    exec unshare --net --uts /bin/bash "$0" "$root" "$evidence" "$policies" inner "$original_net"
fi
[[ $(readlink /proc/self/ns/net) != "${5:?original network namespace}" ]]
printf 'PHASE=isolated-network-namespace\n'
# sysfs must be mounted after NEWNET, so /sys/class/net shows only this fixture.
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$root/sys"
mount -t proc -o nosuid,nodev,noexec proc "$root/proc"
mount --bind "$policies" "$root/usr/lib/systemd/network"
mount -o remount,bind,ro "$root/usr/lib/systemd/network"
chroot "$root" /usr/bin/udevadm --version > "$evidence/udev-version.txt"
[[ $(head -n1 "$evidence/udev-version.txt") == 259* ]]
printf 'PHASE=native-udev259-fixture\n'
for name in wl0 wl1 wl2 unrelated0; do
    chroot "$root" /usr/bin/ip link add "$name" type dummy
    before=$(cat "$root/sys/class/net/$name/address")
    chroot "$root" /usr/bin/udevadm test-builtin --action=add net_setup_link "/sys/class/net/$name" > "$evidence/$name.log" 2>&1
    if [[ $name == unrelated0 ]]; then
        expected=/usr/lib/systemd/network/99-default.link
    else
        expected=/usr/lib/systemd/network/10-leon-asus-wlan-v1.link
    fi
    grep -Fx "ID_NET_LINK_FILE=$expected" "$evidence/$name.log"
    proposed=$(sed -n 's/^ID_NET_NAME=//p' "$evidence/$name.log")
    if [[ $name != unrelated0 ]]; then [[ -z $proposed || $proposed == "$name" ]]; fi
    [[ -e "$root/sys/class/net/$name" ]]
    after=$(cat "$root/sys/class/net/$name/address")
    if [[ $name != unrelated0 ]]; then [[ $before == "$after" ]]; fi
    printf 'PASS name=%s link=%s rename_proposal=%s matched_name_present=true mac_unchanged=%s\n' "$name" "$expected" "${proposed:-absent}" "$([[ $before == "$after" ]] && printf true || printf false)"
done
printf 'PASS four-policy-selection-cases\n'
