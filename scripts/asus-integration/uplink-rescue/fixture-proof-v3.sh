#!/bin/bash
# One new no-NIC Kernel10 case, not the previous recovery/rootfs suite.
set -Eeuo pipefail
exec >/dev/console 2>&1
lab=/usr/libexec/leon-lab/uplink-rescue
run=/run/leon-uplink-rescue-fixture
stage=entry
trap 'echo UPLINK_RESCUE_FIXTURE_ERR line=$LINENO command="$BASH_COMMAND" stage=$stage' ERR
trap 'rc=$?; echo UPLINK_RESCUE_FIXTURE_EXIT=$rc stage=$stage; if test "$rc" != 0; then journalctl -u leon-asus-rescue-link.service -u leon-asus-ssh-uplink-rescue.socket -u "leon-asus-ssh-uplink-rescue@*" -n 35 --no-pager || :; ip -d -N -4 rule show || :; ip -d -N -4 address show || :; cat "$run/controller-setup.log" 2>/dev/null || :; fi' EXIT
stage=entry-marker
test -f /QEMU_LAB_GUEST
stage=entry-pid1
pid1_comm=$(cat /proc/1/comm)
printf 'UPLINK_RESCUE_ENTRY_PID1=%s\n' "$pid1_comm"
test "$pid1_comm" = systemd
stage=entry-no-hardware
for link in /sys/class/net/*; do test ! -e "$link/device"; done
stage=entry-netdev-inventory
netdev_names=$(ls /sys/class/net)
printf 'UPLINK_RESCUE_ENTRY_NETDEV_NAMES=%q\n' "$netdev_names"
# Kernel10 creates these virtual interfaces without any QEMU network card.
# Retain a closed allowlist; do not accept unobserved or fixture-owned names.
test -e /sys/class/net/lo
for link in /sys/class/net/*; do
    case "${link##*/}" in
        blogtcp_local|dummy0|erspan0|gre0|gretap0|ifb0|ifb1|imq0|imq1|imq2|ip6_vti0|ip6gre0|ip6tnl0|ip_vti0|lo|sit0) ;;
        *) echo "UPLINK_RESCUE_UNEXPECTED_INITIAL_LINK=${link##*/}"; exit 1 ;;
    esac
done
stage=entry-no-fixture-collisions
for name in eth0 br0 control-wire eth.ai-10; do test ! -e "/sys/class/net/$name"; done
test ! -e /run/netns/uplink-controller
stage=entry-no-global-ipv4
test -z "$(ip -o -4 address show scope global)"
stage=entry-no-default
ip -N -4 route show default
test -z "$(ip -4 route show default)"
stage=entry-synthetic-account
fixture_uid=$(id -u MastermixStudios)
printf 'UPLINK_RESCUE_ENTRY_UID=%s\n' "$fixture_uid"
test "$fixture_uid" = 2000
stage=entry-runtime-directory
mkdir -m0700 "$run"
stage=entry-preserved-account-hashes
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config > "$run/account-before"
stage=entry-stop-other-ssh
systemctl stop ssh.service ssh.socket leon-asus-ssh-recovery.socket
stage=entry-mask-vendor-ssh
systemctl mask --now leon-asus-ssh.socket
stage=entry-no-vendor-processes
test -z "$(pgrep -x rc-broker || :)"
test -z "$(pgrep -x rc || :)"
stage=entry-sshd-directory
install -d -m0755 /run/sshd
stage=entry-daemon-reload
systemctl daemon-reload

stage=first-kernel-snapshot
systemctl start --no-block leon-asus-rescue-link.service
sleep 0.5
# Fail immediately on actual netlink/parser incompatibility; do not run on.
test "$(systemctl show -p ActiveState --value leon-asus-rescue-link.service)" = activating
test ! -e /run/leon-asus-rescue-link/state
echo UPLINK_RESCUE_MISSING_UPLINK_ZERO_MUTATIONS_PASS

stage=isolated-links
ip netns add uplink-controller
ip link add eth0 type veth peer name control-wire
ip link set eth0 address 02:00:00:f0:00:01
ip link set control-wire netns uplink-controller
ip -n uplink-controller link add br-lan type bridge
ip -n uplink-controller link set br-lan address 02:00:00:f0:00:02
ip -n uplink-controller address add 192.168.100.51/24 dev br-lan
ip -n uplink-controller link set control-wire master br-lan
ip -n uplink-controller link set control-wire up
ip -n uplink-controller link set br-lan up
ip -n uplink-controller link set lo up
ip -n uplink-controller route add default via 192.168.100.1 dev br-lan
for name in all br-lan; do
    ip netns exec uplink-controller sysctl -qw "net.ipv4.conf.$name.arp_ignore=1"
done
ip link set eth0 up
ip link set lo up
# Unrelated AI route is part of the preservation check, never helper-owned.
ip link add eth.ai-10 type dummy
ip link set eth.ai-10 up
ip address add 169.254.0.1/32 dev eth.ai-10
ip route add 169.254.0.2/32 dev eth.ai-10
ip -N -4 route show 169.254.0.2/32 > "$run/ai-route-before"
ip netns exec uplink-controller unshare --mount --pid --fork --mount-proc /bin/bash "$lab/controller-init.sh" &
controller_pid=$!
wait_file() { for i in $(seq 1 100); do test ! -e "$1" || return 0; sleep 0.1; done; return 1; }
wait_file "$run/controller-configured"
systemctl start leon-asus-ssh-uplink-rescue.socket
systemctl is-active --quiet leon-asus-rescue-link.service
ip -o -4 address show dev eth0 | grep -q '169.254.190.15/32.*eth0:lr'
local_route() {
    ip -N -4 route show table local 169.254.190.15/32 | awk -v dev="$1" '
      NR==1 {ok=(NF==10 && $1=="local" && ($2=="169.254.190.15"||$2=="169.254.190.15/32") && $3=="dev" && $4==dev && $5=="proto" && $6=="2" && $7=="scope" && $8=="254" && $9=="src" && $10=="169.254.190.15")} END{exit(NR!=1||!ok)}'
}
local_route eth0
echo UPLINK_RESCUE_DETACHED_ETH0_READY_CONTROLLER_PASS

awk '{print "[169.254.190.15]:2223 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > "$run/known_hosts"
opts=(-F /dev/null -T -p 2223 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ConnectTimeout=3)
login() { timeout -s KILL 8 ip netns exec uplink-controller ssh "${opts[@]}" -b 169.254.190.51 -i /usr/libexec/leon-lab/recovery/client-key MastermixStudios@169.254.190.15 "$@"; }
stage=actual-key-only-login
test "$(login id -u)" = 2000
if timeout -s KILL 8 ip netns exec uplink-controller ssh "${opts[@]}" -b 169.254.190.51 -i /usr/libexec/leon-lab/recovery/denied-key MastermixStudios@169.254.190.15 true > "$run/wrong-key" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$run/wrong-key"
ip -n uplink-controller address add 169.254.190.52/32 dev br-lan
# Fixture-only reverse route lets the wrong source reach PAM/AllowUsers.
ip route add 169.254.190.52/32 dev eth0 src 169.254.190.15
if timeout -s KILL 8 ip netns exec uplink-controller ssh "${opts[@]}" -b 169.254.190.52 -i /usr/libexec/leon-lab/recovery/client-key MastermixStudios@169.254.190.15 true > "$run/wrong-peer" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$run/wrong-peer"
ip -n uplink-controller address del 169.254.190.52/32 dev br-lan
ip route del 169.254.190.52/32 dev eth0 src 169.254.190.15
echo UPLINK_RESCUE_NATIVE_PAM_LOGIN_WRONG_KEY_PEER_REJECT_PASS

stage=master-transition
ip link add br0 type bridge
ip link set br0 address 02:00:00:f0:00:01
ip address add 192.168.100.15/24 dev br0
ip link set br0 up
ip link set eth0 master br0
wait_label() { for i in $(seq 1 60); do if ip -o -4 address show dev "$1" | grep -q "169.254.190.15/32.*$1:lr" && local_route "$1" && ip -N -4 route show 169.254.190.51/32 | grep -q "dev $1 .*proto 186.*scope 253.*src 169.254.190.15.*metric 42760"; then return; fi; sleep 0.1; done; return 1; }
wait_label br0
test -z "$(ip -o -4 address show dev eth0)"
test "$(login id -u)" = 2000
# Normal ASUS/DHCP update is a fixture action, not a helper mutation.
ip address del 192.168.100.15/24 dev br0
ip address add 192.168.100.16/24 dev br0
sleep 1.2
systemctl is-active --quiet leon-asus-rescue-link.service
test "$(login id -u)" = 2000
ip link set eth0 nomaster
wait_label eth0
test "$(login id -u)" = 2000
echo UPLINK_RESCUE_MASTER_RECONNECT_NORMAL_ADDRESS_UPDATE_PASS

stage=exact-cleanup
systemctl stop leon-asus-rescue-link.service
test -z "$(ip -o -4 address show | grep '169.254.190.15/' || :)"
test -z "$(ip -4 route show 169.254.190.51/32)"
touch "$run/controller-cleanup"
wait_file "$run/controller-cleaned"
wait "$controller_pid"
ip -n uplink-controller -o -4 address show dev br-lan | grep -q '192.168.100.51/24'
test -z "$(ip -n uplink-controller -o -4 address show | grep '169.254.190.51/' || :)"
test -z "$(ip -n uplink-controller -4 route show 169.254.190.15/32)"
ip -n uplink-controller -4 route show default | awk 'NR==1 {ok=($1=="default"&&$2=="via"&&$3=="192.168.100.1"&&$4=="dev"&&$5=="br-lan")} END{exit(NR!=1||!ok)}'
ip -o -4 address show dev br0 | grep -q '192.168.100.16/24'
ip -N -4 route show 169.254.0.2/32 > "$run/ai-route-after"
cmp "$run/ai-route-before" "$run/ai-route-after"
sha256sum -c "$run/account-before" >/dev/null
echo UPLINK_RESCUE_EXACT_CLEANUP_NORMAL_LAN_ACCOUNTS_PRESERVED_PASS
echo QEMU_LEON_UPLINK_RESCUE_COMPLETE
