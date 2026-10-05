#!/bin/bash
# Disposable no-NIC guest only. Reuse synthetic identities; never import a
# production private key or exercise the vendor password/control path.
set -euo pipefail
exec >/dev/console 2>&1
stage=start
trap 'rc=$?; echo LAB_SSH_RECOVERY_EXIT_code=$rc stage=$stage; if test "$rc" != 0; then systemctl status leon-asus-ssh-recovery.socket --no-pager || :; journalctl -u "leon-asus-ssh-recovery@*" -u ssh.service -n 25 --no-pager || :; fi' EXIT
recovery_lab=/usr/libexec/leon-lab/recovery
recovery_run=/run/leon-ssh-recovery-test
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
for link in /sys/class/net/*; do test ! -e "$link/device"; done
test -z "$(ip -o address show scope global)"
test -z "$(ip route show default)"
test "$(id -u MastermixStudios)" = 2000
test -d /home/MastermixStudios
mkdir -m 0700 "$recovery_run"
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config > "$recovery_run/preserved-files"

stage=independent-prerequisites
systemctl stop ssh.service ssh.socket
while read -r unit; do
 systemctl mask --now "$unit"
 if systemctl is-active --quiet "$unit"; then exit 1; fi
done < "$recovery_lab/vendor-units"
# There is no imported vendor shadow or ordinary-control authorization file.
test ! -e /run/leon-asus-ssh/control
test ! -e /var/lib/leon-asus-ssh/authorized_keys
test -z "$(pgrep -x rc-broker || :)"
test -z "$(pgrep -x rc || :)"
install -d -o root -g root -m 0755 /run/sshd
/usr/sbin/sshd -t -f /etc/ssh/leon-asus-recovery.conf
/usr/sbin/sshd -T -f /etc/ssh/leon-asus-recovery.conf > "$recovery_run/effective"
for expected in 'authenticationmethods publickey' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'permitrootlogin no' 'disableforwarding yes' 'usepam yes'; do
 grep -qx "$expected" "$recovery_run/effective"
done
systemctl enable leon-asus-ssh-recovery.socket
test ! -e /sys/class/net/br0
if systemctl is-active --quiet leon-asus-ssh-recovery.socket; then exit 1; fi
test -L /etc/systemd/system/sys-subsystem-net-devices-br0.device.wants/leon-asus-ssh-recovery.socket
test ! -e /etc/systemd/system/sockets.target.wants/leon-asus-ssh-recovery.socket
echo LAB_SSH_RECOVERY_VENDOR_CONTROL_UNAVAILABLE_PASS

wait_socket() {
 for attempt in $(seq 1 30); do
  if systemctl is-active --quiet leon-asus-ssh-recovery.socket; then return; fi
  sleep 0.1
 done
 return 1
}
bridge_up() {
 ip link add br0 type bridge
 ip address add 192.168.100.15/24 dev br0
 ip address add 192.168.101.15/24 dev br0
 ip link set br0 up
 udevadm settle
 wait_socket
}
stage=late-bridge-activation
ip link set lo up
# The listener must activate before authorization is provisioned, then accept
# the persistent public key without depending on a vendor-control restart.
mv /var/lib/leon-asus-ssh/recovery_authorized_keys "$recovery_run/pending_authorized_keys"
bridge_up
systemctl is-active --quiet sys-subsystem-net-devices-br0.device
ip netns add recovery-client
ip link add recovery-server type veth peer name recovery-client
ip link set recovery-server master br0
ip link set recovery-server up
ip link set recovery-client netns recovery-client
ip -n recovery-client link set lo up
ip -n recovery-client address add 192.168.100.51/24 dev recovery-client
ip -n recovery-client address add 192.168.101.51/24 dev recovery-client
ip -n recovery-client link set recovery-client up
test -z "$(ip route show default)"
test -z "$(ip -n recovery-client route show default)"
echo LAB_SSH_RECOVERY_LATE_BR0_DEVICE_ACTIVATION_PASS

awk '{print "[192.168.100.15]:2222 "$1" "$2; print "[192.168.101.15]:2222 "$1" "$2; print "[192.168.100.14]:2222 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > "$recovery_run/known_hosts"
recovery_common=(-F /dev/null -T -p 2222 -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$recovery_run/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=4)
recovery_options=("${recovery_common[@]}" -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no)
recovery_ssh() {
 timeout -s KILL 12 ip netns exec recovery-client ssh "${recovery_options[@]}" -i "$recovery_lab/client-key" MastermixStudios@192.168.100.15 "$@"
}
stage=key-only-login
if recovery_ssh true > "$recovery_run/missing-key.log" 2>&1; then exit 1; fi
systemctl is-active --quiet leon-asus-ssh-recovery.socket
mv "$recovery_run/pending_authorized_keys" /var/lib/leon-asus-ssh/recovery_authorized_keys
test "$(recovery_ssh id -u)" = 2000
test "$(recovery_ssh cat /proc/1/comm)" = systemd
echo LAB_SSH_RECOVERY_PINNED_KEY_ONLY_LOGIN_PASS

stage=negative-auth-and-interface
if timeout -s KILL 8 ip netns exec recovery-client ssh "${recovery_options[@]}" -i "$recovery_lab/denied-key" MastermixStudios@192.168.100.15 true > "$recovery_run/denied-key.log" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$recovery_run/denied-key.log"
if timeout -s KILL 8 ip netns exec recovery-client ssh "${recovery_options[@]}" -i "$recovery_lab/client-key" root@192.168.100.15 true > "$recovery_run/root.log" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$recovery_run/root.log"
if timeout -s KILL 8 ip netns exec recovery-client ssh "${recovery_common[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes MastermixStudios@192.168.100.15 true > "$recovery_run/password.log" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$recovery_run/password.log"
if timeout -s KILL 8 ip netns exec recovery-client ssh "${recovery_options[@]}" -b 192.168.101.51 -i "$recovery_lab/client-key" MastermixStudios@192.168.101.15 true > "$recovery_run/non-lan.log" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$recovery_run/non-lan.log"
# A separate veth never joins br0. Both addresses remain within AllowUsers'
# permitted subnet, so refusal checks BindToDevice instead of the source ACL.
ip netns add recovery-other
ip link add recother-s type veth peer name recother-c
ip link set recother-c netns recovery-other
ip address add 192.168.100.14/32 dev recother-s
ip link set recother-s up
ip route add 192.168.100.52/32 dev recother-s
ip -n recovery-other link set lo up
ip -n recovery-other address add 192.168.100.52/32 dev recother-c
ip -n recovery-other link set recother-c up
ip -n recovery-other route add 192.168.100.14/32 dev recother-c
if timeout -s KILL 8 ip netns exec recovery-other ssh "${recovery_options[@]}" -b 192.168.100.52 -i "$recovery_lab/client-key" MastermixStudios@192.168.100.14 true > "$recovery_run/non-br0.log" 2>&1; then exit 1; fi
grep -Eq 'Connection refused|Connection timed out' "$recovery_run/non-br0.log"
echo LAB_SSH_RECOVERY_PASSWORD_ROOT_OTHER_KEY_SOURCE_INTERFACE_REJECT_PASS

stage=ordinary-ssh-runtime-cleanup
systemctl start ssh.service
test -d /run/sshd
timeout -s KILL 18 ip netns exec recovery-client ssh "${recovery_options[@]}" -i "$recovery_lab/client-key" MastermixStudios@192.168.100.15 'echo RECOVERY_SESSION_READY; sleep 4; id -u' > "$recovery_run/live-session" &
recovery_pid=$!
for attempt in $(seq 1 30); do
 if grep -q '^RECOVERY_SESSION_READY$' "$recovery_run/live-session"; then break; fi
 sleep 0.1
done
grep -q '^RECOVERY_SESSION_READY$' "$recovery_run/live-session"
systemctl stop ssh.service
test -d /run/sshd
test "$(recovery_ssh id -u)" = 2000
wait "$recovery_pid"
grep -qx 2000 "$recovery_run/live-session"
echo LAB_SSH_RECOVERY_MAIN_SSH_STOP_LIVE_AND_NEW_LOGIN_PASS

stage=restart-and-device-recreation
systemctl restart leon-asus-ssh-recovery.socket
test "$(recovery_ssh id -u)" = 2000
ip link delete br0
udevadm settle
for attempt in $(seq 1 30); do
 if ! systemctl is-active --quiet leon-asus-ssh-recovery.socket; then break; fi
 sleep 0.1
done
if systemctl is-active --quiet leon-asus-ssh-recovery.socket; then exit 1; fi
bridge_up
ip link set recovery-server master br0
ip link set recovery-server up
test "$(recovery_ssh id -u)" = 2000
sha256sum -c "$recovery_run/preserved-files" > /dev/null
echo LAB_SSH_RECOVERY_SOCKET_RESTART_BR0_RECREATE_NO_ACCOUNT_CONFIG_CHANGE_PASS
echo QEMU_LEON_SSH_RECOVERY_COMPLETE
