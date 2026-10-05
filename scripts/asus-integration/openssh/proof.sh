#!/bin/bash
set -euo pipefail
stage=start
trap 'rc=$?; echo LAB_SSH_CONTROL_EXIT_code=$rc stage=$stage; if test "$rc" != 0; then systemctl status ssh.service leon-asus-ssh.socket --no-pager || :; journalctl -u "leon-asus-ssh@*" -u ssh.service -n 40 --no-pager || :; fi' EXIT
B=/usr/libexec/leon-lab/ssh-control
R=/run/leon-ssh-test
C=$B/request
H=/usr/libexec/leon-asus/ssh-control
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
test "$(sha256sum /sys/kernel/notes | cut -d ' ' -f 1)" = d75d9316e93c45d36290eab8cdb48868c982b5740f54bb63d7cc38d89fae5ab4
echo LAB_SSH_CONTROL_KERNEL10_NOTES_PASS
for link in /sys/class/net/*; do test ! -e "$link/device"; done
test -z "$(ip -o address show scope global)"
test -z "$(ip route show default)"
ip link set lo up
mkdir -m 700 "$R"
mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$R/identity"
ssh-keygen -q -t ed25519 -N '' -f "$R/denied"
# The source candidate contains explicitly recorded lab prototype keys. This
# fixture only discards keys in the disposable guest, never on a live device.
test "$(stat -c "%u:%g:%a" /)" = 0:0:755
stage=host-key-ownership
sha256sum /etc/ssh/ssh_host_* > "$R/prototype-keys"
if "$H" --initialize-device-identity; then exit 1; fi
sha256sum -c "$R/prototype-keys" > /dev/null
rm /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub
"$H" --initialize-device-identity
sha256sum /etc/ssh/ssh_host_* > "$R/device-keys"
"$H" --initialize-device-identity
sha256sum -c "$R/device-keys" > /dev/null
if unshare --mount "$H" --initialize-device-identity; then exit 1; fi
echo LAB_SSH_CONTROL_DEVICE_KEYS_PASS
stage=socket-activation
systemctl stop ssh.service ssh.socket
systemctl start leon-asus-ssh.socket
systemctl is-active --quiet leon-asus-ssh.socket
cp "$C" "$R/unapproved-client"
"$R/unapproved-client" unapproved-peer
if runuser -u nobody -- "$C" apply >/dev/null 2>&1; then exit 1; fi
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow > "$R/accounts-before"
for case in wrong-name wrong-hash wrong-hash-empty wrong-op wan wrong-address wrong-key; do "$C" "$case"; done
sha256sum -c "$R/accounts-before" > /dev/null
test ! -d /home/MastermixStudios
if systemctl is-active --quiet ssh.service; then exit 1; fi
echo LAB_SSH_CONTROL_REJECT_INVALID_NO_CHANGE_PASS
stage=missing-device-marker
mv /var/lib/leon-asus-ssh/device-identity "$R/identity-marker"
"$C" missing-device
mv "$R/identity-marker" /var/lib/leon-asus-ssh/device-identity
test ! -d /home/MastermixStudios
# Only one approved shadow entry may be updated. Root and all other shadow
# lines remain byte-identical; synthetic fixture material is never printed.
grep -v '^MastermixStudios:' /etc/shadow > "$R/shadow-unrelated"
stage=identity-only
"$C" identity
test "$(id -u MastermixStudios)" -ge 1000
test "$(id -u MastermixStudios)" != 0
id -nG MastermixStudios | grep -qw sudo
grep -v '^MastermixStudios:' /etc/shadow | cmp - "$R/shadow-unrelated"
if systemctl is-active --quiet ssh.service; then exit 1; fi
test ! -f /run/leon-asus-ssh/sshd_config
echo LAB_SSH_CONTROL_IDENTITY_ONLY_NO_START_PASS
stage=armel-transport
cp "$C" "$R/native-client"
cp "$B/request-armel" "$C"
"$C" identity
"$C" wrong-name
"$C" wrong-hash
cp "$R/native-client" "$C"
echo LAB_SSH_CONTROL_ARMEL_TIME64_TRANSPORT_PASS
stage=unmanaged-master
mkdir -p /run/systemd/system/ssh.service.d
cat > "$R/unmanaged_config" <<'CONFIG'
Port 2223
ListenAddress 127.0.0.1
PermitRootLogin no
PasswordAuthentication no
UsePAM yes
CONFIG
cat > /run/systemd/system/ssh.service.d/99-unmanaged-fixture.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/sbin/sshd -D -f /run/leon-ssh-test/unmanaged_config
UNIT
systemctl daemon-reload
systemctl start ssh.service
unmanaged_pid=$(systemctl show ssh.service -p MainPID --value)
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow "$R/unmanaged_config" /var/lib/leon-asus-ssh/authorized_keys > "$R/unmanaged-state"
"$C" unmanaged-master
sha256sum -c "$R/unmanaged-state" > /dev/null
test "$unmanaged_pid" = "$(systemctl show ssh.service -p MainPID --value)"
test ! -f /run/leon-asus-ssh/sshd_config
test ! -f /run/systemd/system/ssh.service.d/90-leon-asus.conf
systemctl stop ssh.service
rm /run/systemd/system/ssh.service.d/99-unmanaged-fixture.conf
systemctl daemon-reload
echo LAB_SSH_CONTROL_UNMANAGED_MASTER_REFUSED_UNCHANGED_PASS
stage=apply
"$C" apply
systemctl is-active --quiet ssh.service
if systemctl is-active --quiet ssh.socket; then exit 1; fi
if pidof dropbear; then exit 1; fi
sshd -t -f /run/leon-asus-ssh/sshd_config
sshd -T -f /run/leon-asus-ssh/sshd_config > "$R/effective"
for line in 'passwordauthentication yes' 'permitrootlogin no' 'permitemptypasswords no' 'kbdinteractiveauthentication no' 'allowtcpforwarding no' 'usepam yes' 'listenaddress 127.0.0.1:2222' 'listenaddress [::1]:2222'; do grep -Fxq "$line" "$R/effective"; done
ss -H -ltnp > "$R/listeners"
test "$(wc -l < "$R/listeners")" -eq 2
grep -Fq '127.0.0.1:2222' "$R/listeners"
grep -Fq '[::1]:2222' "$R/listeners"
echo LAB_SSH_CONTROL_IPV4_IPV6_LAN_CONFIG_PASS
pid=$(systemctl show ssh.service -p MainPID --value)
printf 'LAB_SSH_CONTROL_ACTUAL_MASTER_CMDLINE='
tr '\0' '\n' < "/proc/$pid/cmdline"
awk '{print "[127.0.0.1]:2222 "$1" "$2; print "[::1]:2222 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > "$R/known_hosts"
stage=key-login
common=(-F /dev/null -p 2222 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$R/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=5)
key_ssh() { timeout -s KILL 20 ssh "${common[@]}" -i "$R/identity" -o BatchMode=yes "MastermixStudios@$1" "${@:2}"; }
test "$(key_ssh 127.0.0.1 'id -un')" = MastermixStudios
test "$(key_ssh ::1 'id -un')" = MastermixStudios
if timeout -s KILL 12 ssh "${common[@]}" -i "$R/denied" -o BatchMode=yes MastermixStudios@127.0.0.1 true > "$R/denied.log" 2>&1; then exit 1; fi
grep -q 'Permission denied' "$R/denied.log"
if timeout -s KILL 12 ssh "${common[@]}" -i "$R/identity" -o BatchMode=yes root@127.0.0.1 true > "$R/root-denied.log" 2>&1; then exit 1; fi
grep -q 'Permission denied' "$R/root-denied.log"
echo LAB_SSH_CONTROL_KEY_LOGIN_AND_REJECT_PASS
stage=password-and-sudo
write_askpass() {
cat > "$R/askpass" <<'ASK'
#!/bin/sh
printf '%s\n' 'GuestFixture-Only-42!'
ASK
chmod 700 "$R/askpass"
}
write_askpass
password_ssh() { DISPLAY=guest:0 SSH_ASKPASS="$R/askpass" SSH_ASKPASS_REQUIRE=force timeout -s KILL 20 setsid ssh "${common[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 "${1:-MastermixStudios}@127.0.0.1" "${2:-id -un}" </dev/null; }
test "$(password_ssh)" = MastermixStudios
if key_ssh 127.0.0.1 'sudo -n true' > "$R/sudo-denied.log" 2>&1; then exit 1; fi
grep -qi 'password.*required' "$R/sudo-denied.log"
test "$(key_ssh 127.0.0.1 'printf "%s\n" "GuestFixture-Only-42!" | sudo -S -p "" id -u')" = 0
printf '#!/bin/sh\nprintf "wrong-fixture-password\\n"\n' > "$R/askpass"
if password_ssh > "$R/password-denied.log" 2>&1; then exit 1; fi
grep -q 'Permission denied' "$R/password-denied.log"
echo LAB_SSH_CONTROL_PASSWORD_SUDO_POLICY_PASS
stage=legacy-hash
write_askpass
test "$("$R/askpass")" = GuestFixture-Only-42!
"$C" legacy-hash
test "$(password_ssh)" = MastermixStudios
"$C" identity
grep -v '^MastermixStudios:' /etc/shadow | cmp - "$R/shadow-unrelated"
echo LAB_SSH_CONTROL_LEGACY_MD5_AUTH_PASS
stage=idempotent-and-hash-validation
pid=$(systemctl show ssh.service -p MainPID --value)
"$C" apply
test "$pid" = "$(systemctl show ssh.service -p MainPID --value)"
sha256sum /etc/passwd /etc/shadow /etc/group /etc/gshadow /run/leon-asus-ssh/sshd_config > "$R/active-state"
for case in wrong-name wrong-hash wrong-hash-empty wan wrong-key; do "$C" "$case"; done
sha256sum -c "$R/active-state" > /dev/null
test "$pid" = "$(systemctl show ssh.service -p MainPID --value)"
sha256sum -c "$R/device-keys" > /dev/null
grep -v '^MastermixStudios:' /etc/shadow | cmp - "$R/shadow-unrelated"
echo LAB_SSH_CONTROL_IDEMPOTENT_SINGLE_ENTRY_PASS
stage=password-off
"$C" password-off
sshd -T -f /run/leon-asus-ssh/sshd_config | grep -Fxq 'passwordauthentication no'
test "$(key_ssh 127.0.0.1 'id -un')" = MastermixStudios
write_askpass
test "$("$R/askpass")" = GuestFixture-Only-42!
if password_ssh > "$R/password-off.log" 2>&1; then exit 1; fi
grep -q 'Permission denied (publickey)' "$R/password-off.log"
echo LAB_SSH_CONTROL_PASSWORD_DISABLE_PASS
stage=service-restart
systemctl restart ssh.service
test "$(key_ssh 127.0.0.1 'id -un')" = MastermixStudios
sha256sum -c "$R/device-keys" > /dev/null
echo LAB_SSH_CONTROL_SERVICE_RESTART_PASS
stage=disable
"$C" disable
if systemctl is-active --quiet ssh.service; then exit 1; fi
test -z "$(ss -H -ltn)"
sha256sum -c "$R/device-keys" > /dev/null
echo LAB_SSH_CONTROL_DISABLE_PASS
stage=reenable-after-runtime-cleanup
test ! -d /run/sshd
"$C" apply
test "$(key_ssh 127.0.0.1 'id -un')" = MastermixStudios
sha256sum -c "$R/device-keys" > /dev/null
"$C" disable
test -z "$(ss -H -ltn)"
echo LAB_SSH_CONTROL_REENABLE_AFTER_STOP_PASS
dpkg --audit > "$R/dpkg-audit"
test ! -s "$R/dpkg-audit"
echo LAB_SSH_CONTROL_KERNEL10_COMPLETE
