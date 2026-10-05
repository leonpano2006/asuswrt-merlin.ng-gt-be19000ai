#!/bin/bash
# Disposable no-NIC guest only. Real SSH and production-loop timing.
set -euo pipefail
stage=entry
R=/run/leon-trial-loop
B=/usr/libexec/leon-lab/trial-loop
trap 'rc=$?; echo LAB_TRIAL_LOOP_PROOF_EXIT_code=$rc stage=$stage; if test "$rc" != 0; then cat "$R/state" 2>/dev/null || :; systemctl status ssh.service leon-asus-broker.service --no-pager || :; journalctl -u ssh.service -u leon-asus-broker.service -n 30 --no-pager || :; fi' EXIT
test "$(cat /proc/1/comm)" = systemd
test "$(stat -c '%u:%g:%a' /)" = 0:0:755
test "$(sha256sum /sys/kernel/notes | cut -d' ' -f1)" = d75d9316e93c45d36290eab8cdb48868c982b5740f54bb63d7cc38d89fae5ab4
echo LAB_TRIAL_LOOP_ACTUAL_KERNEL_NOTES_PASS
for link in /sys/class/net/*; do test ! -e "$link/device"; done
test -z "$(ip route show default)"
ip link set lo up
case=$(cat /etc/leon/trial-loop-case)
stage=services
mkdir -p /run/sshd /run/leon-asus-ssh /run/asus /data /jffs
chmod 700 /run/leon-asus-ssh
install -o root -g root -m 600 "$B/sshd_config" /run/leon-asus-ssh/sshd_config
mount --bind /var/lib/leon-trial-loop/mount-data /data
mount --bind /var/lib/leon-trial-loop/mount-jffs /jffs
data_dev=$(findmnt -nr -o MAJ:MIN -T /data); jffs_dev=$(findmnt -nr -o MAJ:MIN -T /jffs)
printf 'ASUS_STORAGE_V1\n%s\ndata %s %s ext4 b2779970-ea82-4aec-96ed-816e1aac53a0\njffs %s %s ext4 7575e860-48ee-493e-bb5b-a1ca270b8512\n' "$(cat /proc/sys/kernel/random/boot_id)" "${data_dev/:/ }" "$(stat -c %i /data)" "${jffs_dev/:/ }" "$(stat -c %i /jffs)" > /run/asus/storage-owned
chmod 600 /run/asus/storage-owned
systemctl stop ssh.socket || :
systemctl daemon-reload
systemctl start systemd-user-sessions.service
test ! -e /run/nologin
sshd -t -f /run/leon-asus-ssh/sshd_config
systemctl start ssh.service leon-asus-broker.service
systemctl is-active --quiet ssh.service leon-asus-broker.service
test -f "$R/armed"
test "$(cat "$R/armed")" = 40
/usr/libexec/leon-asus/trial-health --assert-armed
echo LAB_TRIAL_LOOP_IMMUTABLE_OWNER_QUERY_PASS
for n in $(seq 1 100); do test -S /run/leon-rc/control && break; sleep .1; done
test -S /run/leon-rc/control
broker=$(systemctl show leon-asus-broker.service -p MainPID --value)
echo "LAB_TRIAL_LOOP_BROKER_TOPOLOGY pid=$broker"
cat /run/asus/storage-owned
cat "/proc/$broker/cgroup"
for child in $(ps -o pid= --ppid "$broker"); do
 echo "LAB_TRIAL_LOOP_CHILD pid=$child exe=$(readlink /proc/$child/exe)"
 cat "/proc/$child/cgroup"
 cat "/proc/$child/root/etc/.asus-private-etc"
 grep ' /etc ' "/proc/$child/mountinfo"
 for name in run data jffs; do stat -c '%d:%i %n' "/$name" "/proc/$child/root/$name"; done
done
awk '{print "[127.0.0.1]:2222 "$1" "$2}' /etc/ssh/ssh_host_ed25519_key.pub > "$R/known_hosts"
key_ssh() { timeout -s KILL 10 ssh -F /dev/null -p 2222 -i "$B/client-key" -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -o ControlMaster=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$R/known_hosts" -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=3 MastermixStudios@127.0.0.1 "$@"; }
wait_key_ssh() {
 # Type=simple becomes active before sshd has bound its sockets.
 for n in $(seq 1 20); do
  if test "$(key_ssh 'id -un' 2>/dev/null)" = MastermixStudios; then return 0; fi
  sleep .1
 done
 return 1
}
wait_key_ssh
if /usr/libexec/leon-asus/trial-ack --challenge > "$R/local-root.json" 2>/dev/null; then exit 1; fi
if runuser -u MastermixStudios -- /usr/libexec/leon-asus/trial-ack --challenge > "$R/local-user.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_LOOP_REAL_SSH_AND_LOCAL_REJECT_PASS
(
 for n in $(seq 1 20); do
  key_ssh '/usr/libexec/leon-asus/trial-ack --challenge' > "$R/challenge.json"
  sed 's/,"expires_in_ms":20000//' "$R/challenge.json" > "$R/ack.json"
  key_ssh '/usr/libexec/leon-asus/trial-ack --ack' < "$R/ack.json" > "$R/accepted.json"
  grep -q '"accepted":true' "$R/accepted.json"
  test ! -e "$R/stop-acks" || break
  sleep 5
 done
) > "$R/observer.log" 2>&1 &
observer=$!
stage=healthy
for n in $(seq 1 450); do test -f "$R/healthy" && break; sleep .1; done
test -f "$R/healthy"
test ! -f "$R/failed"
stage=explicit-current-boot-accept
boot=$(cat /proc/sys/kernel/random/boot_id)
accept=/usr/libexec/leon-asus/trial-accept
if runuser -u MastermixStudios -- "$accept" --accept-this-boot --expected-boot-id "$boot"; then exit 1; fi
if "$accept" --accept-this-boot --expected-boot-id 00000000-0000-0000-0000-000000000000; then exit 1; fi
"$accept" --accept-this-boot --expected-boot-id "$boot"
"$accept" --status --expected-boot-id "$boot" | tee "$R/accept-status"
grep -q 'accepted_this_boot=1 metadata_committed=2' "$R/accept-status"
cp "$R/watchdog-owner" "$R/accepted-owner"
grep -q '^arms=1 ' "$R/accepted-owner"
echo LAB_ACCEPTED_CURRENT_BOOT_STATUS_PASS
stage=network-and-service-stop
touch "$R/stop-acks"
wait "$observer"
systemctl stop ssh.service leon-asus-broker.service
if systemctl is-active --quiet ssh.service; then exit 1; fi
if systemctl is-active --quiet leon-asus-broker.service; then exit 1; fi
ip link set lo down
echo LAB_ACCEPTED_SSH_ASUS_ACK_NETWORK_STOPPED
before=$(cat "$R/pings")
sleep 65
test ! -f "$R/failed"
test "$(cat "$R/pings")" -gt "$before"
cmp "$R/watchdog-owner" "$R/accepted-owner"
"$accept" --status --expected-boot-id "$boot" | tee "$R/accept-status-after-outage"
grep -q 'accepted_this_boot=1 metadata_committed=2' "$R/accept-status-after-outage"
echo LAB_ACCEPTED_NO_SERVICE_DEPENDENCY_65S_PASS
stage=actual-core-failure
# Remove an actual bind mount; accepted-core still checks real ext4/RW/root
# ownership and compares mount identity against the declared fixture source.
echo LAB_ACCEPTED_CORE_JFFS_UNMOUNT_BEGIN
umount /jffs
test "$(stat -c '%d:%i' /jffs)" != "$(stat -c '%d:%i' /var/lib/leon-trial-loop/mount-jffs)"
echo LAB_ACCEPTED_CORE_JFFS_UNMOUNT_INJECTED
for n in $(seq 1 100); do test -f "$R/failed" && break; sleep .1; done
test -f "$R/failed"
stage=no-feed-after-failure
failed_pings=$(cat "$R/failed-pings")
sleep 6
test "$(cat "$R/pings")" = "$failed_pings"
echo LAB_TRIAL_LOOP_FAILURE_STOPS_FEEDING_PASS
stage=reset-sink
for n in $(seq 1 450); do test -s "$R/reset-sink" && break; sleep .1; done
grep -Fxq LAB_TRIAL_LOOP_RESET_SINK_PASS "$R/reset-sink"
test "$(cat "$R/pings")" = "$failed_pings"
cmp "$R/watchdog-owner" "$R/accepted-owner"
echo LAB_ACCEPTED_SINGLE_WATCHDOG_OWNER_PASS
echo LAB_TRIAL_LOOP_KERNEL10_COMPLETE
printf 'LAB_TRIAL_LOOP_KERNEL10_COMPLETE\n' > /run/leon-pivot-service-ok
