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
if test "$case" = healthy-ssh-argv; then
 # Load the future ExecStart while STARTING. The currently running canonical
 # daemon keeps its original argv; later injection only restarts the service.
 cp /run/leon-asus-ssh/sshd_config /run/leon-asus-ssh/unmanaged_config
 mkdir -p /run/systemd/system/ssh.service.d
 printf '[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -f /run/leon-asus-ssh/unmanaged_config\n' > /run/systemd/system/ssh.service.d/99-unmanaged-fixture.conf
 systemctl daemon-reload
fi
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
before=$(cat "$R/pings")
sleep 6
test "$(cat "$R/pings")" -gt "$before"
echo LAB_TRIAL_LOOP_HEALTHY_KEEPS_FEEDING_PASS
touch "$R/stop-acks"
wait "$observer"
stage=failure-injection
case "$case" in
 healthy-lan-expiry) ;;
 healthy-ssh-argv)
  previous=$(cat "$R/local-sequence")
  for n in $(seq 1 100); do test "$(cat "$R/local-sequence")" != "$previous" && break; sleep .1; done
  test "$(cat "$R/local-sequence")" != "$previous"
  echo LAB_TRIAL_LOOP_SSH_RESTART_INJECTION_BEGIN
  systemctl restart ssh.service
  wait_key_ssh
  echo LAB_TRIAL_LOOP_LIVE_SSH_WRONG_ARGV_INJECTED;;
 healthy-worker-hang) touch "$R/hang-worker"; echo LAB_TRIAL_LOOP_WORKER_HANG_INJECTED;;
 healthy-metadata-change) printf '0\n' > /var/lib/leon-trial-loop/preflight/sys/dev/block/179:1/ro; echo LAB_TRIAL_LOOP_METADATA_RO_LOST_INJECTED;;
 *) exit 1;;
esac
for n in $(seq 1 750); do test -f "$R/failed" && break; sleep .1; done
test -f "$R/failed"
case "$case" in
 healthy-lan-expiry) grep -q 'reason=6 ' "$R/failed";;
 healthy-ssh-argv) grep -q 'reason=4 ' "$R/failed";;
esac
stage=no-feed-after-failure
failed_pings=$(cat "$R/failed-pings")
sleep 6
test "$(cat "$R/pings")" = "$failed_pings"
if key_ssh '/usr/libexec/leon-asus/trial-ack --challenge' > "$R/failed-challenge.json" 2>/dev/null; then exit 1; fi
echo LAB_TRIAL_LOOP_FAILURE_STOPS_FEEDING_PASS
stage=durable-first-failure
boot_id=$(cat /proc/sys/kernel/random/boot_id)
diagnostic_build=$(cat "$B/diagnostic-build-id")
# Capture one complete CRC-checked record. The guardian's independent writer
# may finish an in-flight update, so retry only the read, with a short bound.
for n in $(seq 1 20); do
 if "$B/diagnostic-reader" --dump /etc/leon/boot-diagnostics 1 "$boot_id" "$diagnostic_build" > "$R/diagnostic.txt"; then break; fi
 sleep .1
done
grep -q '^LEON_DIAG_RECORD_PASS producer=1 ' "$R/diagnostic.txt"
grep -Fxq 'producer=guardian' "$R/diagnostic.txt"
grep -Fxq 'handed=1' "$R/diagnostic.txt"
grep -Fxq 'failed=1' "$R/diagnostic.txt"
awk -F= '/^monotonic_ms=/{now=$2} /^last_successful_keepalive_ms=/{ping=$2} END{exit !(ping>0 && now>=ping)}' "$R/diagnostic.txt"
echo LAB_TRIAL_LOOP_DIAGNOSTIC_CRC_BOOT_BUILD_PASS
case "$case" in
 healthy-lan-expiry|healthy-ssh-argv) grep -Fxq 'first_failure=policy-expiry' "$R/diagnostic.txt";;
 healthy-worker-hang)
  grep -Fxq 'first_failure=worker' "$R/diagnostic.txt"
  grep -Fxq 'worker_wait_status_valid=1' "$R/diagnostic.txt"
  # The explicit mock timer handler exits the worker with 124. This is the
  # unmodified waitpid status, not a claim about real hardware signal status.
  grep -Fxq 'worker_raw_wait_status=31744' "$R/diagnostic.txt"
  grep -Fxq 'worker_failed=1' "$R/diagnostic.txt"
  echo LAB_TRIAL_LOOP_DIAGNOSTIC_WORKER_WAIT_STATUS_PASS;;
 healthy-metadata-change) grep -Fxq 'first_failure=metadata-recheck' "$R/diagnostic.txt";;
esac
echo LAB_TRIAL_LOOP_DIAGNOSTIC_FIRST_FAILURE_PASS
cat "$R/diagnostic.txt"
stage=reset-sink
for n in $(seq 1 450); do test -s "$R/reset-sink" && break; sleep .1; done
grep -Fxq LAB_TRIAL_LOOP_RESET_SINK_PASS "$R/reset-sink"
test "$(cat "$R/pings")" = "$failed_pings"
echo LAB_TRIAL_LOOP_KERNEL10_COMPLETE
printf 'LAB_TRIAL_LOOP_KERNEL10_COMPLETE\n' > /run/leon-pivot-service-ok
