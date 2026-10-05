#!/bin/sh
# Real systemd lifecycle; the backend contains no ASUS/hardware operations.
set -eu
test -f /QEMU_LAB_GUEST
test "$(cat /proc/1/comm)" = systemd
D=/usr/libexec/leon-lab/asus-bridge
R=/run/asus-broker-qemu
backend=${1:-native}
case "$backend" in
 native) U=leon-asus-broker-qemu.service;;
 armel) U=leon-asus-broker-armel-qemu.service;;
 *) exit 2;;
esac
for unit in leon-asus-broker-qemu.service leon-asus-broker-armel-qemu.service; do
 if systemctl is-active --quiet "$unit"; then exit 1; fi
done
for name in backend-pid identity-subreaper ready ready-go signals drained control owner.lock power-request marker-fail-closed early-alarm-blocked system-child-mask-reset; do
 rm -f "$R/$name"
done
echo LAB_ASUS_BRIDGE_PHASE_BEGIN_backend=$backend
failed() {
 result=$?
 if test "$result" != 0; then
  systemctl status "$U" --no-pager || :
  journalctl -u "$U" --no-pager || :
 fi
 exit "$result"
}
trap failed EXIT
wait_file() {
 count=0
 while ! test -s "$1"; do
  count=$((count+1)); test "$count" -lt 80; sleep 0.1
 done
}
wait_state() {
 count=0
 while test "$(systemctl show "$U" -p ActiveState --value)" != "$1"; do
  count=$((count+1)); test "$count" -lt 80; sleep 0.1
 done
}
owned_pids() {
 manager=$(tail -1 "$R/backend-pid")
 broker=$(systemctl show "$U" -p MainPID --value)
 test "$broker" -gt 1; test "$manager" -gt 1; test "$broker" != "$manager"
 test "$(awk '/^PPid:/ { print $2 }' /proc/"$manager"/status)" = "$broker"
 grep -q "/system.slice/$U" /proc/"$broker"/cgroup
 grep -q "/system.slice/$U" /proc/"$manager"/cgroup
}
systemctl start --no-block "$U"
wait_file "$R/backend-pid"
test "$(systemctl show "$U" -p ActiveState --value)" = activating
owned_pids
if "$D/rcctl" ping; then exit 1; fi
test "$(cat "$R/identity-subreaper")" = 1
test "$(cat "$R/early-alarm-blocked")" = 1
test "$(cat "$R/system-child-mask-reset")" = 1
echo LAB_ASUS_BRIDGE_ALARM_AND_CHILD_MASK_PASS
touch "$R/ready-go"
wait_state active
"$D/rcctl" ping
echo LAB_ASUS_BRIDGE_SYSTEMD_READY_CGROUP_PASS

"$D/rcctl" notify
wait_file "$R/signals"
test "$(tail -1 "$R/signals")" = 10
test "$(cat /proc/1/comm)" = systemd
echo LAB_ASUS_BRIDGE_NOTIFICATION_PASS

# Test-mode broker records the request instead of issuing systemctl reboot.
"$D/rcctl" reboot
test "$(cat "$R/power-request")" = reboot
systemctl is-active --quiet "$U"
systemctl stop "$U"
test "$(tail -1 "$R/drained")" = 15
test ! -e /proc/"$manager"; test ! -e /proc/"$broker"
test ! -S "$R/control"
test "$(systemctl show "$U" -p Result --value)" = success
echo LAB_ASUS_BRIDGE_ORDERED_STOP_PASS

systemctl start "$U"
owned_pids
old_manager=$manager; old_broker=$broker
systemctl restart "$U"
owned_pids
test "$manager" != "$old_manager"; test "$broker" != "$old_broker"
test ! -e /proc/"$old_manager"; test ! -e /proc/"$old_broker"
test "$(tail -1 "$R/drained")" = 3
"$D/rcctl" ping
echo LAB_ASUS_BRIDGE_RESTART_PASS

# Only the verified direct child of this fixture's MainPID is targeted.
kill -KILL "$manager"
wait_state failed
test "$(systemctl show "$U" -p Result --value)" = exit-code
test "$(systemctl show "$U" -p NRestarts --value)" = 0
test ! -e /proc/"$manager"; test ! -e /proc/"$broker"
test ! -S "$R/control"
if "$D/rcctl" notify; then exit 1; fi
systemctl reset-failed "$U"
systemctl start "$U"
owned_pids
"$D/rcctl" ping
systemctl stop "$U"
test "$(systemctl show "$U" -p Result --value)" = success
echo LAB_ASUS_BRIDGE_CRASH_RECOVERY_PASS
test "$(cat /proc/1/comm)" = systemd
echo LAB_ASUS_BRIDGE_SYSTEMD_LIFECYCLE_PASS
echo LAB_ASUS_BRIDGE_PHASE_END_backend=$backend
