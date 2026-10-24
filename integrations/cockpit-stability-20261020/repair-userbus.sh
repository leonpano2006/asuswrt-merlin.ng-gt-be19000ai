set -euo pipefail
printf 'BASELINE\n'
date -u
cat /proc/sys/kernel/random/boot_id
systemctl show ssh.service leon-asus-broker.service -p Id -p MainPID -p ActiveState
dpkg-query -W -f='${binary:Package} ${Version}\n' systemd libsystemd0 libpam-systemd
printf '\nREPRODUCE EXISTING WRAPPER FAILURE\n'
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 python3 - <<'PY'
from cockpit._vendor.systemd_ctypes.bus import Bus
for i in range(2):
    try:
        bus=Bus.default_user()
        bus.attach_event(None,0)
        print(i, 'connected')
    except OSError as e:
        print(i, type(e).__name__, e.errno, str(e))
PY
printf '\nINSTALL EXACT MISSING PACKAGE\n'
export DEBIAN_FRONTEND=noninteractive
apt-get --no-remove --no-upgrade --no-install-recommends -y install dbus-user-session=1.16.2-2ubuntu4
printf '\nSTART USER SOCKET\n'
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user daemon-reload
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user start dbus.socket
printf '\nVERIFY USER BUS\n'
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 busctl --user --no-pager list
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 python3 - <<'PY'
import errno
from cockpit._vendor.systemd_ctypes.bus import Bus
for i in range(2):
    bus=Bus.default_user()
    try:
        bus.attach_event(None,0)
    except OSError as e:
        if e.errno != errno.EBUSY:
            raise
    print(i,'Cockpit user bus initialized; repeat attach handled as EBUSY')
PY
printf '\nPACKAGE AND SERVICE HEALTH\n'
apt-get check
dpkg --audit
dpkg-query -W -f='${binary:Package} ${Version}\n' systemd libsystemd0 libpam-systemd dbus-user-session
systemctl show ssh.service leon-asus-broker.service -p Id -p MainPID -p ActiveState
runuser -u MastermixStudios -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user status dbus.socket dbus.service --no-pager
cat /proc/sys/kernel/random/boot_id
date -u
