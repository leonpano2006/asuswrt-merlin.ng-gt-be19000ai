set -euo pipefail
backup=/var/backups/leon-asus-network-owner/20261010
conf=/etc/NetworkManager/conf.d/99-leon-asus-owner.conf
test "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000025
systemctl is-active --quiet leon-asus-broker.service
systemctl is-active --quiet leon-asus-ssh-recovery.socket
test "$(nmcli -g GENERAL.NM-MANAGED device show br0)" = no
test -z "$(nmcli -t -f NAME connection show --active)"
test ! -e "$backup"
test ! -e "$conf"
install -d -m700 "$backup"
systemctl show NetworkManager.service NetworkManager-wait-online.service wpa_supplicant.service -p Id -p ActiveState -p UnitFileState -p MainPID > "$backup/units-before.txt"
bridge -d link show > "$backup/bridge-before.txt"
ip -j address show > "$backup/addresses-before.json"
ip -j route show > "$backup/routes-before.json"
ss -ntp state established '( sport = :22 )' > "$backup/ssh-sessions-before.txt"
install -d -m755 /etc/NetworkManager/conf.d
python3 - <<'PY'
from pathlib import Path
import os
p=Path('/etc/NetworkManager/conf.d/99-leon-asus-owner.conf')
text='''# ASUS rc/AiMesh owns the appliance interfaces. Retain packages for
# dependencies, but do not allow NetworkManager to reconfigure these devices.
[main]
no-auto-default=*
dns=none
rc-manager=unmanaged
hostname-mode=none

[keyfile]
unmanaged-devices=*
'''
fd=os.open(str(p),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
with os.fdopen(fd,'w') as f:f.write(text)
PY
# Mask before stopping so D-Bus clients cannot reactivate the competitors.
systemctl disable NetworkManager.service NetworkManager-wait-online.service wpa_supplicant.service
systemctl mask NetworkManager.service NetworkManager-wait-online.service wpa_supplicant.service
systemctl stop NetworkManager.service NetworkManager-wait-online.service wpa_supplicant.service
for u in NetworkManager.service NetworkManager-wait-online.service wpa_supplicant.service; do
 test "$(systemctl is-enabled "$u" 2>/dev/null || true)" = masked
 test "$(systemctl is-active "$u" 2>/dev/null || true)" = inactive
done
/usr/sbin/NetworkManager --print-config | awk '/^\[/ || /unmanaged-devices|no-auto-default|dns=|rc-manager|hostname-mode/'
printf 'BRIDGE AFTER RELEASE\n'
bridge link show
printf 'ASUS CONFIG\n'
for key in sw_mode re_mode lan_ipaddr sshd_enable wl0_radio wl1_radio wl2_radio wl0.2_bss_enabled wl1.2_bss_enabled wl2.2_bss_enabled; do printf '%s=' "$key"; asus nvram get "$key"; done
printf 'SSH UNIT\n'
systemctl show ssh.service ssh.socket -p Id -p ActiveState -p SubState -p MainPID -p KillMode -p Result -p ExecMainStatus -p FragmentPath
printf 'RECOVERY LISTENER\n'
ss -lntp '( sport = :22 or sport = :2222 )'
printf 'WIFI BSS STATE\n'
for i in wl0.2 wl1.2 wl2.2; do printf '%s\n' "$i"; timeout 3 asus wl -i "$i" bss || true; done
