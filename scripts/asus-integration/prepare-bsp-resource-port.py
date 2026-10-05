#!/usr/bin/env python3
"""Build reviewed private BSP resources; never execute a vendor boot script."""
import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'build/kernel9-ui1-rootfs'
HASHES = {
 'init.d/mount-fs.sh':'db4c12ff9738818eb578ab81136a5ccc4953b65edbc1cc836d27e012f27a3ee6',
 'init.d/partitioncfg':'45b1c150215d0238fb61a0e5e68c47e4f3425f5a958edb2e5dd7bda158daa4d9',
 'init.d/defaults':'52ffb91e7f649a0e90f897af15fd2a599eb98d83c5f47b2e3116cffd14b815e8',
 'init.d/check-and-restore.sh':'458e090cec33aded85dfc69f81deace106f2bed4fcf9bf845b959b2771df7488',
 'init.d/init-defaults.sh':'1438f56f7abe90d7b2fbd1efad377993d9a9f9de3cfb97fd552af58055949022',
 'init.d/hndmfg.sh':'c26926b9220d7c83c37efa87d1090452af1071e072d61484606a715608c0ef1b',
 'init.d/hndnvram.sh':'a997146f454eec5e80f03e02edd26cd3a44c23d5c81c41dbc0fda9f4b39e9816',
 'init.d/mount-data.inc':'053ed6d2fbc0c02de5cde82407f4143869728d7b7137d6e9fc7bed7ffdaf16e2',
 'profile':'756dfc9991ed60971f80b6eaa2f3a6079ba0ba8e8d779c612dcbb358414d3c79',
 'hotplug2.rules':'e2c195e573028c7f7e10de3e45f14f3b05da25685776b456960ba6968dd14176',
 'make_static_devnodes.sh':'8afa83f81ebaf64e262fc8b1939e5bac655cbf28f7b161b3fdecf3999364a08c',
 'init.d/system-config.sh':'f49360c868cd72159b707460957eca3dd8cdf27d29868799857e1c4d5341c375',
}
GUARD = '/usr/libexec/asus/bsp-ownership --require || exit 125\n'
HEADER = '#!/bin/sh\n# Ubuntu profile: native storage/device ownership; private ASUS namespace.\n' + GUARD


def sha(data): return hashlib.sha256(data).hexdigest()


def change_once(text, before, after):
 assert text.count(before) == 1, before[:100]
 return text.replace(before, after, 1)


def replace_function(text, name, body):
 pattern = r'^' + re.escape(name) + r'\(\)[ \t]*\n?\{\n.*?^\}'
 text, count = re.subn(pattern, name + '()\n{\n' + body + '\n}', text, flags=re.M|re.S)
 assert count == 1, name
 return text


def transforms(original):
 result = {}
 result['init.d/mount-fs.sh'] = HEADER + '''case "$1" in
 start)
  # Storage/device mounts and health acknowledgement belong to native units.
  # The guard rejects erase_psi and manufacturing/provisioning requests.
  mkdir -p /mnt/fs_update /var/state/dhcp /var/ppp /var/udhcpd /var/zebra /var/siproxd /var/cache /var/tmp /var/samba/share /var/samba/homes /var/samba/private /var/samba/locks
  if [ -x /bin/fscryptctl ] && [ -r /proc/device-tree/key_dev_specific_512 ]; then
   fscryptctl insert_key < /proc/device-tree/key_dev_specific_512 || exit 125
  fi
  [ ! -f /etc/smb.conf ] || cp /etc/smb.conf /var/samba/ || exit 125
  ;;
 stop) sync ;;
 *) exit 2 ;;
esac
'''
 result['init.d/mount-data.inc'] = '#!/bin/sh\n# Native units own every persistent filesystem. No repair/format fallback.\nmount_data() { /usr/libexec/asus/bsp-ownership --require; }\n'
 result['init.d/partitioncfg'] = HEADER + '# Exact existing mounts were verified. Partition creation and repair require a separate maintenance workflow.\ncase "$1" in start|stop) exit 0 ;; *) exit 2 ;; esac\n'
 result['init.d/defaults'] = HEADER + '''# CFE defaults programming is provisioning, not ordinary service startup.
for item in /proc/brcm/blxparms/defaults_*; do
 [ ! -e "$item" ] || { echo "Native provisioning required for bootloader defaults" >&2; exit 125; }
done
'''
 result['init.d/check-and-restore.sh'] = original['init.d/check-and-restore.sh'].replace('#!/bin/sh\n', HEADER, 1)
 result['init.d/init-defaults.sh'] = replace_function(original['init.d/init-defaults.sh'], 'init_defaults', '''    # This model invokes the function without a file list. Reject any future
    # write request instead of silently remounting native defaults writable.
    [ -z "$2" ] || { echo "Native defaults update required" >&2; exit 125; }''').replace('#!/bin/sh\n', HEADER, 1)
 result['init.d/hndmfg.sh'] = HEADER + '''# Normal boot is allowed only after the guard proves manufacturing mode off.
# Downloading/programming calibration and rebooting require maintenance mode.
case "$1" in start|stop) exit 0 ;; *) echo "Manufacturing operation requires native maintenance workflow" >&2; exit 125 ;; esac
'''
 text = original['init.d/hndnvram.sh'].replace('#!/bin/sh\n', HEADER, 1)
 start = text.index('echo "[$0]: mount /tmp/mnt/defaults"')
 end = text.index('# user_nvram_file is required', start)
 text = text[:start] + '# Native units supply /mnt/defaults and its compatibility aliases.\n\n' + text[end:]
 for function in ['mount_nand_mfg_nvram_fs','umount_nand_mfg_nvram_fs','mount_emmc_mfg_nvram_fs','umount_emmc_mfg_nvram_fs','mount_nor_mfg_nvram_fs','umount_nor_mfg_nvram_fs','mfg_remount_defaults','mount_mfg_nvram_fs','umount_mfg_nvram_fs']:
  # mfg_remount_defaults has the same full-line brace format.
  text = replace_function(text, function, '    /usr/libexec/asus/bsp-ownership --require || exit 125\n    return 0')
 text = change_once(text, '\t   mkdir -p $DIR_MFG_NVRAM\n\t\tcp $image_default_nvram_file $DEFAULTS_DIR_MFG_NVRAM/$FILE_MFG_NVRAM\n\t   ln -sf $image_default_nvram_file $DIR_MFG_NVRAM/$FILE_MFG_NVRAM', '\t   /usr/libexec/asus/bsp-ownership --nvram-template "$image_default_nvram_file" || exit 125')
 text = change_once(text, '    mkdir -p $DEFAULTS_DIR_MFG_NVRAM', '    # Defaults is native read-only storage; do not create calibration files here.')
 text = change_once(text, '    [ ! -L $DIR_MFG_NVRAM ] && ln -s $DEFAULTS_DIR_MFG_NVRAM $DIR_MFG_NVRAM', '    # A real private /mnt/nvram mountpoint is supplied by packaging.')
 text = change_once(text, '\tif  [ ! -e $kernel_nvram_file ]; then', '\tif  [ ! -e $kernel_nvram_file ]; then\n\t\trestored_existing=0\n\t\trestore_target="$kernel_nvram_file"\n\t\tkernel_nvram_file="${kernel_nvram_file}.leon-recovery"')
 for suffix in ['new','old']:
  needle=f'\t\t\tcp -f $kernel_nvram_file_{suffix} $kernel_nvram_file'
  text = change_once(text,needle,needle+' || exit 125\n\t\t\trestored_existing=1')
 text = change_once(text, '\t\t\tcp $original_kernel_nvram_file $kernel_nvram_file', '\t\t\tcp $original_kernel_nvram_file $kernel_nvram_file || exit 125')
 text = change_once(text, '\t\tif [ "$NEEDMOUNT" == "1" ]', '\t\t# A recovered complete new/old file needs no factory-template overwrite.\n\t\tif [ "$restored_existing" = "0" ]; then\n\t\tif [ "$NEEDMOUNT" == "1" ]')
 text = change_once(text, '\t\tfi\n\tfi\n\n\tif  [ ! -f /data/$wl_srom_nm ]; then', '\t\tfi\n\t\tfi\n\tfi\n\n\tif  [ ! -f /data/$wl_srom_nm ]; then')
 text = change_once(text, '\t    \t\tif  [ -f $DIR_MFG_NVRAM/$FILE_MFG_NVRAM ]; then', '\t    \t\tif  [ -f $DEFAULTS_DIR_MFG_NVRAM/$FILE_MFG_NVRAM ]; then\n\t\t\t/usr/libexec/asus/bsp-ownership --nvram-defaults || exit 125')
 text = change_once(text, '    nvram restore_mfg $kernel_nvram_file', '    nvram restore_mfg $kernel_nvram_file || return 125')
 text = change_once(text, '    nvram kernelset $kernel_nvram_file', '    nvram kernelset $kernel_nvram_file || return 125')
 text = re.sub(r'^(\s*)nvram_mfg_restore_default$', r'\1nvram_mfg_restore_default || exit 125', text, flags=re.M)
 text = change_once(text, '\t\tpopulate_nvram\n', '\t\tpopulate_nvram || exit 125\n')
 text = change_once(text, '\tif  [ -n "$STILLNOK" ] && [ -f $image_default_nvram_file ]; then', '\tif  [ -n "$STILLNOK" ]; then\n\t   [ -f "$image_default_nvram_file" ] || { echo "No factory or firmware calibration source" >&2; exit 125; }')
 text = change_once(text, '\t\techo  "*** populated ***"', '\t\tif [ -n "$restore_target" ]; then\n\t\t\tmv -f "$kernel_nvram_file" "$restore_target" || exit 125\n\t\t\tsync\n\t\tfi\n\t\techo  "*** populated ***"')
 start=text.index('# Get flash type\n');end=text.index('case "$1" in\n',start)
 text=text[:start]+'# Exact AI model and ext4 UUID policy determine storage, not the Ubuntu root device.\nFLASHTYPE="eMMC"\nFSTYPE=ext4\n\n'+text[end:]
 result['init.d/hndnvram.sh'] = text
 result['init.d/system-config.sh'] = HEADER + '''# Native systemd owns loopback, VM policy, module autoload and crash handling.
# Do not set modprobeX or load a raw-offset flash crash writer.
case "$1" in
 start)
  . /rom/etc/build_profile
  [ -n "$RDK_BUILD" ] || : > /var/udhcpd/udhcpd.leases
  # Keep the Broadcom acceleration compatibility setting.
  [ ! -e /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal ] || printf '1\\n' > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal
  # Legacy CMS files are separate from Ubuntu's /etc identity databases.
  cp /rom/etc/passwd.static /var/passwd || exit 125
  cp /rom/etc/group.static /var/group || exit 125
  ;;
 stop)
  [ -e /tmp/reboot_reason ] || printf 'Unknown\\n' > /tmp/reboot_reason
  if ! cmp -s /tmp/reboot_reason /data/reboot_reason; then cp /tmp/reboot_reason /data/reboot_reason || exit 125; fi
  ;;
 *) exit 2 ;;
esac
'''
 profile = original['profile']
 profile = change_once(profile, 'export LD_LIBRARY_PATH=/lib:/usr/lib:/lib/aarch64\n', '# Multiarch loader paths are package-owned; no legacy LD_LIBRARY_PATH.\n')
 start = profile.index('enable=`nvram get enable_core_dump`')
 end = profile.index('[ -f /jffs/etc/profile ]', start)
 profile = profile[:start] + '# Native crash policy owns root mounts and core_pattern.\n' + profile[end:]
 result['profile'] = profile
 rules = original['hotplug2.rules']
 for block in ['DEVPATH is set, ACTION == add {\nmakedev /dev/%DEVICENAME% 0644\n}\n',
               'SUBSYSTEM ~~ ^(usb|tty|block|scsi_generic)$, ACTION == remove {\nremove /dev/%DEVICENAME%\n}\n',
               'MODALIAS is set, ACTION == add {\nexec /sbin/modprobe -q %MODALIAS% ;\n}\n',
               'SUBSYSTEM == misc, DEVICENAME ~~ ^(tun|tap)$, DEVPATH is set, ACTION == add {\nexec mkdir -p -m 0777 /dev/net ;\nsymlink /dev/%DEVICENAME% /dev/net/%DEVICENAME%\n}\n']:
  rules = change_once(rules, block, '')
 # Preserve the exact vendor callback set; native dispatcher awaits udev nodes.
 rules = re.sub(r'exec /sbin/(asus_[a-z_]+) %DEVICENAME% %ACTION% ;', r'exec /usr/libexec/asus/device-event \1 %DEVICENAME% %ACTION% ;', rules)
 rules = rules.replace('exec /sbin/hotplug %SUBSYSTEM% ;', 'exec /usr/libexec/asus/device-event hotplug %SUBSYSTEM% %ACTION% ;')
 result['hotplug2.rules'] = '# ASUS_NATIVE_UDEV_CALLBACKS_V1\n' + rules
 result['make_static_devnodes.sh'] = HEADER + '# Native tmpfiles owns proprietary device nodes; the guard verifies them.\n'
 return result


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--label',required=True);a=p.parse_args()
 assert a.label and all(c.isalnum() or c in '-_' for c in a.label)
 work=ROOT/'build/asus-bsp-resources'/a.label;work.mkdir(parents=True,exist_ok=False)
 original={}
 for name,digest in HASHES.items():
  raw=(BASE/'rom/etc'/name).read_bytes();assert sha(raw)==digest,name
  original[name]=raw.decode()
 updated=transforms(original)
 rom=work/'rom';shutil.copytree(BASE/'rom/etc',rom/'etc',symlinks=True)
 patch='';changes=[]
 for name,text in updated.items():
  relative='rom/etc/'+name
  patch+='diff --git a/'+relative+' b/'+relative+'\n'+''.join(difflib.unified_diff(original[name].splitlines(True),text.splitlines(True),fromfile='a/'+relative,tofile='b/'+relative))
  target=rom/'etc'/name;target.write_text(text)
  changes.append({'path':relative,'before_sha256':HASHES[name],'after_sha256':sha(text.encode())})
  if name!='hotplug2.rules':subprocess.run(['/usr/bin/busybox','ash','-n',str(target)],check=True)
 patchfile=ROOT/'patches/ubuntu26/asuswrt6/0012-asus-bsp-resource-ownership.patch'
 patchfile.write_text(patch)
 # Keep an explicit private /etc allowlist, including firmware data and scripts.
 native={'fstab','ld.so.conf','nsswitch.conf','resolv.conf','modprobe.conf','e2fsck.conf','protocols','services','filesystems'}
 seed=work/'etc-seed';seed.mkdir()
 entries=[]
 for source in sorted((rom/'etc').iterdir()):
  if source.name in native:
   entries.append({'path':source.name,'policy':'native Ubuntu owns /etc path; vendor ROM copy retained as reference'});continue
  target=seed/source.name
  if source.is_symlink():target.symlink_to(os.readlink(source))
  elif source.is_dir():shutil.copytree(source,target,symlinks=True)
  else:shutil.copy2(source,target)
  entries.append({'path':source.name,'policy':'private ASUS etc lower only'})
 dangling=[]
 for link in (rom/'etc/rc3.d').iterdir():
  if link.is_symlink() and not link.exists():dangling.append(str(link.relative_to(work)))
 # Generate only proprietary nodes. Native core device nodes are never replaced.
 nodes=[]
 for name,major,minor in re.findall(r'^mknod /dev/([A-Za-z0-9_]+) c\s+(\d+)\s+(\d+)\s*$',original['make_static_devnodes.sh'],re.M):
  if int(major)>=300:nodes.append({'name':name,'major':int(major),'minor':int(minor)})
 tmpfiles=''.join(f"c /dev/{n['name']} 0600 root root - {n['major']}:{n['minor']}\n" for n in nodes)
 (work/'asus-bcm-devices.conf').write_text(tmpfiles)
 header='/* Generated from the hash-guarded model static node list; no core devices. */\nstruct leon_bsp_node { const char *path; unsigned int major_number,minor_number; };\nstatic const struct leon_bsp_node leon_bsp_nodes[] = {\n'
 header+=''.join(f'    {{"/dev/{n["name"]}", {n["major"]}, {n["minor"]}}},\n' for n in nodes)+'};\n'
 (ROOT/'scripts/asus-integration/bsp-devices.h').write_text(header)
 # PARTNAME is a partition label, not a filesystem LABEL.
 (work/'70-asus-mmc-aliases.rules').write_text('SUBSYSTEM=="block", KERNEL=="mmcblk[0-9]*p[0-9]*", ENV{PARTNAME}=="data|jffs|defaults|aiboard|misc|nvram|rootfs1|rootfs2", SYMLINK+="$env{PARTNAME}"\n')
 report={'status':'projected resource candidate; native helper/launcher wiring and actual BSP execution still gated',
  'base':'build/kernel9-ui1-rootfs/rom/etc','patch':{'path':str(patchfile.relative_to(ROOT)),'sha256':sha(patchfile.read_bytes())},
  'projection':str(work.relative_to(ROOT)),'changes':changes,'etc_top_level_policy':entries,'static_nodes':nodes,
  'syntax_checks':'BusyBox ash -n only; no vendor scripts executed',
  'boot_order':'Original rc3.d names and relative symlinks retained exactly',
  'dangling_original_boot_links':dangling,
  'native_requirements':['bsp-ownership --require verifies private namespace, base storage proof, native defaults/AI mount UUID policy, udev and static nodes before any BSP script.',
   'device-event dispatcher validates fixed callback names, waits for native udev nodes on add, then invokes rc inside the inherited private namespace.',
   'Package ROM projection and private etc seed explicitly; never unpack this over native Ubuntu /etc.',
   'Original S50ssl dangling link is retained as not applicable: stock launcher logs/ignores its failure; ASUS HTTPS uses start_httpd -> prepare_cert_in_etc -> httpds independently.',
   'Stock BCM launcher logs/ignores every script failure; full boot acceptance must verify actual script and service outcomes, not launcher exit0.',
   'Firmware rollback health acknowledgement now belongs to native final-health gate; no early boot_failed_count reset.',
   'Manufacturing mode, erase_psi and defaults programming fail closed; normal new/old recovery writes data only. Firmware-template fallback uses a private read-only /mnt/nvram view and never writes defaults.',
   'Package a real /mnt/nvram directory; private template view cannot mount onto the stock dangling symlink. Missing factory and ROM calibration sources still require recovery.'],
  'preserved':['hndnvram normal populate/restore-to-data logic','driver and Wi-Fi script bytes/order','USB/net callback routing','ASUS service private configuration resources'],
  'removed_ownership_conflicts':['mount/umount-all and mount_data repair/format fallbacks','partitioncfg repartition/format/reboot','mdev/static-node mutation from projected resources','kernel modprobeX','raw-offset MMC crash writer and global VM/core settings','legacy profile remount and LD_LIBRARY_PATH'],
  'actual_asus_services_executed':False,'flash_allowed':False,'builder_sha256':sha(Path(__file__).read_bytes())}
 (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 (ROOT/'reports/ubuntu26/asus-bsp-resource-ownership.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'projection':str(work),'changed_resources':len(changes),'static_nodes':len(nodes),'dangling_boot_links':dangling,'flash_allowed':False}))


if __name__=='__main__':main()
