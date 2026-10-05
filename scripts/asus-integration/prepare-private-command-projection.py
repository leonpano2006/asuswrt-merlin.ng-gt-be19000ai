#!/usr/bin/env python3
"""Prepare reviewed command/absolute-library aliases for a private namespace.

Produces inert overlay lower directories, never global /usr links. Native
conflicts need an explicit policy. Power, flash and legacy boot ownership are
blocked rather than accidentally inherited through a broader vendor PATH.
"""
import argparse, collections, hashlib, json, os, posixpath, re, tarfile
from pathlib import Path
R=Path(__file__).resolve().parents[2]
BLOCKED=set('''ATE bcm_boot_launcher bcm_bootstate bcm_flasher doc_loadbios docfdisk
flash_erase flash_lock flash_otp_erase flash_otp_lock flash_otp_write flash_unlock flashcp
ftl_format mmc mtd_debug mtdpart nandflipbits nandtest nandwrite nftl_format recv_image
rfdformat sgdisk ubiattach ubiblock ubidetach ubiformat ubimkvol ubinize ubirename
ubirmvol ubirsvol ubiupdatevol hnd-erase hnd-write mtd_erase_image_update mtd_erase_misc2
firmware_check_update firmware_webs_update set_factory_mode dropbear dropbearkey
dropbearconvert dropbearmulti dbclient reboot halt poweroff shutdown init telinit
switch_root pivot_root mdev udevtrigger test_disk1 test_disk2 wdtctl'''.split())
# Explicit native ownership even where the vendor spelling is in the other bin
# directory. ip/tc are the only same-path vendor overrides: their Broadcom QoS
# extensions are used by the preserved vendor networking stack.
NATIVE_NAMES=set('''dbus-uuidgen dbus-daemon taskset e2fsck mke2fs tune2fs openssl ssh scp
fsck.ext2 fsck.ext3 fsck.ext4 mkfs.ext2 mkfs.ext3 mkfs.ext4
insmod modprobe rmmod depmod mount umount swapon swapoff'''.split())
VENDOR_COLLISIONS={'ip','tc','service'}
DENIED='/usr/libexec/asus/command-denied'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def usrmerge(s):
    if s.startswith(('/bin/','/sbin/','/lib/')):return '/usr'+s
    return s
def base_inventory(p):
    with tarfile.open(p) as a:return {'/'+x.name.removeprefix('./'):x for x in a if x.name not in ('.','./')}
def resolve_stock(root,path):
    seen=set()
    while True:
        assert path not in seen,path;seen.add(path)
        p=root/path.lstrip('/')
        if not p.is_symlink():return path
        link=os.readlink(p);path=posixpath.normpath(link if link.startswith('/') else posixpath.join(posixpath.dirname(path),link))
def main():
    p=argparse.ArgumentParser();p.add_argument('--projection',type=Path,required=True);p.add_argument('--label',required=True);a=p.parse_args()
    j=json.loads(a.projection.read_text());base=R/j['base']['path'];assert sha(base)==j['base']['sha256']
    out=R/'build/asus-command-projection'/a.label;assert not out.exists();out.mkdir(parents=True)
    stage=out/'payload/usr/share/asus/commands';stage.mkdir(parents=True)
    stock=R/'build/stock-rootfs';basefiles=base_inventory(base)
    actual={x['original']:x for x in j['files']};private={x['target']:x for x in j['files']}
    originals={k:{'original':k,'target':v['target'],'kind':v['kind'],'abi':v['abi']} for k,v in actual.items()}
    applets=R/'build/asus-private-shell/native-v4/applets.txt';available=set(applets.read_text().splitlines())
    for root,dirs,files in os.walk(stock,followlinks=False):
        for name in dirs+files:
            source=Path(root)/name
            if not source.is_symlink():continue
            original='/'+source.relative_to(stock).as_posix()
            if not original.startswith(('/bin/','/sbin/','/usr/bin/','/usr/sbin/','/lib/','/usr/lib/')):continue
            resolved=resolve_stock(stock,original)
            if resolved in actual:
                f=actual[resolved];originals[original]={'original':original,'target':f['target'],'kind':f['kind'],'abi':f['abi']}
            elif resolved=='/bin/busybox':
                if name in available:originals[original]={'original':original,'target':'/usr/libexec/asus/busybox','kind':'busybox','abi':'arm64'}
                elif usrmerge(original) not in basefiles:
                    originals[original]={'original':original,'target':None,'kind':'missing-applet','abi':'arm64'}
    rows=[];mapped={};unknown=[];native_preserved=[]
    def native(name):
        for prefix in ['/usr/sbin/','/usr/bin/']:
            path=prefix+name
            if path in basefiles:return path
        return None
    for original,item in sorted(originals.items()):
        canonical=usrmerge(original);name=posixpath.basename(canonical)
        if not canonical.startswith(('/usr/bin/','/usr/sbin/','/usr/lib/')):continue
        row={**item,'path':canonical,'base_same_path':canonical in basefiles,'installed_globally':False}
        is_command=canonical.startswith(('/usr/bin/','/usr/sbin/'))
        if is_command and name in BLOCKED:
            row.update(policy='blocked-owned-action',target=DENIED,reason='Flash, factory reset, legacy init/device/power, hardware watchdog or Dropbear requires its separate reviewed owner.')
        elif is_command and (name in NATIVE_NAMES or (item['kind']=='busybox' and native(name))):
            target=native(name)
            if target is None:unknown.append(row);continue
            if canonical==target:row.update(policy='keep-native',target=target);native_preserved.append(row);rows.append(row);continue
            row.update(policy='native-compat-alias',target=target)
        elif item['kind']=='missing-applet':
            row.update(policy='unresolved-missing-applet');unknown.append(row);continue
        elif canonical in basefiles:
            if not is_command or name not in VENDOR_COLLISIONS:
                unknown.append(row);continue
            row.update(policy='private-vendor-override',reason='ip/tc retain Broadcom network extensions; service dispatches the scoped ASUS broker.')
        else:
            row['policy']='private-busybox-applet' if item['kind']=='busybox' else 'private-vendor-alias'
        if canonical in mapped:
            # The firmware itself has two libuuid builds. Before usrmerge its
            # /lib copy wins loader search; retain that audited choice for the
            # merged legacy alias, keeping both real private files available.
            if canonical in ['/usr/lib/libuuid.so','/usr/lib/libuuid.so.1']:
                assert mapped[canonical]['original'].startswith('/lib/') and original.startswith('/usr/lib/')
                row.update(policy='coalesced-stock-lib-priority',selected_target=mapped[canonical]['target'])
                rows.append(row);continue
            assert mapped[canonical]['target']==row['target'],(mapped[canonical],row)
            row['coalesced_with']=mapped[canonical]['original'];rows.append(row);continue
        mapped[canonical]=row;rows.append(row)
    # Block native fall-through power commands even if factory did not ship a
    # same-spelling alias. This is a migration policy, not a security sandbox.
    for name in ['reboot','halt','poweroff','shutdown','init','telinit','switch_root','pivot_root']:
        for prefix in ['/usr/sbin/','/usr/bin/']:
            path=prefix+name
            if path in mapped:continue
            if path not in basefiles and prefix=='/usr/bin/':continue
            row={'original':None,'path':path,'target':DENIED,'kind':'control','abi':'arm64','policy':'blocked-owned-action','base_same_path':path in basefiles,'installed_globally':False}
            mapped[path]=row;rows.append(row)
    assert not unknown,'Unreviewed collisions or missing applets: '+json.dumps(unknown)
    for row in mapped.values():
        target=stage/row['path'].removeprefix('/usr/');target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(row['target'])
    for directory in [stage,*[x for x in stage.rglob('*') if x.is_dir() and not x.is_symlink()]]:directory.chmod(0o755)
    counts=collections.Counter(x['policy'] for x in rows)
    report={'schema_version':1,'status':'inert-private-overlay-projection','production_ready':False,
            'source_projection':str(a.projection),'source_projection_sha256':sha(a.projection),
            'base_sha256':j['base']['sha256'],'private_shell_applets_sha256':sha(applets),
            'payload':str((out/'payload').relative_to(R)),'rows':rows,'counts':dict(counts),
            'overlay_mounts':{str(stage/x):'/usr/'+x for x in ['bin','sbin','lib']},
            'path':'/usr/sbin:/usr/bin:/sbin:/bin','no_global_aliases':True,'unknown_collisions':unknown,
            'known_stock_missing_paths':['/bin/pspctl'],
            'limitations':['No alias executes a program during preparation.','Read-only mount layering and native host preservation require namespace tests before activation.','This is an integration policy, not a sandbox against root.','Vendor main, constructor, dlopen runtime behavior and Broadcom hardware remain untested.'],
            'builder_sha256':sha(Path(__file__))}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'aliases':len(mapped),'counts':dict(counts),'manifest':str((out/'manifest.json').relative_to(R))},indent=2))
if __name__=='__main__':main()
