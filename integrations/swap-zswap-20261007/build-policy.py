#!/usr/bin/env python3
import hashlib,json,subprocess
from pathlib import Path
B=Path(__file__).resolve().parent;W=B/'policy-v1';W.mkdir(exist_ok=False);S=W/'package-stage';D=S/'DEBIAN';D.mkdir(parents=True)
uuid='104f78ec-d147-4a50-9218-b847c6c3748b'
unit=subprocess.check_output(['systemd-escape','--path','--suffix=swap','/dev/disk/by-uuid/'+uuid],text=True).strip()
script='''#!/bin/sh
set -eu
base=/sys/module/zswap/parameters
for parameter in compressor zpool max_pool_percent enabled; do
    test -r "$base/$parameter"
    test -w "$base/$parameter"
done
# Same-valued writes are skipped; enabling is the final step.
configure() {
    current=$(cat "$base/$1")
    if test "$current" != "$2"; then printf '%s\\n' "$2" > "$base/$1"; fi
    test "$(cat "$base/$1")" = "$2"
}
configure compressor zstd
configure zpool zsmalloc
configure max_pool_percent 30
case "$(cat "$base/enabled")" in Y|1) ;; *) printf '1\\n' > "$base/enabled" ;; esac
case "$(cat "$base/enabled")" in Y|1) ;; *) exit 1 ;; esac
printf 'zswap enabled: compressor=zstd zpool=zsmalloc max_pool_percent=30\\n'
'''
p=S/'usr/libexec/leon-memory/zswap-setup';p.parent.mkdir(parents=True);p.write_text(script);p.chmod(0o755)
units=S/'usr/lib/systemd/system';units.mkdir(parents=True)
(units/'leon-zswap.service').write_text('''[Unit]
Description=Configure BCM zswap with zstd before swap activation
DefaultDependencies=no
Before=swap.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/leon-memory/zswap-setup
RemainAfterExit=yes
TimeoutStartSec=10s

[Install]
WantedBy=swap.target
''')
drop=units/(unit+'.d');drop.mkdir();(drop/'20-leon-zswap.conf').write_text('''[Unit]
Requires=leon-zswap.service
After=leon-zswap.service
''')
doc=S/'usr/share/doc/leon-bcm-zswap-policy';doc.mkdir(parents=True)
line=f'UUID={uuid} none swap sw,pri=10,nofail,x-systemd.device-timeout=10s 0 0'
(doc/'ssd-swap.fstab').write_text(line+'\n')
(doc/'README').write_text('Native BCM Ubuntu memory policy: zswap uses built-in zstd and zsmalloc, retaining the qualified kernel default 30% RAM compressed-pool cap. The existing SSD swap signature is reused by UUID; no formatting or partition changes. The systemd UUID swap unit Requires/After the setup service. zsmalloc in this 4.19 tree does not evict cached pages to disk when full; new pages can use backing SSD swap. vm.swappiness and vm.page-cluster remain unchanged. No boot-slot activation or guardian ACK.\n')
version='0.1+20261007.1'
(D/'control').write_text(f'Package: leon-bcm-zswap-policy\nVersion: {version}\nArchitecture: all\nMulti-Arch: foreign\nSection: admin\nPriority: optional\nDepends: systemd (>= 259), util-linux\nMaintainer: Leon BCM Project <noreply@localhost>\nDescription: BCM zswap zstd policy and UUID SSD swap ordering\n Enables the qualified built-in zstd zsmalloc pool before SSD swap.\n')
files=[p for p in sorted(S.rglob('*')) if p.is_file() and 'DEBIAN' not in p.relative_to(S).parts]
(D/'md5sums').write_text(''.join(hashlib.md5(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(S))+'\n' for p in files))
for p in [S,*S.rglob('*')]:
 if p.is_dir():p.chmod(0o755)
 elif p != S/'usr/libexec/leon-memory/zswap-setup':p.chmod(0o644)
deb=W/f'leon-bcm-zswap-policy_{version}_all.deb';subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','-z6','--build',str(S),str(deb)],check=True)
m={'package':{'path':str(deb),'sha256':hashlib.sha256(deb.read_bytes()).hexdigest(),'bytes':deb.stat().st_size,'name':'leon-bcm-zswap-policy','version':version},'swap_uuid':uuid,'swap_unit':unit,'fstab_entry':line,'zswap':{'enabled':True,'compressor':'zstd','zpool':'zsmalloc','max_pool_percent':30},'kernel_rebuild':False,'maintainer_scripts':False,'no_format_or_partition_change':True}
(W/'manifest.json').write_text(json.dumps(m,indent=2)+'\n');print(json.dumps(m,indent=2))
