#!/usr/bin/env python3
"""Package SSH convenience commands; no maintainer scripts or activation."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/asus-command-access/package-v2'
OUT.mkdir(parents=True,exist_ok=False)
stage=OUT/'root'
source=ROOT/'scripts/asus-integration/command-access/asus'
dest=stage/'usr/bin/asus'; dest.parent.mkdir(parents=True)
shutil.copyfile(source,dest); dest.chmod(0o755)
aliases={'usr/bin/nvram':'asus','usr/sbin/wl':'../bin/asus','usr/sbin/ethctl':'../bin/asus','usr/sbin/rc':'../bin/asus','usr/sbin/asus-service':'../bin/asus'}
for path,target in aliases.items():
 p=stage/path;p.parent.mkdir(parents=True,exist_ok=True);p.symlink_to(target)
control=stage/'DEBIAN';control.mkdir()
(control/'control').write_text('''Package: leon-asus-command-access
Version: 0.1+leonb53.1
Architecture: all
Section: admin
Priority: optional
Maintainer: BE19000AI local integration <local@invalid>
Depends: bash, coreutils, util-linux, systemd, leon-asus-integration, leon-asus-command-map
Description: Native SSH entry for broker-owned ASUS commands
 Adds namespace-aware nvram, wl, ethctl and broker rc conveniences.
 ASUS service remains available as asus service or asus-service.
 No service restart, sudo policy change or global library configuration.
''')
deb=OUT/'leon-asus-command-access_0.1+leonb53.1_all.deb'
for p in [stage,*stage.rglob('*')]:
 if p.is_symlink(): continue
 p.chmod(0o755 if p.is_dir() or p==dest else 0o644)
subprocess.run(['dpkg-deb','--root-owner-group','-Zzstd','--build',str(stage),str(deb)],check=True)
archive=[]
for p in [stage,*stage.rglob('*')]:
 if p==stage or 'DEBIAN' in p.relative_to(stage).parts: continue
 row={'path':'/'+str(p.relative_to(stage)),'mode':0o777 if p.is_symlink() else 0o755 if p.is_dir() or p==dest else 0o644,'type':'symlink' if p.is_symlink() else 'directory' if p.is_dir() else 'regular'}
 if p.is_symlink():row['target']=str(p.readlink())
 elif p.is_file():row['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
 archive.append(row)
manifest={'package':{'name':'leon-asus-command-access','version':'0.1+leonb53.1','architecture':'all','path':str(deb.relative_to(ROOT)),'sha256':hashlib.sha256(deb.read_bytes()).hexdigest()},'archive':archive,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'aliases':aliases,'maintainer_scripts':False,'automatic_activation':False,'native_service_replaced':False}
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
