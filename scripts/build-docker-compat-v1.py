#!/usr/bin/env python3
"""Package Docker-only legacy iptables selection for the BCM kernel profile."""
import hashlib,json,os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'build/ubuntu26-docker-compat/v1';W.mkdir(parents=True,exist_ok=False)
os.umask(0o022)
stage=W/'stage';(stage/'DEBIAN').mkdir(parents=True)
tools=stage/'usr/libexec/leon-docker-netfilter';tools.mkdir(parents=True)
for family in ['iptables','ip6tables']:
 for suffix in ['', '-save', '-restore']:
  (tools/(family+suffix)).symlink_to('/usr/sbin/'+family+'-legacy'+suffix)
unit=stage/'etc/systemd/system/docker.service.d';unit.mkdir(parents=True)
(unit/'10-bcm-legacy-netfilter.conf').write_text('[Service]\nEnvironment="PATH=/usr/libexec/leon-docker-netfilter:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"\nExecStartPre=/usr/bin/test -x /usr/sbin/iptables-legacy\nExecStartPre=/usr/bin/test -x /usr/sbin/ip6tables-legacy\n')
config=stage/'etc/docker';config.mkdir(parents=True)
(config/'daemon.json').write_text(json.dumps({'firewall-backend':'iptables','ip-forward-no-drop':True},indent=2)+'\n')
doc=stage/'usr/share/doc/leon-docker-bcm-compat';doc.mkdir(parents=True)
(doc/'README').write_text('BCM kernel10 lacks nftables IPv4 NAT support. Select legacy tools only in the Docker service PATH.\nDocker keeps firewall/NAT management enabled and does not change the host FORWARD policy to DROP.\nGlobal iptables alternatives are unchanged. Install executes no service or firmware action.\nSources: https://docs.docker.com/engine/network/packet-filtering-firewalls/\n')
(stage/'DEBIAN/control').write_text('Package: leon-docker-bcm-compat\nVersion: 0.1+leonb53.1\nArchitecture: all\nSection: admin\nPriority: optional\nMaintainer: Leon BCM Project <noreply@localhost>\nDepends: iptables (>= 1.8), docker-ce | docker.io\nDescription: Docker networking compatibility for the BCM kernel profile\n Scoped legacy iptables selection and router forwarding policy preservation.\n No global alternatives or service actions in maintainer scripts.\n')
(stage/'DEBIAN/conffiles').write_text('/etc/docker/daemon.json\n/etc/systemd/system/docker.service.d/10-bcm-legacy-netfilter.conf\n')
sums=[]
for f in sorted(stage.rglob('*')):
 if f.is_symlink():continue
 f.chmod(0o755 if f.is_dir() else 0o644)
 if f.is_file() and 'DEBIAN' not in f.relative_to(stage).parts:sums.append(hashlib.md5(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(stage)))
stage.chmod(0o755)
(stage/'DEBIAN/md5sums').write_text('\n'.join(sums)+'\n')
deb=W/'leon-docker-bcm-compat_0.1+leonb53.1_all.deb'
subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(stage),str(deb)],check=True)
report={'schema_version':1,'packages':[{'name':'leon-docker-bcm-compat','version':'0.1+leonb53.1','architecture':'all','path':str(deb.relative_to(R)),'sha256':hashlib.sha256(deb.read_bytes()).hexdigest(),'bytes':deb.stat().st_size}], 'maintainer_scripts':False,'global_alternatives_changed':False,'container_runtime_proven':False}
(W/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
