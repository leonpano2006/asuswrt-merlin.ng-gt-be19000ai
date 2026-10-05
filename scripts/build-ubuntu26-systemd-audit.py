#!/usr/bin/env python3
"""Validate every control archive before accepting a versioned systemd candidate."""
import hashlib,json,pathlib,re,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-systemd';E=pathlib.Path('/tmp/be19000ai-ubuntu26-systemd-env/work');V='259.5-0ubuntu3.4+leonb53.2'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fields(s):
 d={};key=None
 for line in s.splitlines():
  if line.startswith(' '):d[key]+='\n'+line
  elif ': ' in line:key,value=line.split(': ',1);d[key]=value
 return d
report=R/'reports/ubuntu26/systemd-credentials-build.json';record=json.loads(report.read_text())
record['build_result']=json.loads((W/'build.json').read_text());assert record['build_result']['returncode']==0
record['packages']=[];controls=W/('controls-'+V);controls.mkdir(exist_ok=True)
counts={'packages':0,'control_files':0,'maintainer_scripts':0,'trigger_files':0,'trigger_directives':0,'md5sum_entries':0,'conffile_entries':0}
for f in sorted((W/'packages').glob('*_'+V+'_*.deb')):
 c=fields(subprocess.check_output(['dpkg-deb','-f',str(f)],text=True));assert c['Version']==V
 dest=controls/c['Package'];dest.mkdir(exist_ok=True);subprocess.run(['dpkg-deb','-e',str(f),str(dest)],check=True)
 for m in dest.iterdir():
  assert m.is_file() and not m.is_symlink(),m
  text=m.read_text();counts['control_files']+=1
  assert not re.search(r'^(find:|dpkg-deb: error:|/bin/(?:ba)?sh:|Traceback \(most recent call last\):)',text,re.M),(m,'build diagnostic in metadata')
  if m.name in ['preinst','postinst','prerm','postrm','config']:
   assert re.fullmatch(r'#!/bin/sh(?: -e)?',text.splitlines()[0]),m
   assert m.stat().st_mode & 0o111,m
   subprocess.run(['/bin/sh','-n',str(m)],check=True);counts['maintainer_scripts']+=1
  elif m.name=='triggers':
   counts['trigger_files']+=1
   for line in text.splitlines():
    if not line.strip() or line.lstrip().startswith('#'):continue
    assert re.fullmatch(r'(interest|activate)(-await|-noawait)?\s+\S+',line),(m,line)
    counts['trigger_directives']+=1
  elif m.name=='md5sums':
   for line in text.splitlines():
    assert re.fullmatch(r'[0-9a-f]{32}  [^\n]+',line),(m,line)
    p=pathlib.PurePosixPath(line[34:]);assert not p.is_absolute() and '..' not in p.parts,(m,p)
    counts['md5sum_entries']+=1
  elif m.name=='conffiles':
   for line in text.splitlines():
    parts=line.split();assert len(parts) in (1,2) and parts[0].startswith('/'),(m,line)
    if len(parts)==2:assert parts[1]=='remove-on-upgrade',(m,line)
    assert '..' not in pathlib.PurePosixPath(parts[0]).parts,(m,line)
    counts['conffile_entries']+=1
 counts['packages']+=1
 record['packages'].append({'path':str(f.relative_to(R)),'sha256':sha(f),'bytes':f.stat().st_size,'control':c,'triggers':(dest/'triggers').read_text() if (dest/'triggers').exists() else None,'control_members':{m.name:sha(m) for m in sorted(dest.iterdir())},'maintainer_scripts':{n:sha(dest/n) for n in ['preinst','postinst','prerm','postrm'] if (dest/n).exists()}})
assert counts['packages']==30,counts
minimal=['systemd','systemd-sysv','udev','libsystemd-shared','libsystemd0','libudev1']
record['minimal_runtime_packages']=[x['path'] for x in record['packages'] if x['control']['Package'] in minimal];assert len(record['minimal_runtime_packages'])==6
for n in ['ccache-stats.txt','build-environment.tsv']:shutil.copyfile(E/n,W/n)
for pattern in ['systemd_'+V+'_*.buildinfo','systemd_'+V+'_*.changes']:
 for f in E.glob(pattern):shutil.copyfile(f,W/f.name)
record['status']='metadata_validated_isolated_apt_pending';record['candidate_version']=V
record['metadata_validation']={'result':'pass','counts':counts,'checks':['dpkg-deb Deb822 parser and exact version for every package','Every control file scanned for producer diagnostics','All shell maintainer scripts executable with valid shebang and sh -n','Every trigger directive parsed against dpkg grammar','All md5sum and conffile entries syntax and relative/absolute path checks']}
record['scope']='Local source/build namespace only; router and kernel10 unchanged; original Ubuntu rootfs unchanged. Parent owns full-system credential acceptance.'
record['patch_sha256']=sha(R/record['patch']);record['build_script_sha256']=sha(R/'scripts/build-ubuntu26-systemd.py');record['audit_script_sha256']=sha(pathlib.Path(__file__))
record['build_log']='build/ubuntu26-systemd/build.log';record['build_log_sha256']=sha(W/'build.log');record['ccache_stats']='build/ubuntu26-systemd/ccache-stats.txt';record['package_signature']='Local unsigned candidate artifacts; not a published/signed repository.'
record.pop('rejection_reason',None)
report.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'status':record['status'],'counts':counts,'minimal_runtime_packages':record['minimal_runtime_packages']},indent=2))
