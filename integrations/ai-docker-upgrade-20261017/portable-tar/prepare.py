import concurrent.futures, hashlib, json, lzma, os, pathlib, re, shutil, subprocess, tarfile, urllib.request
P=pathlib.Path
ROOT=P(__file__).resolve().parent
BASE='https://ports.ubuntu.com/ubuntu-ports/'
WANTED={'tar','libacl1','libselinux1','libpcre2-8-0'}
KEYRING='/usr/share/keyrings/ubuntu-archive-keyring.gpg'
def get(url):
    with urllib.request.urlopen(url,timeout=30) as f:return f.read()
def repo(suite):
    d=ROOT/'metadata'/suite;d.mkdir(parents=True,exist_ok=True)
    release=get(BASE+'dists/'+suite+'/InRelease');(d/'InRelease').write_bytes(release)
    p=subprocess.run(['gpgv','--keyring',KEYRING,str(d/'InRelease')],capture_output=True,text=True)
    (d/'signature-validation.txt').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
    rel='main/binary-arm64/Packages.xz'
    match=re.search(r'^ ([0-9a-f]{64})\s+(\d+)\s+'+re.escape(rel)+r'$',release.decode(),re.M);assert match
    compressed=get(BASE+'dists/'+suite+'/'+rel)
    assert len(compressed)==int(match[2]) and hashlib.sha256(compressed).hexdigest()==match[1]
    (d/'Packages.xz').write_bytes(compressed)
    selected=[]
    for block in lzma.decompress(compressed).decode().split('\n\n'):
        fields={}
        for line in block.splitlines():
            if ': ' in line and not line[0].isspace():
                k,v=line.split(': ',1);fields[k]=v
        if fields.get('Package') in WANTED and fields.get('Architecture')=='arm64':
            selected.append({k:fields[k] for k in ('Package','Version','Architecture','Filename','Size','SHA256')} | {'suite':suite})
    return selected
rows=[]
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    for entries in pool.map(repo,['jammy','jammy-updates','jammy-security']):rows.extend(entries)
chosen={}
for row in rows:
    name=row['Package']
    if name not in chosen or subprocess.run(['dpkg','--compare-versions',row['Version'],'gt',chosen[name]['Version']]).returncode==0:chosen[name]=row
assert set(chosen)==WANTED
extract=ROOT/'extracted';extract.mkdir(exist_ok=True)
for name,row in chosen.items():
    pkg=ROOT/'packages'/P(row['Filename']).name
    data=get(BASE+row['Filename']);assert len(data)==int(row['Size']) and hashlib.sha256(data).hexdigest()==row['SHA256']
    pkg.write_bytes(data)
    subprocess.run(['dpkg-deb','-x',str(pkg),str(extract)],check=True)
payload=ROOT/'payload';(payload/'bin').mkdir(parents=True,exist_ok=True);(payload/'lib').mkdir(exist_ok=True)
shutil.copyfile(extract/'bin/tar',payload/'bin/tar');(payload/'bin/tar').chmod(0o755)
for lib in ('libacl.so.1','libselinux.so.1','libpcre2-8.so.0'):
    matches=list(extract.rglob(lib));assert len(matches)==1,(lib,matches)
    shutil.copyfile(matches[0].resolve(),payload/'lib'/lib);(payload/'lib'/lib).chmod(0o755)
(payload/'tar').write_text('''#!/bin/sh
set -eu
here=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
LD_LIBRARY_PATH="$here/lib"
export LD_LIBRARY_PATH
exec "$here/bin/tar" "$@"
''');(payload/'tar').chmod(0o755)
files={}
for path in [payload/'bin/tar',*sorted((payload/'lib').iterdir())]:
    versions=subprocess.check_output(['readelf','-V',str(path)],text=True)
    required=sorted({tuple(map(int,x.split('.'))) for x in re.findall(r'Name: GLIBC_([0-9.]+)',versions)})
    assert max(required)<=(2,35),(path,required)
    files[str(path.relative_to(payload))]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'max_glibc':'.'.join(map(str,max(required)))}
version=subprocess.check_output([str(payload/'tar'),'--version'],text=True).splitlines()[0]
helptext=subprocess.check_output([str(payload/'tar'),'--help'],text=True)
assert all(x in helptext for x in ('--xattrs','--acls','--one-file-system','--numeric-owner'))
manifest={'source':'Official Ubuntu Jammy ARM64 packages; InRelease gpgv-verified with Ubuntu archive keyring, index and package SHA256 verified','packages':chosen,'files':files,'version':version,'entrypoint':'portable-tar/tar','glibc_provided':False,'maximum_required_glibc':'2.34','target_requirement':'Native aarch64 loader /lib/ld-linux-aarch64.so.1 and glibc >=2.34','local_validation':'Version/options and ELF requirements only; parent performs isolated target xattr/ACL/hardlink roundtrip before any production stop.'}
(payload/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(payload/'README').write_text('Portable GNU tar from signed Ubuntu Jammy arm64 packages.\nRun portable-tar/tar; private libacl/libselinux/libpcre2-8 only.\nNo system files are installed or replaced. Native loader/glibc used.\nPackage/index/signature verification evidence remains in local metadata/.\n')
archive=ROOT.parent/'portable-tar.tar.gz'
with tarfile.open(archive,'w:gz') as tf:tf.add(payload,arcname='portable-tar')
receipt={'archive':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size,**manifest}
(ROOT/'manifest.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
