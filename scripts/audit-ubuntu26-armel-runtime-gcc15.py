#!/usr/bin/env python3
"""Audit archive ownership/ELF ABI for the newly built ARMEL package set."""
import hashlib,importlib.util,io,json,os,stat,subprocess,tarfile,tempfile
from pathlib import Path
R=Path(__file__).resolve().parents[1];W=R/'build/ubuntu26-armel-runtime-gcc15'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('crypt_audit',R/'scripts/build-asus-libcrypt-compat.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def compare(old,new):
 a=m.inspect_elf(old);b=m.inspect_elf(new);missing=sorted(set(a['exports'])-set(b['exports']));changes={};incompat=[]
 for name,x in a['exports'].items():
  y=b['exports'].get(name)
  if not y:continue
  if x!=y:changes[name]={'old':x,'new':y}
  if any(x[k]!=y[k] for k in ['type','object_size','visibility']):incompat.append(name)
  if x['binding']!=y['binding'] and (x['binding'],y['binding'])!=('STB_WEAK','STB_GLOBAL'):incompat.append(name+':binding')
 return {'old_sha256':sha(old),'new_sha256':sha(new),'old_exports':len(a['exports']),'new_exports':len(b['exports']),'missing_exports':missing,'incompatible_exports':incompat,'export_changes':changes,'old_elf':a,'new_elf':b}
def main():
 packages=json.loads((W/'packages.json').read_text())['packages'];out={'schema_version':1,'packages':[]};extracted={}
 temp=Path(tempfile.mkdtemp(prefix='armel-package-audit-'));vendor=R/'build/kernel9-ui1-rootfs'
 for rec in packages:
  p=R/rec['path'];assert sha(p)==rec['sha256'];key=rec['name']+':'+rec['architecture'];root=temp/key;root.mkdir();extracted[key]=root
  subprocess.run(['dpkg-deb','-x',p,root],check=True)
  data=subprocess.check_output(['dpkg-deb','--fsys-tarfile',p]);members=[];elfs=[]
  with tarfile.open(fileobj=io.BytesIO(data)) as tf:
   for member in tf:
    name=member.name.removeprefix('./');assert not name.startswith('/') and '..' not in Path(name).parts
    q=root/name;assert member.uid==member.gid==0 and not (member.isdev() or member.isfifo())
    row={'path':name,'mode':oct(member.mode),'uid':member.uid,'gid':member.gid,'type':member.type.decode()}
    if member.issym():row['target']=member.linkname;assert q.is_symlink() and os.readlink(q)==member.linkname
    elif member.isfile():
     blob=tf.extractfile(member).read();row['sha256']=hashlib.sha256(blob).hexdigest();assert sha(q)==row['sha256']
     if blob.startswith(b'\x7fELF'):
      e=m.inspect_elf(q);assert e['machine']==('EM_ARM' if rec['architecture']=='armel' else 'EM_AARCH64'),(key,name)
      # glibc gconv modules intentionally resolve sibling conversion DSOs.
      assert not e['rpath_runpath'] or ('/gconv/' in name and e['rpath_runpath']==['<DynamicTag (DT_RUNPATH) "$ORIGIN">']),(key,name,e['rpath_runpath'])
      if rec['architecture']=='armel':assert e['elf_class']==32 and e['float_abi_flags']==0x200,(key,name,e['float_abi_flags'])
      elfs.append({'path':name,'sha256':sha(q),'machine':e['machine'],'float_abi_flags':e['float_abi_flags'],'needed':e['needed']})
    assert stat.S_IMODE(q.lstat().st_mode)==member.mode,(key,name,oct(q.lstat().st_mode),oct(member.mode))
    members.append(row)
  out['packages'].append({**rec,'control':subprocess.check_output(['dpkg-deb','-f',p],text=True),'roundtrip_passed':True,'members':members,'elf_files':elfs})
 crypt=extracted['libcrypt1:armel']/'usr/lib/arm-linux-gnueabi/libcrypt.so.1.1.0'
 out['vendor_armel_libcrypt']=compare(vendor/'lib/libcrypt.so.1',crypt)
 e=out['vendor_armel_libcrypt'];assert not e['missing_exports'] and not e['incompatible_exports']
 assert not [s for s in e['new_elf']['imports'] if s.endswith('@GLIBC_PRIVATE')]
 oldnative=temp/'old-native-libcrypt'
 with tarfile.open(R/'build/ubuntu26-rootfs/ubuntu26-bcm-gnu-systemd-openssh-b53-v3.tar') as tf:
  candidates=[x for x in tf if x.isfile() and x.name.endswith('/aarch64-linux-gnu/libcrypt.so.1.1.0')];assert len(candidates)==1
  oldnative.write_bytes(tf.extractfile(candidates[0]).read())
 out['native_libcrypt_allowlisted_upgrade']=compare(oldnative,extracted['libcrypt1:arm64']/'usr/lib/aarch64-linux-gnu/libcrypt.so.1.1.0')
 e=out['native_libcrypt_allowlisted_upgrade'];assert not e['missing_exports'] and not e['incompatible_exports'];assert not e['export_changes']
 libs=extracted['leon-gcc15-runtime:armel']/'usr/lib/arm-linux-gnueabi'
 out['legacy_gcc_runtime_exports']={}
 for name in ['libgcc_s.so.1','libstdc++.so.6']:
  e=compare(vendor/'lib'/name,libs/name);out['legacy_gcc_runtime_exports'][name]=e
  if name=='libgcc_s.so.1':
   assert not e['missing_exports'] and not e['incompatible_exports']
   continue
  policy_path=R/'configs/ubuntu26/armel-libstdcxx-abi-delta.json';policy=json.loads(policy_path.read_text())
  assert e['old_sha256']==policy['baseline_sha256']
  assert set(e['missing_exports'])==set(policy['missing_inline_exports'])
  assert set(e['export_changes'])==set(policy['binding_changes'])|set(policy['default_version_changes'])
  for name in e['missing_exports']:
   assert e['old_elf']['exports'][name]['binding']=='STB_WEAK' and e['old_elf']['exports'][name]['type']=='FUNCTION'
  for name,change in e['export_changes'].items():
   old,new=change['old'],change['new'];allowed=dict(old)
   for field,key in [('binding','binding_changes'),('hidden_version','default_version_changes')]:
    if name in policy[key]:
     assert [old[field],new[field]]==policy[key][name]
     allowed[field]=new[field]
   assert allowed==new,name
  consumers=[];scanned=0;self_definitions=[]
  missing_names=[x.split('@')[0].encode() for x in e['missing_exports']]
  for file in vendor.rglob('*'):
   if file.is_symlink() or not file.is_file():continue
   data=file.read_bytes()
   if data[:4]==b'\x7fELF' and (data[4]!=1 or int.from_bytes(data[36:40],'little')&0x600==0x400):continue
   if sha(file)==e['old_sha256']:continue
   # A weak inline implementation emitted into the executable is a provider,
   # not an unresolved dependency or dlsym literal. Account only its exact
   # defining .dynstr string offset, then reject every unexplained occurrence.
   definitions={}
   if data[:4]==b'\x7fELF':
    ef=m.ELFFile(io.BytesIO(data))
    for ds in ef.iter_sections():
     if ds['sh_type'] not in ['SHT_DYNSYM','SHT_SYMTAB']:continue
     strings=ef.get_section(ds['sh_link'])
     for sym in ds.iter_symbols():
      bare=sym.name.split('@')[0].encode()
      if sym['st_shndx']!='SHN_UNDEF' and bare in missing_names:
       offset=strings['sh_offset']+sym['st_name'];definitions[offset]=bare
       self_definitions.append({'path':str(file.relative_to(vendor)),'symbol':sym.name,'table':ds.name,'defined_section':sym['st_shndx'],'string_file_offset':offset,'binding':sym['st_info']['bind']})
   for symbol in missing_names:
    start=0
    while True:
     offset=data.find(symbol+b'\0',start)
     if offset<0:break
     assert definitions.get(offset)==symbol,(file,symbol.decode(),offset)
     start=offset+len(symbol)
   scanned+=1
   if data[:4]==b'\x7fELF' and ef.get_section_by_name('.dynsym') and ef.get_section_by_name('.dynamic'):
    elf=m.inspect_elf(file)
    if 'libstdc++.so.6' in elf['needed']:
     required=sorted(x for x in elf['imports'] if '@GLIBCXX_' in x or '@CXXABI_' in x)
     assert not set(required)-set(e['new_elf']['exports']),(file,set(required)-set(e['new_elf']['exports']))
     consumers.append({'path':str(file.relative_to(vendor)),'sha256':sha(file),'required_exports':required})
  e.update(reviewed_delta_policy=str(policy_path.relative_to(R)),reviewed_delta_policy_sha256=sha(policy_path),policy_source='BE98 GCC15.2 reviewed ABI delta; exact identical vendor baseline hash and entire delta rechecked here',matching_delta_accepted_for_current_vendor_consumers=True,literal_lookup_scan_files=scanned,self_defined_weak_inline_symbols=self_definitions,current_cpp_consumers=consumers,external_plugin_compatibility_not_claimed=True)
 out.update(static_package_abi_audit_passed=True,compiler_policy={'path':'configs/ubuntu26/compiler-policy.json','sha256':sha(R/'configs/ubuntu26/compiler-policy.json')},full_upstream_test_suites_run=False,full_asus_runtime_accepted=False,host_packages_modified=False,router_access=False)
 (R/'reports/ubuntu26/armel-runtime-package-audit.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'static_package_abi_audit_passed':True,'packages':len(packages),'native_libcrypt_symbol_changes':len(out['native_libcrypt_allowlisted_upgrade']['export_changes']),'vendor_crypt_old_exports':out['vendor_armel_libcrypt']['old_exports']},indent=2))
if __name__=='__main__':main()
