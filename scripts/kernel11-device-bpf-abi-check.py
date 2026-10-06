#!/usr/bin/env python3
"""Compare device-only BPF against the frozen, accepted kernel10 ABI."""
import hashlib,importlib.util,json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
K=R/'source/release/src-rt-5.04behnd.4916/kernel/linux-4.19'
W=R/'build/kernel11-device-bpf/abi';W.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('audit',R/'scripts/time64-abi-check.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
basepath=R/'build/kernel10/candidate-full.json';base=json.loads(basepath.read_text())
assert base['vmlinux_sha256']==json.loads((R/'reports/kernel10/abi-check.json').read_text())['candidate_vmlinux_sha256']
new=a.capture(K/'vmlinux',K/'.config',K/'Module.symvers')
(W/'candidate-full.json').write_text(json.dumps(new,indent=2)+'\n')
norm=lambda variants:sorted(json.dumps(v['layout'],sort_keys=True) for v in variants)
changes=[name for name,variants in base['layout']['types'].items() if norm(variants)!=norm(new['layout']['types'].get(name,[]))]
allowed={'structure cgroup_bpf','structure cgroup','structure cgroup_root'}
protected={'structure task_struct','structure sock','structure net_device','structure sk_buff','structure user_struct'}
assert protected <= set(base['layout']['types'])
assert protected <= set(new['layout']['types'])
protected_changes=[name for name in protected if norm(base['layout']['types'][name])!=norm(new['layout']['types'][name])]
unexpected=[x for x in changes if x not in allowed]
exports=[name for name,kind in base['elf_exports']['symbols'].items() if new['elf_exports']['symbols'].get(name)!=kind]
dispatch=[];bpf_entries=[]
for name,oldentries in base['dispatch']['tables'].items():
 entries=new['dispatch']['tables'][name];assert len(entries)==len(oldentries)
 bpfno=280 if name=='sys_call_table' else 386
 for old in oldentries:
  now=entries[old['number']]
  if old['number']==bpfno:
   bpf_entries.append({'table':name,'number':bpfno,'handlers':now['handlers'],'pass':now['address']==new['dispatch']['symbols'].get('__arm64_sys_bpf')})
  elif not set(old['handlers'])&set(now['handlers']):dispatch.append({'table':name,'number':old['number'],'old':old['handlers'],'new':now['handlers']})
configchanges={key:[base['config'].get(key),new['config'].get(key)] for key in set(base['config'])|set(new['config']) if base['config'].get(key)!=new['config'].get(key)}
assert new['config'].get('CONFIG_CGROUP_BPF','n')=='n' and new['config'].get('CONFIG_SOCK_CGROUP_DATA','n')=='n'
assert new['config']['CONFIG_GTBE98_CGROUP_ABI']=='y' and new['config']['CONFIG_BCM_CGROUP_DEVICE_BPF']=='y'
assert new['config']['CONFIG_BPF_SYSCALL']=='y'
report={'schema_version':1,'baseline_sha256':hashlib.sha256(basepath.read_bytes()).hexdigest(),'baseline_vmlinux_sha256':base['vmlinux_sha256'],'candidate_vmlinux_sha256':new['vmlinux_sha256'],
 'layout_changes':changes,'allowed_internal_cgroup_changes':sorted(allowed),'unexpected_layout_changes':unexpected,'protected_layout_changes':protected_changes,'old_export_changes':exports,'old_dispatch_changes':dispatch,'bpf_dispatch':bpf_entries,'config_changes':configchanges,
 'changed_internal_layouts':{name:{'before':base['layout']['types'][name],'after':new['layout']['types'].get(name,[])} for name in changes if name in allowed},
 'limits':['Recorded complete named DWARF layouts and existing exports only; not proof of every proprietary ABI access','Allow/deny enforcement requires a separate runtime test; symbol presence alone is insufficient','Hardware startup must still be verified before claiming live container support']}
report['pass']=not any([unexpected,protected_changes,exports,dispatch]) and len(bpf_entries)==2 and all(x['pass'] for x in bpf_entries)
(W/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='changed_internal_layouts'},indent=2))
raise SystemExit(0 if report['pass'] else 1)
