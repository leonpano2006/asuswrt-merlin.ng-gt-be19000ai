#!/usr/bin/env python3
"""Map unresolved standalone DSOs to actual application export scopes."""
import argparse,importlib.util,json
from pathlib import Path
R=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('audit',R/'scripts/audit-asus-closure.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
p=argparse.ArgumentParser();p.add_argument('--projection',type=Path,required=True);args=p.parse_args()
j=json.loads(args.projection.read_text());stage=args.projection.parent/'stage';meta,_=a.inventory_directory(stage)
checks={x['target']:x for x in j['static_closure']};apps=[x['target'] for x in j['files'] if x['kind']=='application' and not checks[x['target']]['unresolved_symbols']]
def exports(root):return {n for p in checks[root]['closure'] if p in meta for n,v in meta[p]['_exports']}
ex={p:exports(p) for p in checks};plans=[];unresolved=[]
for target,x in checks.items():
 if not x['unresolved_symbols']:continue
 required={i['name'] for i in x['unresolved_symbols']}
 preferred=[]
 if '/ipsec/plugins/' in target:preferred=['/usr/libexec/asus/vendor/usr/lib/ipsec/charon']
 elif '/l2tp/' in target:preferred=['/usr/libexec/asus/vendor/usr/sbin/l2tpd']
 elif '/pppd/' in target:preferred=['/usr/libexec/asus/vendor/usr/sbin/pppd']
 elif Path(target).name.startswith('mod_'):preferred=['/usr/libexec/asus/vendor/usr/sbin/lighttpd']
 elif '/libnl/cli/' in target:
  # These CLI modules are shipped without any libnl CLI executable. A library
  # scope verifies their registration ABI; actual CLI use remains absent.
  preferred=['/usr/lib/arm-linux-gnueabi/asus/libnl-cli-3.so.200.20.0']
 for owner in preferred+[p for p in apps if target in checks[p]['closure']]:
  if (target in checks[owner]['closure'] and not checks[owner]['unresolved_symbols']) or required <= ex[owner]|ex[target]:break
 else:
  unresolved.append({'target':target,'missing_symbols':sorted(required),'preferred_missing':{p:sorted(required-ex[p]-ex[target]) for p in preferred}});continue
 plans.append({'target':target,'owner':owner,'method':'LD_PRELOAD plugin into actual owner loader trace; no main or constructors','ownership_evidence':'known plugin family' if owner in preferred else 'DT_NEEDED closure includes DSO','symbols_supplied_by_owner':sorted(required)})
report={'projection':str(args.projection),'plans':plans,'unresolved':unresolved,'constructors_or_plugins_executed':False}
(args.projection.parent/'plugin-plan.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'plans':len(plans),'unresolved':unresolved},indent=2))
