#!/usr/bin/env python3
"""Validate visibility semantics and event transitions without touching hardware."""
import json,subprocess,tempfile,copy
from pathlib import Path
r=Path(__file__).resolve().parents[1];p=r/'evidence/network-overview';checks=[]
def check(name,ok):
 assert ok,name
 checks.append(name)
base=json.loads((p/'status-before.json').read_text());base['monotonic']=1000;base['seen']=200000;base['uptime_s']=900000
fixtures={n:json.loads((p/(n+'.json')).read_text()) for n in ['leases','arp','fdb','neighbors']}
def run(status=None,previous=None,replace=None):
 with tempfile.TemporaryDirectory() as td:
  d=Path(td);items={**fixtures,**(replace or {}),'previous':previous or {}}
  cmd=['jq','-c']
  for n,v in items.items():
   (d/n).write_text(json.dumps(v));cmd+=['--slurpfile',n,str(d/n)]
  out=subprocess.run(cmd+['-f',str(r/'configs/ccr-status/network.jq')],input=json.dumps(status or base),text=True,capture_output=True)
  assert out.returncode==0,out.stderr
  return json.loads(out.stdout)
a=run();check('LAN-only inventory has unique MAC keys',len({d['mac'] for d in a['network']['devices']})==len(a['network']['devices']) and all(ip.startswith('192.168.100.') for d in a['network']['devices'] for ip in d['ips']))
check('Old ASUS ARP address is not shown as current',next(d for d in a['network']['devices'] if d['mac']=='02:00:00:F0:00:01')['ips']==['192.168.100.15'] and '192.168.100.38' in next(d for d in a['network']['devices'] if d['mac']=='02:00:00:F0:00:01')['cached_ips'])
check('ASUS loopback LLDP address resolved using same-MAC ARP',next(p for p in a['network']['peers'] if p['name']=='GT-BE98')['ip']=='192.168.100.10')
check('MNDP/CDP visibility is not asserted to be LLDP adjacency',next(p for p in a['network']['peers'] if p['name']=='CRS418')['kind']=='discovered')
check('Unused ports do not trigger alarms',not a['network']['issues'])
fake=[{'mac-address':'02:00:00:00:00:01','address':'192.168.100.60','host-name':'old <img src=x onerror=alert(1)>','status':'waiting'}, {'mac-address':'02:00:00:00:00:02','address':'192.168.100.61','active-address':'192.168.100.61','status':'bound'}]
b=run(replace={'leases':fake,'arp':[],'fdb':[],'neighbors':[]})
check('Reservations and bound leases alone remain unconfirmed',all(d['state']=='unknown' for d in b['network']['devices']))
check('Inactive reservation is separate from an observed IP',b['network']['devices'][0]['ips']==[] and b['network']['devices'][0]['reserved_ip']=='192.168.100.60')
check('Hostname is data, unchanged rather than interpreted',b['network']['devices'][0]['name']==fake[0]['host-name'])
b=run(replace={'leases':[],'arp':[], 'fdb':[{'mac-address':'02:00:00:00:00:03','local':'false','bridge':'lan','on-interface':'bond-c1000'},{'mac-address':'02:00:00:00:00:03','local':'false','bridge':'lan','on-interface':'sfp28-3'}],'neighbors':[]})
check('Ambiguous MAC paths retain both observations',b['network']['devices'][0]['via']==['bond-c1000','sfp28-3'])
nexts=copy.deepcopy(base);nexts['seen']+=30;nexts['monotonic']+=30;nexts['uptime_s']+=30
next(p for p in nexts['ports'] if p['name']=='sfp28-3')['up']=False
b=run(nexts,a)
check('Observed link loss emits event and current issue',any(e['kind']=='link-down' and e['target']=='sfp28-3' for e in b['network']['events']) and any(e['kind']=='link-down' and e['target']=='sfp28-3' for e in b['network']['issues']))
nexts['seen']+=30;nexts['monotonic']+=30;nexts['uptime_s']+=30;c=run(nexts,b)
check('Unchanged disconnected link does not flood events',c['network']['events']==b['network']['events'])
next(p for p in nexts['ports'] if p['name']=='sfp28-3')['up']=True;nexts['seen']+=30;nexts['monotonic']+=30;nexts['uptime_s']+=30;d=run(nexts,c)
check('Link restoration clears current issue and records recovery',not any(e['kind']=='link-down' for e in d['network']['issues']) and d['network']['events'][0]['kind']=='link-up')
nexts['uptime_s']=10;e=run(nexts,d)
check('CCR restart resets expected links and records reboot',any(e['kind']=='reboot' for e in e['network']['events']))
nexts=copy.deepcopy(base);nexts['seen']+=1000;nexts['monotonic']+=1000;nexts['uptime_s']+=1000;nexts['ports'][0]['rx_errors']=99
b=run(nexts,a)
check('Collection gap does not invent per-sample counter alarms',not any(e['kind']=='counter' for e in b['network']['issues']) and b['network']['events'][0]['kind']=='gap')
nexts=copy.deepcopy(base);nexts['errors']=['routes','ethernet','leases','arp','fdb','neighbors'];nexts['wan']=[];nexts['ports']=[]
b=run(nexts,a,replace={n:{} for n in fixtures})
check('Missing tables produce a collection warning, not false WAN/link loss',len(b['network']['issues'])==1 and b['network']['issues'][0]['kind']=='collection' and not b['network']['devices'])
nexts=copy.deepcopy(base);nexts['seen']+=30;nexts['monotonic']+=30;nexts['uptime_s']+=30;nexts['ports'][0]['rx_errors']=5
b=run(nexts,a)
check('Counter increases become alerts with actual delta',any(i['kind']=='counter' and i['detail']=='rx_errors' and i['value']==5 for i in b['network']['issues']))
large=[{'mac-address':f'02:01:00:00:{i//256:02X}:{i%256:02X}','address':f'192.168.100.{i%254+1}','host-name':'字'*500,'status':'waiting'} for i in range(220)]
b=run(replace={'leases':large,'arp':[],'fdb':[],'neighbors':[]})
check('Inventory truncation is explicit and payload bounded',b['network']['total']==220 and len(b['network']['devices'])==160 and b['network']['truncated'] and len(json.dumps(b,ensure_ascii=False).encode())<131072)
report={'passed':len(checks),'checks':checks};(r/'reports/ui-audit/network-overview-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
