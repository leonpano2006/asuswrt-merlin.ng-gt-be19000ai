#!/usr/bin/env python3
"""Verify counter resets, missing values, API encoding and read-only fixture parsing."""
from pathlib import Path
import json, subprocess, tempfile, sqlite3, base64, copy
root=Path(__file__).resolve().parents[1];cfg=root/'configs/ccr-status';src=root/'evidence/ccr-status'
checks=[]
def check(name,ok):
 assert ok,name
 checks.append(name)
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for n in ['resource','identity','health','ethernet','interfaces','neighbors','routes']:
  (d/(n+'.json')).write_bytes((src/(n+'.json')).read_bytes())
 (d/'monitors.json').write_text('[]');(d/'previous.json').write_text('{}')
 def run(now=1000,mono=100,uptime=990000,errors=[]):
  args=['jq','-nc','--argjson','now',str(now),'--argjson','mono',str(mono),'--argjson','uptime',str(uptime),'--argjson','errors',json.dumps(errors)]
  for n in ['resource','identity','health','ethernet','interfaces','neighbors','routes','monitors','previous']:args+=['--slurpfile',n,str(d/(n+'.json'))]
  return json.loads(subprocess.run(args+['-f',str(cfg/'normalize.jq')],capture_output=True,text=True,check=True).stdout)
 first=run();check('first sample has unknown rates',all(p['rx_mbps'] is None for p in first['ports']))
 check('active default route identifies WAN',[p['name'] for p in first['ports'] if p['wan']]==['sfp28-1'])
 old=copy.deepcopy(first)
 for p in old['ports']:p['rx_bytes']=0;p['tx_bytes']=0
 (d/'previous.json').write_text(json.dumps(old));i=json.loads((d/'interfaces.json').read_text())
 for p in i:p['rx-byte']='3750000';p['tx-byte']='7500000'
 (d/'interfaces.json').write_text(json.dumps(i));second=run(1030,130,990030)
 check('30 second rates convert bytes to Mbps',all(p['rx_mbps']==1 and p['tx_mbps']==2 for p in second['ports']))
 (d/'previous.json').write_text(json.dumps(second))
 check('router reboot invalidates deltas',all(p['rx_mbps'] is None for p in run(1060,160,20)['ports']))
 check('sampler outage invalidates deltas',all(p['rx_mbps'] is None for p in run(1300,400,990300)['ports']))
 for p in i:p['rx-byte']='10'
 (d/'interfaces.json').write_text(json.dumps(i))
 check('counter reset does not become negative throughput',all(p['rx_mbps'] is None for p in run(1060,160,990060)['ports']))
 (d/'interfaces.json').write_text('{}');(d/'health.json').write_text('{}');partial=run(1060,160,990060,['interfaces','health'])
 check('missing data is partial and not zero',partial['status']=='partial' and partial['health']==[] and all(p['rx_bytes'] is None for p in partial['ports']))
 (d/'identity.json').write_text(json.dumps({'name':"Test ' 路由器 <script>"}));payload=run(1060,160,990060,['health','interfaces'])
 raw=json.dumps(payload,ensure_ascii=False,separators=(',',':'));encoded=base64.b64encode(raw.encode()).decode()
 db=sqlite3.connect(':memory:');db.executescript((cfg/'schema.sql').read_text());db.execute('INSERT INTO DATA_INFO VALUES(1,?,?)',(1060,encoded))
 row=db.execute('SELECT data_time,payload FROM DATA_INFO').fetchone()
 check('stock API columns contain no SQL NULL',all(x is not None for x in row))
 check('Unicode and quote-safe payload round trip',json.loads(base64.b64decode(row[1]))==payload)
 check('snapshot is bounded',len(raw)<65536)
report={'passed':len(checks),'checks':checks};(root/'reports/ui-audit/ccr-status-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
