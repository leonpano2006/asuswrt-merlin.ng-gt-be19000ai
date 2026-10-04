#!/usr/bin/env python3
"""Exercise counter resets, missing radio data, retention, and NULL-free API rows."""
from pathlib import Path
import sqlite3,subprocess,tempfile,json
root=Path(__file__).resolve().parents[1];config=root/'configs/node-history'
with tempfile.TemporaryDirectory() as tmp:
 d=Path(tmp);previous=d/'previous';previous.write_text('');nxt=d/'next';db=sqlite3.connect(':memory:');db.executescript((config/'schema.sql').read_text())
 def sample(ts,up,index,rx,tx,radio='RADIO 0 1 2 6 30 10 3 -83'):
  body=f'CLOCK {ts} {up}\nIF eth0 {index} {rx} {tx}\n{radio}\n';result=subprocess.run(['awk','-v',f'previous={previous}','-v',f'next_previous={nxt}','-f',str(config/'collect.awk')],input=body,text=True,check=True,capture_output=True);db.executescript(result.stdout);previous.write_text(nxt.read_text());return db.execute("SELECT rx_mbps,tx_mbps FROM DATA_INFO WHERE kind='interface' ORDER BY data_id DESC LIMIT 1").fetchone()
 assert sample(1791056000,100,20,100,200)==(-1,-1)
 assert sample(1791056060,160,20,7500100,15000200)==(1,2)
 assert sample(1791056120,220,21,100,200)==(-1,-1), 'Changed interface index must reset counters'
 assert sample(1791056180,280,21,10,20)==(-1,-1), 'Counter wrap/reset must make a gap'
 assert sample(1791056800,900,21,800,1600)==(-1,-1), 'Long gaps must not become averaged traffic'
 sample(1791056860,960,21,800,1600,'RADIO 0 0 99 6 90 80 5 -83')
 assert db.execute("SELECT links,chspec,busy,noise FROM DATA_INFO ORDER BY data_id DESC LIMIT 1").fetchone()==(0,'',-1,-999)
 assert all(v is not None for row in db.execute('SELECT * FROM DATA_INFO') for v in row), 'Stock libcodb cannot serialize NULL safely'
 sample(1791144000,88000,21,800,1600)
 assert db.execute('SELECT MIN(data_time) FROM DATA_INFO').fetchone()[0]>=1791144000-86400
 print(json.dumps({'passed':['first sample gap','counter delta rates','interface replacement','counter reset','long gap','radio disabled','NULL-free API','24-hour pruning']}))
