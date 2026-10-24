#!/usr/bin/python3
"""No UDP observer for production init; one explicit private readiness record."""
import os,sys,json,stat,re
from pathlib import Path
nonce=sys.argv[1]
assert os.geteuid()==0 and re.fullmatch('[0-9a-f]{32}',nonce)
p=Path('/run/leon-ai-watch-'+nonce)
s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
for name in ['collector-ready.json','collector-result.json']:
 fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  json.dump({'nonce':nonce,'no_udp_observer':True,'reason':'Production init uses runtime SSH health proof; no UDP diagnostics'},f);f.flush();os.fsync(f.fileno())
