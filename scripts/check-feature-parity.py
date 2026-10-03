#!/usr/bin/env python3
from pathlib import Path
import json
r=Path(__file__).resolve().parents[1]
def cfg(name):return dict(line.split('=',1) for line in (r/'configs'/name).read_text().splitlines() if line.startswith('CONFIG_') and '=' in line)
stock,reference,candidate=map(cfg,['stock.config','be98-reference.config','candidate.config']);rank={'n':0,'m':1,'y':2};exceptions={'CONFIG_SYSFS_DEPRECATED','CONFIG_SYSFS_DEPRECATED_V2'}
def missing(base,excepts=set()):return [k for k,v in base.items() if v in rank and rank[v]>rank.get(candidate.get(k,'n'),0) and k not in excepts]
record={'stock_features_lost':missing(stock),'be98_features_missing':missing(reference,exceptions),'intentional_interface_exceptions':sorted(exceptions),'sysfs_matches_stock':candidate.get('CONFIG_SYSFS_DEPRECATED','n')==stock.get('CONFIG_SYSFS_DEPRECATED','n')=='n','zsmalloc_builtin':candidate.get('CONFIG_ZSMALLOC')=='y'}
assert not record['stock_features_lost'] and not record['be98_features_missing'] and record['sysfs_matches_stock'] and record['zsmalloc_builtin'],record
(r/'reports/feature-parity.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
