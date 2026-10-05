#!/usr/bin/env python3
"""One bounded format test run. Prefix tears model interruption, not hardware."""
import importlib.util,json,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('diag_parse',Path(__file__).with_name('parse.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def run(path):
    data=path.read_bytes();assert len(data)==16384
    old,new=data[:8192],data[8192:];assert m.record(old,0)['sequence']==1 and m.record(new,0)['sequence']==2
    good=bad=0
    for cut in range(8193):
        torn=new[:cut]+old[cut:]
        try:r=m.record(torn,0)
        except (ValueError,UnicodeError):bad+=1
        else:assert r['status']=='valid' and torn in (old,new);good+=1
    for offset in range(8192):
        broken=bytearray(new);broken[offset]^=1
        try:m.record(bytes(broken),0)
        except (ValueError,UnicodeError):pass
        else:raise AssertionError('undetected corruption at '+str(offset))
    assert m.parse(old+bytes(8192))['slots'][1]['status']=='empty'
    assert m.parse(bytes(8192)+old)['slots'][1]['status']=='invalid_or_torn'
    return {'passed':True,'prefix_interruptions':8193,'valid_complete_old_or_new':good,'rejected_torn':bad,
            'single_byte_bit_corruptions_rejected':8192,'cross_producer_rejected':True,
            'limit':'In-memory prefix and bit-corruption model, not a physical power-cut or persistence test.'}
if __name__=='__main__':
    if not __debug__:raise RuntimeError('Python -O forbidden')
    print(json.dumps(run(Path(sys.argv[1])),indent=2))
