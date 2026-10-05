#!/usr/bin/env python3
"""One isolated host model; never touches initial namespace interfaces."""
import json,os,socket,struct,subprocess,sys,time
from pathlib import Path
assert os.getuid()==0 and os.geteuid()==0
assert os.readlink('/proc/self/ns/net')!=sys.argv[1]
assert os.readlink('/proc/self/ns/user')!=sys.argv[2]
ip=sys.argv[3]
assert Path(ip).is_file()
def call(*args):
    subprocess.run([ip,*args],check=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
def routes():
    out=[];s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE);s.settimeout(3);s.bind((0,0))
    payload=struct.pack('BBBBBBBBI',socket.AF_INET,0,0,0,0,0,0,0,0)
    s.sendto(struct.pack('IHHII',16+len(payload),26,0x301,1,0)+payload,(0,0))
    size=0
    try:
        while True:
            data,addr=s.recvfrom(65536);assert addr[0]==0;size+=len(data);assert size<=1048576
            at=0
            while at+16<=len(data):
                n,t,f,q,p=struct.unpack_from('IHHII',data,at);assert n>=16 and at+n<=len(data) and q==1
                body=data[at+16:at+n];at+=(n+3)&~3
                if t==3:return out
                if t==2:raise RuntimeError('netlink error '+repr(body.hex()))
                assert t==24 and len(body)>=12
                family,pre,srcpre,tos,table,proto,scope,kind,flags=struct.unpack_from('BBBBBBBBI',body)
                attrs={};pos=12
                while pos+4<=len(body):
                    al,ak=struct.unpack_from('HH',body,pos);assert al>=4 and pos+al<=len(body)
                    attrs[ak]=body[pos+4:pos+al].hex();pos+=(al+3)&~3
                if attrs.get(1)==socket.inet_aton('169.254.190.51').hex():
                    out.append(dict(prefix=pre,src_prefix=srcpre,tos=tos,table=table,protocol=proto,scope=scope,type=kind,flags=flags,attrs=attrs))
    finally:s.close()
call('link','add','eth0','type','veth','peer','name','control-wire')
call('link','set','eth0','up');call('link','set','control-wire','up')
call('link','add','br0','type','bridge');call('link','set','br0','up')
call('address','add','192.168.100.15/24','dev','br0')
call('link','set','eth0','master','br0')
call('address','add','169.254.190.15/32','dev','br0','scope','link','label','br0:lr','noprefixroute')
call('route','add','169.254.190.51/32','dev','br0','scope','link','proto','186','metric','42760','src','169.254.190.15')
before=routes();assert len(before)==1
setting=Path('/proc/sys/net/ipv4/conf/br0/ignore_routes_with_linkdown').read_text().strip()
call('link','set','eth0','nomaster');time.sleep(.3)
after=routes();assert len(after)==1
print(json.dumps(dict(schema=1,status='isolated_raw_route_dump_captured',kernel=os.uname().release,ignore_routes_with_linkdown=setting,before=before,after=after,initial_namespace_touched=False)))
