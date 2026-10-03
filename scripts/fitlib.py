"""FIT parser and payload repacker; no key material or device writes."""
import hashlib, struct, time
def sha(b): return hashlib.sha256(b).hexdigest()
def fdt(data):
    h=struct.unpack_from('>10I',data); magic,total,pos,strings=h[:4]
    assert magic==0xd00dfeed and total<=len(data)
    end=pos+h[9]; stack=[]; nodes={}; locations={}
    while pos<end:
        token,=struct.unpack_from('>I',data,pos);pos+=4
        if token==1:
            stop=data.index(b'\0',pos,end); stack.append(data[pos:stop].decode())
            nodes['/'.join(stack)]={};pos=(stop+4)&~3
        elif token==2:stack.pop()
        elif token==3:
            size,noff=struct.unpack_from('>2I',data,pos);pos+=8
            start=strings+noff;stop=data.index(b'\0',start,strings+h[8]);name=data[start:stop].decode()
            node='/'.join(stack);nodes[node][name]=data[pos:pos+size];locations[(node,name)]=(pos,size)
            pos=(pos+size+3)&~3
        elif token==4:pass
        elif token==9:assert not stack;return total,nodes,locations
        else:raise ValueError(token)
    raise ValueError('missing FDT end')
def string(b): return b.rstrip(b'\0').decode()
def images(data):
    total,nodes,loc=fdt(data);result={}
    for name,props in nodes.items():
        if name.count('/')!=2 or not name.startswith('/images/'):continue
        size=int.from_bytes(props['data-size'],'big')
        offset=int.from_bytes(props.get('data-position',props.get('data-offset')),'big')
        if 'data-position' not in props:offset+=(total+3)&~3
        payload=data[offset:offset+size];assert len(payload)==size
        assert nodes[name+'/hash-1']['algo']==b'sha256\0'
        assert hashlib.sha256(payload).digest()==nodes[name+'/hash-1']['value'],name
        result[name]=(offset,payload)
    return result
def repack(data,replacements):
    total,nodes,locations=fdt(data);old=images(data)
    first=min(v[0] for v in old.values());out=bytearray(data[:first]);record={}
    def prop(node,name,value):
        pos,size=locations[(node,name)];assert len(value)==size;out[pos:pos+size]=value
    for name,(offset,previous) in sorted(old.items(),key=lambda item:item[1][0]):
        payload=replacements.get(name,previous)
        start=len(out);out.extend(payload);out.extend(b'\0'*(-len(out)%4))
        key='data-position' if 'data-position' in nodes[name] else 'data-offset'
        value=start if key=='data-position' else start-((total+3)&~3)
        prop(name,key,struct.pack('>I',value));prop(name,'data-size',struct.pack('>I',len(payload)))
        prop(name+'/hash-1','value',hashlib.sha256(payload).digest())
        record[name]={'before_sha256':sha(previous),'after_sha256':sha(payload),'bytes':len(payload),'offset':start}
    if ('','timestamp') in locations:prop('','timestamp',struct.pack('>I',int(time.time())))
    assert images(bytes(out)).keys()==old.keys()
    return bytes(out),record
