"""Verify the portable backup tool on this Yocto host using disposable files."""
import ctypes,errno,json,os,pathlib,shutil,stat,struct,subprocess,tempfile
P=pathlib.Path;root=P('/home/leon-docker-upgrade-20261017');work=P(tempfile.mkdtemp(prefix='tar-roundtrip-',dir=root))
src=work/'src';src.mkdir();dest=work/'dest';dest.mkdir();f=src/'file';f.write_bytes(b'backup-preservation-test\0\xff\n')
os.chown(f,1234,1234);os.chmod(f,0o640);os.setxattr(f,'user.leon',b'\0binary\xffvalue')
acl=ctypes.CDLL('libacl.so.1',use_errno=True);acl.acl_from_text.argtypes=[ctypes.c_char_p];acl.acl_from_text.restype=ctypes.c_void_p;acl.acl_set_file.argtypes=[ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p];acl.acl_free.argtypes=[ctypes.c_void_p]
a=acl.acl_from_text(b'user::rw-,user:12345:r--,group::r--,mask::r--,other::---');assert a
try:
 rc=acl.acl_set_file(os.fsencode(f),0x8000,a);acl_errno=ctypes.get_errno() if rc else 0
 assert rc==0 or acl_errno==errno.EOPNOTSUPP,('acl_set_file',acl_errno)
finally:acl.acl_free(a)
cap_errno=0
try:os.setxattr(f,'security.capability',struct.pack('<IIIII',0x02000001,1<<10,0,0,0))
except OSError as e:
 cap_errno=e.errno
 if e.errno!=errno.EOPNOTSUPP:raise
os.link(f,src/'hardlink');os.symlink('file',src/'symlink');os.mkfifo(src/'fifo');os.mknod(src/'whiteout',stat.S_IFCHR|0o600,os.makedev(0,0))
tar=str(root/'portable-tar/tar');archive=work/'test.tar'
subprocess.run([tar,'--xattrs','--xattrs-include=*','--acls','--numeric-owner','-cpf',str(archive),'-C',str(work),'src'],check=True,timeout=20)
subprocess.run([tar,'--xattrs','--xattrs-include=*','--acls','--numeric-owner','-xpf',str(archive),'-C',str(dest)],check=True,timeout=20)
g=dest/'src/file';assert g.read_bytes()==f.read_bytes()
assert {k:os.getxattr(g,k) for k in os.listxattr(g)}=={k:os.getxattr(f,k) for k in os.listxattr(f)}
assert (g.stat().st_uid,g.stat().st_gid,stat.S_IMODE(g.stat().st_mode))==(f.stat().st_uid,f.stat().st_gid,stat.S_IMODE(f.stat().st_mode))
assert g.stat().st_ino==(dest/'src/hardlink').stat().st_ino
assert os.readlink(dest/'src/symlink')=='file' and stat.S_ISFIFO((dest/'src/fifo').stat().st_mode)
assert stat.S_ISCHR((dest/'src/whiteout').stat().st_mode) and (dest/'src/whiteout').stat().st_rdev==0
r={'passed':True,'acl_supported':acl_errno==0,'acl_errno':acl_errno,'file_capability_supported':cap_errno==0,'file_capability_errno':cap_errno,'checks':['file contents','numeric owner','mode','binary user xattr','hardlink','symlink','FIFO','Docker-style whiteout']}
if not acl_errno:r['checks'].append('ACL')
if not cap_errno:r['checks'].append('security.capability')
(root/'tar-roundtrip.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));shutil.rmtree(work)
