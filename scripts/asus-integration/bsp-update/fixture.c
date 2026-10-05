/* Tests the exact new regular-file transaction, never the device entrypoint. */
#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
static int fail_fsync;
static int fixture_fsync(int fd) {
    if(fail_fsync&&!--fail_fsync){errno=EIO;return -1;}
    return (int)syscall(SYS_fsync,fd);
}
#define fsync fixture_fsync
#define BSP_UPDATE_MAIN bsp_provision_main
#include "provision.c"
#undef fsync
#include <assert.h>

static unsigned cases;
static void pass(const char *name){printf("PASS %s\n",name);cases++;}
static int make_dir(int parent,const char *name) {
    assert(!mkdirat(parent,name,0755));int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=0);assert(!fchmod(fd,0755));return fd;
}
static void put(int dir,const char *name,const unsigned char *bytes,size_t size,mode_t mode) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,mode);assert(fd>=0);assert(!fchmod(fd,mode));
    size_t used=0;while(used<size){ssize_t n=write(fd,bytes+used,size-used);assert(n>0);used+=(size_t)n;}assert(!close(fd));
}
static int resource_fixture(const char *source_path) {
    char path[]="/tmp/bsp-resource-fixture.XXXXXX";assert(mkdtemp(path));assert(!chmod(path,0755));
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),source=open(source_path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    assert(root>=0&&source>=0);int leaf[2];
    for(unsigned copy=0;copy<2;copy++) {
        int fd=dup(root);assert(fd>=0);
        for(unsigned part=0;part<(copy?7U:6U);part++) {
            if(mkdirat(fd,resource_parents[copy][part],0755))assert(errno==EEXIST);
            int next=openat(fd,resource_parents[copy][part],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);assert(next>=0);assert(!fchmod(next,0755));close(fd);fd=next;
        }
        leaf[copy]=fd;
        for(unsigned i=0;i<4;i++) {
            int from=openat(source,resource_files[i].name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st;assert(from>=0&&!fstat(from,&st));
            assert(st.st_size>0&&st.st_size<65536);unsigned char *data=malloc((size_t)st.st_size);assert(data&&!read_range(from,data,(size_t)st.st_size,0));
            put(fd,resource_files[i].name,data,(size_t)st.st_size,0755);free(data);close(from);
        }
    }
    assert(!bsp_resources(root));pass("both-reviewed-resource-copies-accepted");
    int corrupt=openat(leaf[1],"hndnvram.sh",O_RDWR|O_CLOEXEC);unsigned char byte,changed;assert(corrupt>=0&&pread(corrupt,&byte,1,0)==1);changed=byte^1U;assert(pwrite(corrupt,&changed,1,0)==1);
    assert(bsp_resources(root));pass("changed-rom-script-refused");assert(pwrite(corrupt,&byte,1,0)==1);close(corrupt);
    assert(!fchmodat(leaf[0],"mount-data.inc",0664,0));assert(bsp_resources(root));pass("mutable-etc-seed-script-refused");assert(!fchmodat(leaf[0],"mount-data.inc",0755,0));
    assert(!renameat(leaf[0],"hndmfg.sh",leaf[0],"saved"));assert(!symlinkat("saved",leaf[0],"hndmfg.sh"));assert(bsp_resources(root));pass("resource-symlink-refused");assert(!unlinkat(leaf[0],"hndmfg.sh",0));assert(!renameat(leaf[0],"saved",leaf[0],"hndmfg.sh"));
    assert(!fchmod(leaf[1],0775));assert(bsp_resources(root));pass("mutable-resource-parent-refused");assert(!fchmod(leaf[1],0755));assert(!bsp_resources(root));
    for(unsigned copy=0;copy<2;copy++){for(unsigned i=0;i<4;i++)assert(!unlinkat(leaf[copy],resource_files[i].name,0));close(leaf[copy]);}
    /* All directory components are fixture-owned, fixed, empty paths. */
    for(unsigned copy=0;copy<2;copy++) {
        unsigned count=copy?7:6;
        for(unsigned remaining=count;remaining>4;remaining--) {
            int parent=parents(root,resource_parents[copy],remaining-1);assert(parent>=0);assert(!unlinkat(parent,resource_parents[copy][remaining-1],AT_REMOVEDIR));close(parent);
        }
    }
    for(unsigned remaining=4;remaining>0;remaining--){int parent=remaining==1?dup(root):parents(root,resource_parents[0],remaining-1);assert(parent>=0);assert(!unlinkat(parent,resource_parents[0][remaining-1],AT_REMOVEDIR));close(parent);}
    close(source);close(root);assert(!rmdir(path));printf("RESOURCE_CASES %u\n",cases);return 0;
}
int main(int argc,char **argv) {
    alarm(20);umask(077);assert(getuid()==0);
    if(argc==3&&!strcmp(argv[1],"--resources-only"))return resource_fixture(argv[2]);
    assert(argc==2);
    int oldfd=open(argv[1],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat oldst;assert(oldfd>=0&&!fstat(oldfd,&oldst));
    assert(oldst.st_size>0&&oldst.st_size<16*1024*1024);size_t size=(size_t)oldst.st_size;
    unsigned char *old=malloc(size);assert(old&&!read_range(oldfd,old,size,0));close(oldfd);
    char path[]="/tmp/bsp-update-fixture.XXXXXX";assert(mkdtemp(path));assert(!chmod(path,0755));
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0);struct stat rootst,one,two;assert(!fstat(root,&rootst));
    int usr=make_dir(root,"usr"),libexec=make_dir(usr,"libexec"),dir=make_dir(libexec,"asus");
    int published=0,temporary=0;
    put(dir,BSP_NAME,old,size,0755);assert(!fstatat(dir,BSP_NAME,&one,AT_SYMLINK_NOFOLLOW));
    assert(!bsp_update(root,&published,&temporary)&&published&&temporary);assert(!bsp_file(dir,BSP_NAME,rootst.st_dev,BSP_NEW_SHA,0755,&two));
    assert(one.st_ino!=two.st_ino);assert(fstatat(dir,BSP_TEMP,&one,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT);pass("atomic-old-to-new-exact-readback");
    one=two;published=temporary=0;assert(!bsp_update(root,&published,&temporary)&&!published&&!temporary);
    assert(!fstatat(dir,BSP_NAME,&two,AT_SYMLINK_NOFOLLOW)&&one.st_ino==two.st_ino);pass("exact-new-idempotent-no-rewrite");
    assert(!unlinkat(dir,BSP_NAME,0));assert(bsp_update(root,&published,&temporary)&&!published&&!temporary);pass("missing-target-refused");
    old[0]^=1;put(dir,BSP_NAME,old,size,0755);assert(bsp_update(root,&published,&temporary)&&!temporary);pass("foreign-bytes-refused");assert(!unlinkat(dir,BSP_NAME,0));old[0]^=1;
    put(dir,BSP_NAME,old,size,0664);assert(bsp_update(root,&published,&temporary));pass("unsafe-target-mode-refused");assert(!fchmodat(dir,BSP_NAME,0755,0));
    assert(!fchownat(dir,BSP_NAME,1,1,0));assert(bsp_update(root,&published,&temporary));pass("foreign-target-owner-refused");assert(!fchownat(dir,BSP_NAME,0,0,0));
    assert(!linkat(dir,BSP_NAME,dir,"hardlink",0));assert(bsp_update(root,&published,&temporary));pass("target-hardlink-refused");assert(!unlinkat(dir,"hardlink",0));assert(!unlinkat(dir,BSP_NAME,0));
    assert(!symlinkat("/bin/true",dir,BSP_NAME));assert(bsp_update(root,&published,&temporary));pass("target-symlink-refused");assert(!unlinkat(dir,BSP_NAME,0));
    assert(!mkfifoat(dir,BSP_NAME,0600));assert(bsp_update(root,&published,&temporary));pass("target-fifo-refused-without-blocking");assert(!unlinkat(dir,BSP_NAME,0));
    put(dir,BSP_NAME,old,size,0755);put(dir,BSP_TEMP,(const unsigned char *)"partial",7,0600);
    assert(bsp_update(root,&published,&temporary)&&!published&&!temporary);assert(!bsp_file(dir,BSP_NAME,rootst.st_dev,BSP_OLD_SHA,0755,&one));pass("leftover-staging-refused-old-unchanged");assert(!unlinkat(dir,BSP_TEMP,0));
    assert(!mkfifoat(dir,BSP_TEMP,0600));assert(bsp_update(root,&published,&temporary));pass("staging-fifo-refused-without-blocking");assert(!unlinkat(dir,BSP_TEMP,0));
    assert(!fchmod(dir,0775));assert(bsp_update(root,&published,&temporary));pass("unsafe-parent-refused");assert(!fchmod(dir,0755));
    assert(!renameat(libexec,"asus",libexec,"asus-real"));assert(!symlinkat("asus-real",libexec,"asus"));assert(bsp_update(root,&published,&temporary));pass("parent-symlink-refused");assert(!unlinkat(libexec,"asus",0));assert(!renameat(libexec,"asus-real",libexec,"asus"));
    fail_fsync=1;assert(bsp_update(root,&published,&temporary)&&temporary&&!published&&!fail_fsync);
    assert(!bsp_file(dir,BSP_NAME,rootst.st_dev,BSP_OLD_SHA,0755,&one));assert(!bsp_file(dir,BSP_TEMP,rootst.st_dev,BSP_NEW_SHA,0600,&two));pass("pre-rename-sync-failure-retains-old-and-temp");assert(!unlinkat(dir,BSP_TEMP,0));
    temporary=published=0;fail_fsync=3;assert(bsp_update(root,&published,&temporary)&&temporary&&published&&!fail_fsync);
    assert(!bsp_file(dir,BSP_NAME,rootst.st_dev,BSP_NEW_SHA,0755,&one));assert(fstatat(dir,BSP_TEMP,&two,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT);pass("post-rename-sync-failure-reported-published");
    assert(!unlinkat(dir,BSP_NAME,0));close(dir);assert(!unlinkat(libexec,"asus",AT_REMOVEDIR));close(libexec);assert(!unlinkat(usr,"libexec",AT_REMOVEDIR));close(usr);assert(!unlinkat(root,"usr",AT_REMOVEDIR));close(root);assert(!rmdir(path));free(old);
    printf("CASES %u\n",cases);return 0;
}
