/* SPDX-License-Identifier: GPL-2.0-or-later
 * Exercise only new fixed-payload transactions in fixture-owned directories.
 * Frozen physical device entrypoint is not called by successful fixture paths.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
static int fail_sync;
static int test_fsync(int fd) {
    if(fail_sync&&!--fail_sync){errno=EIO;return -1;}
    return (int)syscall(SYS_fsync,fd);
}
#define fsync test_fsync
#define RECOVERY_INSTALL_MAIN unused_recovery_install_main
#include "install.c"
#undef fsync
#include <assert.h>
#include <ftw.h>

static unsigned count;
static char fixture_path[128];
static void pass(const char *text){printf("PASS %s\n",text);count++;}
static int cleanup(const char *path,const struct stat *st,int type,struct FTW *walk) {
    (void)st;(void)type;(void)walk;return remove(path);
}
static int fixture_root(void) {
    strcpy(fixture_path,"/tmp/recovery-install-fixture.XXXXXX");assert(mkdtemp(fixture_path));assert(!chmod(fixture_path,0755));
    int root=open(fixture_path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);struct stat st;assert(root>=0&&!fstat(root,&st));
    const char *const dirs[]={"etc","systemd","system"};int dir=dup(root);assert(dir>=0);
    for(unsigned i=0;i<3;i++){int next=safe_dir(dir,dirs[i],st.st_dev,1);assert(next>=0);close(dir);dir=next;}close(dir);
    int var=safe_dir(root,"var",st.st_dev,1),lib=safe_dir(var,"lib",st.st_dev,1);assert(var>=0&&lib>=0);
    assert(!mkdirat(lib,"leon-asus-ssh",0700));int state=state_dir(lib,st.st_dev);assert(state>=0&&!fchmod(state,0700));
    int key=openat(state,"private-marker",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(key>=0&&write(key,"keep\n",5)==5&&!close(key));
    close(state);close(lib);close(var);return root;
}
static void fixture_done(int root){close(root);assert(!nftw(fixture_path,cleanup,32,FTW_DEPTH|FTW_PHYS));}
static int file_dir(int root,char name[NAME_MAX+1]){int dir=recovery_parent(root,recovery_payloads[0].path,1,name);assert(dir>=0);return dir;}
static void put(int dir,const char *name,const void *bytes,size_t size,mode_t mode) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,mode);assert(fd>=0&&!fchmod(fd,mode));
    assert(write(fd,bytes,size)==(ssize_t)size&&!close(fd));
}
static int install(int root,unsigned *published,unsigned *temporary,int *mode,int *enabled) {
    *published=*temporary=0;*mode=*enabled=0;return install_recovery(root,published,temporary,mode,enabled);
}
int main(void) {
    assert(getuid()==0);umask(077);alarm(30);
    unsigned published,temporary;int mode,enabled;struct stat st,volume;char name[NAME_MAX+1];
    int root=fixture_root();struct recovery_saved before,after;
    assert(!identity_save(root,"var/lib/leon-asus-ssh/private-marker",&before));
    assert(!install(root,&published,&temporary,&mode,&enabled)&&published==RECOVERY_PAYLOAD_COUNT&&temporary==published&&mode&&enabled);
    assert(!fstat(root,&volume));struct stat installed[RECOVERY_PAYLOAD_COUNT];
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++){int dir=recovery_parent(root,recovery_payloads[i].path,0,name);assert(dir>=0&&!recovery_file(dir,name,volume.st_dev,&recovery_payloads[i],0644,&installed[i]));close(dir);}
    assert(!enable_link(root,0));pass("all-exact-files-and-last-device-enable-link");
    assert(!identity_save(root,"var/lib/leon-asus-ssh/private-marker",&after)&&identity_equal(&before,&after));pass("private-marker-mode-bytes-inode-preserved");
    assert(!install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++){int dir=recovery_parent(root,recovery_payloads[i].path,0,name);assert(dir>=0&&!fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)&&st.st_ino==installed[i].st_ino);close(dir);}pass("idempotent-no-file-rewrite");fixture_done(root);
    for(unsigned variant=0;variant<7;variant++) {
        root=fixture_root();int dir=file_dir(root,name);char temp[NAME_MAX+1];assert(snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name)>0);
        if(variant==0)put(dir,name,"foreign\n",8,0644);
        if(variant==1)assert(!symlinkat("/etc/passwd",dir,name));
        if(variant==2)assert(!mkfifoat(dir,name,0644));
        if(variant==3){put(dir,name,recovery_payloads[0].data,recovery_payloads[0].size,0644);assert(!linkat(dir,name,dir,"extra",0));}
        if(variant==4)put(dir,name,recovery_payloads[0].data,recovery_payloads[0].size,0664);
        if(variant==5){put(dir,name,recovery_payloads[0].data,recovery_payloads[0].size,0644);assert(!fchownat(dir,name,1,1,0));}
        if(variant==6)put(dir,temp,"partial\n",8,0600);
        assert(install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);
        assert(!enable_link(root,1));
        const char *const labels[]={"foreign-file-refused-before-publication","symlink-target-refused","fifo-target-refused-without-blocking","hardlinked-target-refused","unsafe-file-mode-refused","foreign-file-owner-refused","leftover-staging-refused"};
        pass(labels[variant]);close(dir);fixture_done(root);
    }
    root=fixture_root();int dir=enable_dir(root,1);assert(dir>=0&&!symlinkat("/tmp/foreign.socket",dir,ENABLE_NAME));close(dir);
    assert(install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);pass("foreign-enable-link-refused-before-files");fixture_done(root);
    root=fixture_root();int var=openat(root,"var",O_RDONLY|O_DIRECTORY),lib=openat(var,"lib",O_RDONLY|O_DIRECTORY);assert(var>=0&&lib>=0);
    assert(!fchmodat(lib,"leon-asus-ssh",0750,0));assert(install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);pass("unexpected-state-mode-refused");close(lib);close(var);fixture_done(root);
    root=fixture_root();var=openat(root,"var",O_RDONLY|O_DIRECTORY);lib=openat(var,"lib",O_RDONLY|O_DIRECTORY);assert(var>=0&&lib>=0);
    assert(!renameat(lib,"leon-asus-ssh",lib,"saved-state")&&!symlinkat("saved-state",lib,"leon-asus-ssh"));
    assert(install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);pass("state-symlink-refused");close(lib);close(var);fixture_done(root);
    root=fixture_root();dir=file_dir(root,name);assert(!fchmod(dir,0775));assert(install(root,&published,&temporary,&mode,&enabled)&&!published&&!temporary&&!mode&&!enabled);pass("mutable-parent-refused");close(dir);fixture_done(root);
    root=fixture_root();assert(!target_preflight(root,&recovery_payloads[0]));published=temporary=0;fail_sync=1;
    assert(install_target(root,&recovery_payloads[0],&published,&temporary)&&!published&&temporary==1&&!fail_sync);
    dir=file_dir(root,name);assert(fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT);
    char temp[NAME_MAX+1];assert(snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name)>0&&!fstat(root,&volume));
    assert(!recovery_file(dir,temp,volume.st_dev,&recovery_payloads[0],0600,&st));pass("pre-publication-sync-failure-retains-staging-only");close(dir);fixture_done(root);
    printf("RECOVERY_INSTALL_CASES %u\n",count);return 0;
}
