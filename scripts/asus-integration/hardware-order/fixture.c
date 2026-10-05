/* Focused new-file safety tests only. Never calls the device entry point. */
#define HARDWARE_PROVISION_MAIN hardware_provision_main
#include "provision.c"
#include <assert.h>

static unsigned cases;
static void pass(const char *name) {printf("PASS %s\n",name);cases++;}
static void put(int dir,const char *name,const void *bytes,size_t size,mode_t mode) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,mode);assert(fd>=0);
    assert(!fchmod(fd,mode));assert(write(fd,bytes,size)==(ssize_t)size);assert(!close(fd));
}
static int make_dir(int parent,const char *name) {
    assert(!mkdirat(parent,name,0755));int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(fd>=0);assert(!fchmod(fd,0755));return fd;
}
int main(int argc,char **argv) {
    alarm(20);umask(077);assert(getuid()==0);
    assert(argc==2);
    char path[]="/tmp/hardware-order-fixture.XXXXXX";assert(mkdtemp(path));assert(!chmod(path,0755));
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(root>=0);
    assert(!mkdirat(root,"etc",0755));int etc=openat(root,"etc",O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(etc>=0);assert(!fchmod(etc,0755));
    /* Arbitrary prior diagnostic bytes stay byte-identical, including nonzero. */
    unsigned char records[LEON_DIAG_BYTES];for(unsigned i=0;i<sizeof(records);i++)records[i]=(unsigned char)(i*7U+3U);
    put(etc,"sentinel-diagnostics",records,sizeof(records),0600);
    put(etc,"sentinel-token","token\n",6,0600);put(etc,"sentinel-resolver","resolver\n",9,0644);
    struct stat st;assert(!fstat(root,&st));struct saved_file d1,d2,t1,t2,r1,r2;
    assert(!save_file(etc,"sentinel-diagnostics",st.st_dev,0600,sizeof(records),&d1));
    assert(!save_file(etc,"sentinel-token",st.st_dev,0600,6,&t1));
    assert(!save_file(etc,"sentinel-resolver",st.st_dev,0644,9,&r1));
    int created=0;assert(!install_hardware_order(root,&created)&&created);pass("create-exact-config-and-directory");
    int dir=openat(etc,"modprobe.d",O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(dir>=0);struct stat one,two;
    assert(!fstatat(dir,HARDWARE_NAME,&one,AT_SYMLINK_NOFOLLOW));
    created=0;assert(!install_hardware_order(root,&created)&&!created);
    assert(!fstatat(dir,HARDWARE_NAME,&two,AT_SYMLINK_NOFOLLOW)&&one.st_ino==two.st_ino&&one.st_mtim.tv_sec==two.st_mtim.tv_sec&&one.st_mtim.tv_nsec==two.st_mtim.tv_nsec);
    pass("exact-safe-existing-idempotent-no-rewrite");
    assert(!save_file(etc,"sentinel-diagnostics",st.st_dev,0600,sizeof(records),&d2)&&file_equal(&d1,&d2));
    assert(!save_file(etc,"sentinel-token",st.st_dev,0600,6,&t2)&&file_equal(&t1,&t2));
    assert(!save_file(etc,"sentinel-resolver",st.st_dev,0644,9,&r2)&&file_equal(&r1,&r2));pass("unrelated-bytes-and-inodes-unchanged");
    assert(!unlinkat(dir,HARDWARE_NAME,0));put(dir,HARDWARE_NAME,"foreign",7,0644);
    created=0;assert(install_hardware_order(root,&created)&&!created);assert(!expected_file(dir,HARDWARE_NAME,st.st_dev,0644,"foreign",7));pass("foreign-content-retained");
    assert(!unlinkat(dir,HARDWARE_NAME,0));put(dir,HARDWARE_NAME,hardware_payload,1,0644);
    assert(install_hardware_order(root,&created));assert(!expected_file(dir,HARDWARE_NAME,st.st_dev,0644,hardware_payload,1));pass("partial-file-retained");
    assert(!unlinkat(dir,HARDWARE_NAME,0));assert(!symlinkat("../sentinel-token",dir,HARDWARE_NAME));
    assert(install_hardware_order(root,&created));pass("symlink-refused");assert(!unlinkat(dir,HARDWARE_NAME,0));
    assert(!mkfifoat(dir,HARDWARE_NAME,0644));assert(install_hardware_order(root,&created));pass("fifo-refused-without-blocking");assert(!unlinkat(dir,HARDWARE_NAME,0));
    put(dir,HARDWARE_NAME,hardware_payload,sizeof(hardware_payload)-1,0644);assert(!linkat(dir,HARDWARE_NAME,dir,"alias",0));
    assert(install_hardware_order(root,&created));pass("hardlink-refused");assert(!unlinkat(dir,"alias",0));
    assert(!fchmodat(dir,HARDWARE_NAME,0664,0));assert(install_hardware_order(root,&created));pass("unsafe-file-mode-refused");
    assert(!fchmodat(dir,HARDWARE_NAME,0644,0));assert(!fchownat(dir,HARDWARE_NAME,1,1,0));assert(install_hardware_order(root,&created));pass("foreign-file-owner-refused");
    assert(!unlinkat(dir,HARDWARE_NAME,0));assert(!fchmod(dir,0775));assert(install_hardware_order(root,&created));pass("unsafe-parent-mode-refused");
    assert(!fchmod(dir,0755));assert(!fchown(dir,1,1));assert(install_hardware_order(root,&created));pass("foreign-parent-owner-refused");assert(!fchown(dir,0,0));
    close(dir);assert(!unlinkat(etc,"modprobe.d",AT_REMOVEDIR));assert(!symlinkat("/tmp",etc,"modprobe.d"));
    assert(install_hardware_order(root,&created));pass("parent-symlink-refused");assert(!unlinkat(etc,"modprobe.d",0));
    put(etc,"modprobe.d","x",1,0644);assert(install_hardware_order(root,&created));pass("parent-regular-file-refused");
    assert(!unlinkat(etc,"modprobe.d",0));
    int usr=make_dir(root,"usr"),libexec=make_dir(usr,"libexec"),asus=make_dir(libexec,"asus");
    int source=open(argv[1],O_RDONLY|O_CLOEXEC|O_NOFOLLOW);assert(source>=0);assert(!fstat(source,&one));
    assert(one.st_size>0&&one.st_size<64*1024*1024);unsigned char *busybox=malloc((size_t)one.st_size);assert(busybox);
    assert(!read_range(source,busybox,(size_t)one.st_size,0));close(source);put(asus,"busybox",busybox,(size_t)one.st_size,0755);
    int share=make_dir(usr,"share"),share_asus=make_dir(share,"asus"),commands=make_dir(share_asus,"commands"),sbin=make_dir(commands,"sbin");
    assert(!hardware_preflight(root)&&!insmod_preflight(root));pass("both-paths-preflight-and-exact-busybox");
    put(sbin,"insmod","foreign",7,0644);
    assert(!hardware_preflight(root)&&insmod_preflight(root));
    assert(fstatat(etc,"modprobe.d",&two,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT);pass("unsafe-alias-refused-before-config-creation");assert(!unlinkat(sbin,"insmod",0));
    created=0;assert(!install_insmod(root,&created)&&created&&!insmod_preflight(root));pass("create-private-alias");
    assert(!fstatat(sbin,"insmod",&one,AT_SYMLINK_NOFOLLOW));created=0;assert(!install_insmod(root,&created)&&!created);
    assert(!fstatat(sbin,"insmod",&two,AT_SYMLINK_NOFOLLOW)&&one.st_ino==two.st_ino);pass("exact-existing-alias-idempotent");
    assert(!unlinkat(sbin,"insmod",0));assert(!symlinkat("/bin/false",sbin,"insmod"));assert(insmod_preflight(root));pass("foreign-alias-target-refused");assert(!unlinkat(sbin,"insmod",0));
    assert(!mkfifoat(sbin,"insmod",0644));assert(insmod_preflight(root));pass("fifo-alias-refused");assert(!unlinkat(sbin,"insmod",0));
    assert(!symlinkat(INSMOD_TARGET,sbin,"insmod"));assert(!linkat(sbin,"insmod",sbin,"alias",0));assert(insmod_preflight(root));pass("hardlinked-alias-refused");assert(!unlinkat(sbin,"alias",0));
    assert(!fchownat(sbin,"insmod",1,1,AT_SYMLINK_NOFOLLOW));assert(insmod_preflight(root));pass("foreign-alias-owner-refused");assert(!fchownat(sbin,"insmod",0,0,AT_SYMLINK_NOFOLLOW));
    assert(!fchmod(sbin,0775));assert(insmod_preflight(root));pass("unsafe-alias-parent-refused");assert(!fchmod(sbin,0755));
    assert(!fchmodat(asus,"busybox",0775,0));assert(insmod_preflight(root));pass("unsafe-busybox-mode-refused");assert(!fchmodat(asus,"busybox",0755,0));
    int corrupt=openat(asus,"busybox",O_WRONLY|O_CLOEXEC);assert(corrupt>=0);unsigned char different=busybox[0]^1U;assert(pwrite(corrupt,&different,1,0)==1);assert(!close(corrupt));
    assert(insmod_preflight(root));pass("different-busybox-bytes-refused");free(busybox);
    assert(!unlinkat(sbin,"insmod",0));close(sbin);assert(!unlinkat(commands,"sbin",AT_REMOVEDIR));close(commands);assert(!unlinkat(share_asus,"commands",AT_REMOVEDIR));close(share_asus);assert(!unlinkat(share,"asus",AT_REMOVEDIR));close(share);assert(!unlinkat(usr,"share",AT_REMOVEDIR));
    assert(!unlinkat(asus,"busybox",0));close(asus);assert(!unlinkat(libexec,"asus",AT_REMOVEDIR));close(libexec);assert(!unlinkat(usr,"libexec",AT_REMOVEDIR));close(usr);assert(!unlinkat(root,"usr",AT_REMOVEDIR));
    assert(!unlinkat(etc,"sentinel-diagnostics",0));assert(!unlinkat(etc,"sentinel-token",0));assert(!unlinkat(etc,"sentinel-resolver",0));
    close(etc);assert(!unlinkat(root,"etc",AT_REMOVEDIR));close(root);assert(!rmdir(path));
    printf("CASES %u\n",cases);return 0;
}
