/* SPDX-License-Identifier: GPL-2.0-or-later
 * Reuse an immutable accepted hardware-order/device guard snapshot, without
 * calling its installer. The sole update is the fixed BSP ownership helper.
 */
#define HARDWARE_PROVISION_MAIN unused_hardware_order_provision_main
#include "hardware-provision.c"
#include "bsp-payload.h"

#define BSP_NAME "bsp-ownership"
#define BSP_TEMP "bsp-ownership.leon-update"
#define BSP_OLD_SHA "f51beb4faf20bac73df894a7752b385a06436967d782e3c264e48416e24ddbc9"
struct update_state { struct preserved files; struct saved_file hardware; struct stat alias; };
static int bsp_resources(int root);

static int update_preserve(int root,const struct context *context,struct update_state *saved) {
    static const char *const parts[]={"etc","modprobe.d"};
    struct stat st;if(fstat(root,&st)||preserve(root,context,&saved->files)||hardware_installed(root)||insmod_preflight(root)||bsp_resources(root))return -1;
    int config=parents(root,parts,2);if(config<0)return -1;
    int rc=save_file(config,HARDWARE_NAME,st.st_dev,0644,sizeof(hardware_payload)-1,&saved->hardware);close(config);if(rc)return -1;
    int dir=insmod_parent(root);if(dir<0)return -1;
    rc=insmod_link(dir,st.st_dev,0)||fstatat(dir,"insmod",&saved->alias,AT_SYMLINK_NOFOLLOW);close(dir);return rc?-1:0;
}
static int update_preserved_equal(const struct update_state *a,const struct update_state *b) {
    return preserved_equal(&a->files,&b->files)&&file_equal(&a->hardware,&b->hardware)&&
        a->alias.st_dev==b->alias.st_dev&&a->alias.st_ino==b->alias.st_ino&&a->alias.st_mode==b->alias.st_mode&&
        a->alias.st_uid==b->alias.st_uid&&a->alias.st_gid==b->alias.st_gid&&a->alias.st_nlink==b->alias.st_nlink;
}
static int bsp_parent(int root) {
    static const char *const parts[]={"usr","libexec","asus"};return parents(root,parts,3);
}
static int bsp_file(int dir,const char *name,dev_t device,const char *expected,mode_t mode,struct stat *st) {
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    int rc=-1;
    if(fstat(fd,st)||!S_ISREG(st->st_mode)||st->st_uid||st->st_gid||st->st_nlink!=1||
       st->st_dev!=device||(st->st_mode&07777)!=mode||st->st_size<=0||st->st_size>16*1024*1024||
       hash_fd(fd,(uint64_t)st->st_size,expected))goto done;
    rc=0;
done:close(fd);return rc;
}
static const struct { const char *name,*sha; } resource_files[]={
    {"hndmfg.sh","39845e29972a2e31efa987c6faa52d20cec51507323483052980f64b843eadf5"},
    {"hndnvram.sh","6c7328049f2fe8362e8a279617c5bedf1d8433f2125636af3e96b39f21aaa1c7"},
    {"mount-data.inc","d7439bbb478c72891c534ab4f3bbb415d73f4156759ed138e5941e99ca12ed58"},
    {"mount-fs.sh","b08d58dfe34bba39dd4b63dc432ae82de6a3971bc9c68838d4dd95bec20598a2"}
};
static const char *const resource_parents[2][7]={
    {"usr","share","asus","integration","etc-seed","init.d",NULL},
    {"usr","share","asus","integration","rom","etc","init.d"}
};
static int bsp_resources(int root) {
    struct stat st,leaf;if(fstat(root,&st))return -1;
    for(unsigned copy=0;copy<2;copy++) {
        int dir=parents(root,resource_parents[copy],copy?7:6);if(dir<0)return -1;
        for(unsigned i=0;i<sizeof(resource_files)/sizeof(resource_files[0]);i++) {
            if(bsp_file(dir,resource_files[i].name,st.st_dev,resource_files[i].sha,0755,&leaf)) {close(dir);return -1;}
        }
        close(dir);
    }
    return 0;
}
static int bsp_update(int root,int *published,int *temporary_created) {
    struct stat root_st,old,again,tmp;int dir=-1,fd=-1,rc=-1;
    if(fstat(root,&root_st))return -1;
    dir=bsp_parent(root);if(dir<0)return -1;
    /* Any leftover staging object, including a symlink/FIFO, needs review. */
    if(!fstatat(dir,BSP_TEMP,&tmp,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(!bsp_file(dir,BSP_NAME,root_st.st_dev,BSP_NEW_SHA,0755,&old)) {rc=0;goto done;}
    if(bsp_file(dir,BSP_NAME,root_st.st_dev,BSP_OLD_SHA,0755,&old))goto done;
    fd=openat(dir,BSP_TEMP,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)goto done;
    *temporary_created=1;
    if(fchmod(fd,0600))goto done;
    size_t used=0;
    while(used<sizeof(bsp_payload)) {
        ssize_t n=write(fd,bsp_payload+used,sizeof(bsp_payload)-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto done;
        used+=(size_t)n;
    }
    if(fsync(fd)||bsp_file(dir,BSP_TEMP,root_st.st_dev,BSP_NEW_SHA,0600,&tmp)||
       fstat(fd,&again)||again.st_dev!=tmp.st_dev||again.st_ino!=tmp.st_ino)goto done;
    if(fchmod(fd,0755)||fsync(fd)||bsp_file(dir,BSP_TEMP,root_st.st_dev,BSP_NEW_SHA,0755,&tmp)||
       bsp_file(dir,BSP_NAME,root_st.st_dev,BSP_OLD_SHA,0755,&again)||
       old.st_dev!=again.st_dev||old.st_ino!=again.st_ino)goto done;
    /* Same-volume rename atomically replaces only the twice-verified old inode.
     * The shared lock and exclusive stock maintenance exclude cooperating writers.
     */
    if(renameat(dir,BSP_TEMP,dir,BSP_NAME))goto done;
    *published=1;
    if(fsync(dir)||bsp_file(dir,BSP_NAME,root_st.st_dev,BSP_NEW_SHA,0755,&again)||
       again.st_dev!=tmp.st_dev||again.st_ino!=tmp.st_ino)goto done;
    rc=0;
done:if(fd>=0)close(fd);if(dir>=0)close(dir);return rc;
}

#ifndef BSP_UPDATE_MAIN
#define BSP_UPDATE_MAIN main
#endif
int BSP_UPDATE_MAIN(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--update-bsp-ownership")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,published=0,temporary_created=0,volume_fd=-1;
    struct stat self,init,st;struct statfs fs;struct statvfs vfs;struct update_state before,after;
    if(setrlimit(RLIMIT_CORE,&limit)||prctl(PR_SET_DUMPABLE,0)||clearenv())return 125;
    umask(077);alarm(300);stage="stock-root-and-native-namespace";
    if(getuid()||geteuid()||stat("/proc/self/ns/mnt",&self)||stat("/proc/1/ns/mnt",&init)||
       self.st_dev!=init.st_dev||self.st_ino!=init.st_ino||stat("/",&st)||major(st.st_dev)!=179||minor(st.st_dev)!=6||
       statfs("/",&fs)||fs.f_type!=SQUASHFS_MAGIC||statvfs("/",&vfs)||!(vfs.f_flag&ST_RDONLY))goto done;
    stage="shared-identity-provision-lock";
    lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       (st.st_mode&07777)!=0600||flock(lock,LOCK_EX|LOCK_NB)||recheck(&context))goto done;
    stage="filesystem-uuid-enrolled-fd";
    volume_fd=block_open(11,slot_parts[10].sectors*UINT64_C(512));
    unsigned char superblock[120];char volume_path[64];
    if(volume_fd<0||read_range(volume_fd,superblock,sizeof(superblock),1024)||
       superblock[56]!=0x53||superblock[57]!=0xef||memcmp(superblock+104,slot_parts[10].uuid,16))goto done;
    snprintf(volume_path,sizeof(volume_path),"/proc/self/fd/%d",volume_fd);
    stage="private-mount";
    if(!mkdtemp(mountpoint))goto done;
    created=1;
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
       mount(volume_path,mountpoint,"ext4",MS_NODEV|MS_NOSUID|MS_NOEXEC|MS_RELATIME,"data=ordered,errors=remount-ro"))goto done;
    mounted=1;context.mounted=1;close(volume_fd);volume_fd=-1;
    root=open(mountpoint,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root<0||fstatfs(root,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(root,&vfs)||(vfs.f_flag&ST_RDONLY)||recheck(&context))goto done;
    stage="preserve-existing-prerequisites";
    if(update_preserve(root,&context,&before))goto done;
    stage="replace-exact-bsp-ownership";
    if(bsp_update(root,&published,&temporary_created))goto done;
    stage="sync-readback-and-preservation";
    if(syncfs(root)||recheck(&context)||update_preserve(root,&context,&after)||!update_preserved_equal(&before,&after))goto done;
    int parent=bsp_parent(root);struct stat helper,root_st;
    if(parent<0)goto done;
    int helper_rc=fstat(root,&root_st)||bsp_file(parent,BSP_NAME,root_st.st_dev,BSP_NEW_SHA,0755,&helper);close(parent);if(helper_rc)goto done;
    close(root);root=-1;
    if(umount2(mountpoint,0))goto done;
    mounted=0;context.mounted=0;
    if(recheck(&context))goto done;
    rc=0;
done:
    if(volume_fd>=0)close(volume_fd);
    if(root>=0)close(root);
    if(mounted&&umount2(mountpoint,0))rc=1;
    if(created&&rmdir(mountpoint))rc=1;
    if(lock>=0)close(lock);
    if(rc)fprintf(stderr,"LEON_BSP_UPDATE_REFUSED stage=%s temporary_created=%d published=%d retained_for_review=true\n",stage,temporary_created,published);
    else printf("{\"schema\":1,\"status\":\"bsp_ownership_updated\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"old_sha256\":\"%s\",\"new_sha256\":\"%s\",\"published\":%s,\"prerequisites_unchanged\":true,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],BSP_OLD_SHA,BSP_NEW_SHA,published?"true":"false");
    return rc;
}
