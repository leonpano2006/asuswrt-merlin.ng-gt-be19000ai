/* SPDX-License-Identifier: GPL-2.0-or-later
 * One fixed admin configuration only. The stock/device guards below are an
 * immutable slot-proof v7 snapshot; their original main is never called.
 */
#define _GNU_SOURCE
#define main unused_frozen_slot_proof_main
#include "slot-device.c"
#undef main
#include "boot-diagnostics.h"
#include "hardware-payload.h"
#include "resolver-payload.h"

#define HARDWARE_NAME "90-leon-asus-hardware-order.conf"
#define INSMOD_TARGET "/usr/libexec/asus/busybox"
#define BUSYBOX_SHA "686d6f8557891d97814415092daac5a7b176a94aeacd76c6b96e2a0a868d20c6"
struct saved_file { struct stat st; size_t size; unsigned char bytes[LEON_DIAG_BYTES]; };
struct preserved {
    struct saved_file diagnostic,token,resolver;
    struct leon_diag_map diagnostic_map;
    struct stat resolver_link;
    char resolver_target[128];
};

static int safe_dir(int parent,const char *name,dev_t device,int create) {
    int made=0;
    if(create) { if(!mkdirat(parent,name,0755))made=1;else if(errno!=EEXIST)return -1; }
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return -1;
    struct stat st;
    if((made && (fchmod(fd,0755)||fsync(fd)||fsync(parent)))||
       fstat(fd,&st)||leon_diag_directory(fd,device)||(st.st_mode&07777)!=0755) {close(fd);return -1;}
    return fd;
}
static int parents(int root,const char *const *names,size_t count) {
    struct stat st;if(fstat(root,&st)||leon_diag_directory(root,st.st_dev))return -1;
    int fd=dup(root);if(fd<0)return -1;
    for(size_t i=0;i<count;i++) {int next=safe_dir(fd,names[i],st.st_dev,0);close(fd);fd=next;if(fd<0)return -1;}
    return fd;
}
static int save_file(int dir,const char *name,dev_t device,mode_t mode,size_t size,struct saved_file *saved) {
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    int rc=-1;
    if(size>sizeof(saved->bytes)||fstat(fd,&saved->st)||!S_ISREG(saved->st.st_mode)||
       saved->st.st_uid||saved->st.st_gid||saved->st.st_nlink!=1||saved->st.st_dev!=device||
       (saved->st.st_mode&07777)!=mode||saved->st.st_size!=(off_t)size||read_range(fd,saved->bytes,size,0))goto done;
    saved->size=size;rc=0;
done:close(fd);return rc;
}
static int file_equal(const struct saved_file *a,const struct saved_file *b) {
    return a->size==b->size && a->st.st_dev==b->st.st_dev && a->st.st_ino==b->st.st_ino &&
        a->st.st_mode==b->st.st_mode && a->st.st_uid==b->st.st_uid && a->st.st_gid==b->st.st_gid &&
        a->st.st_nlink==b->st.st_nlink && !memcmp(a->bytes,b->bytes,a->size);
}
static int expected_file(int dir,const char *name,dev_t device,mode_t mode,const void *bytes,size_t size) {
    struct saved_file saved;
    return save_file(dir,name,device,mode,size,&saved)||memcmp(saved.bytes,bytes,size)?-1:0;
}
static int hardware_preflight(int root) {
    struct stat st;if(fstat(root,&st)||leon_diag_directory(root,st.st_dev))return -1;
    int etc=safe_dir(root,"etc",st.st_dev,0);if(etc<0)return -1;
    struct stat parent_st;
    if(fstatat(etc,"modprobe.d",&parent_st,AT_SYMLINK_NOFOLLOW)) {
        int rc=errno==ENOENT?0:-1;close(etc);return rc;
    }
    int dir=safe_dir(etc,"modprobe.d",st.st_dev,0),rc=-1;close(etc);
    if(dir<0)return -1;
    struct stat leaf;
    if(fstatat(dir,HARDWARE_NAME,&leaf,AT_SYMLINK_NOFOLLOW))rc=errno==ENOENT?0:-1;
    else rc=expected_file(dir,HARDWARE_NAME,st.st_dev,0644,hardware_payload,sizeof(hardware_payload)-1);
    close(dir);return rc;
}
static int hardware_installed(int root) {
    static const char *const parts[]={"etc","modprobe.d"};
    struct stat st;if(fstat(root,&st))return -1;
    int dir=parents(root,parts,2);if(dir<0)return -1;
    int rc=expected_file(dir,HARDWARE_NAME,st.st_dev,0644,hardware_payload,sizeof(hardware_payload)-1);
    close(dir);return rc;
}
static int busybox_verified(int root) {
    static const char *const parts[]={"usr","libexec","asus"};
    struct stat root_st,st;if(fstat(root,&root_st))return -1;
    int dir=parents(root,parts,3);if(dir<0)return -1;
    int fd=openat(dir,"busybox",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);close(dir);
    if(fd<0)return -1;
    int rc=-1;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       st.st_dev!=root_st.st_dev||(st.st_mode&07777)!=0755||st.st_size<=0||st.st_size>64*1024*1024||
       hash_fd(fd,(uint64_t)st.st_size,BUSYBOX_SHA))goto done;
    rc=0;
done:close(fd);return rc;
}
static int insmod_link(int dir,dev_t device,int allow_missing) {
    struct stat st;char target[128];
    if(fstatat(dir,"insmod",&st,AT_SYMLINK_NOFOLLOW))return allow_missing&&errno==ENOENT?0:-1;
    if(!S_ISLNK(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||st.st_dev!=device)return -1;
    ssize_t n=readlinkat(dir,"insmod",target,sizeof(target)-1);
    if(n<0||(size_t)n>=sizeof(target)-1)return -1;
    target[n]=0;return strcmp(target,INSMOD_TARGET)?-1:0;
}
static int insmod_parent(int root) {
    static const char *const parts[]={"usr","share","asus","commands","sbin"};
    return parents(root,parts,5);
}
static int insmod_preflight(int root) {
    struct stat st;if(fstat(root,&st)||busybox_verified(root))return -1;
    int dir=insmod_parent(root);if(dir<0)return -1;
    int rc=insmod_link(dir,st.st_dev,1);close(dir);return rc;
}
static int install_insmod(int root,int *created) {
    struct stat st;if(fstat(root,&st)||busybox_verified(root))return -1;
    int dir=insmod_parent(root);if(dir<0)return -1;
    int rc=-1;
    if(!symlinkat(INSMOD_TARGET,dir,"insmod"))*created=1;
    else if(errno!=EEXIST)goto done;
    if(insmod_link(dir,st.st_dev,0)||fsync(dir))goto done;
    rc=0;
done:close(dir);return rc;
}
static int preserve(int root,const struct context *context,struct preserved *saved) {
    static const char *const etc_parts[]={"etc"};
    static const char *const resolver_parts[]={"etc","systemd","system","leon-asus-resolver.path.d"};
    struct stat st;if(fstat(root,&st))return -1;
    int parent=leon_diag_parent_at(root);if(parent<0)return -1;
    int rc=-1,fd=-1,etc=-1,resolver=-1;char token[512];
    int n=snprintf(token,sizeof(token),
        "LEON_TRIAL_SLOT_V1\ngeneration %smetadata_sha256 %s\nstock_kernel_sha256 %s\nstock_rootfs_sha256 %s\n",
        SLOT_GENERATION,context->metadata_sha,SLOT_KERNEL_SHA,SLOT_ROOTFS_SHA);
    if(n<=0||(size_t)n>=sizeof(token)||
       expected_file(parent,"root-generation",st.st_dev,0644,SLOT_GENERATION,sizeof(SLOT_GENERATION)-1)||
       save_file(parent,"trial-slot-proof",st.st_dev,0600,(size_t)n,&saved->token)||memcmp(saved->token.bytes,token,(size_t)n))goto done;
    /* Read-only descriptor: diagnostic contents are never initialized/reset. */
    fd=openat(parent,LEON_DIAG_NAME,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0||leon_diag_file(fd,st.st_dev)||leon_diag_fiemap(fd,&saved->diagnostic_map)||
       save_file(parent,LEON_DIAG_NAME,st.st_dev,0600,LEON_DIAG_BYTES,&saved->diagnostic))goto done;
    struct stat diag_st;if(fstat(fd,&diag_st)||diag_st.st_ino!=saved->diagnostic.st.st_ino)goto done;
    resolver=parents(root,resolver_parts,4);
    if(resolver<0||save_file(resolver,"10-leon-ordering.conf",st.st_dev,0644,sizeof(resolver_payload)-1,&saved->resolver)||
       memcmp(saved->resolver.bytes,resolver_payload,sizeof(resolver_payload)-1))goto done;
    etc=parents(root,etc_parts,1);
    if(etc<0||fstatat(etc,"resolv.conf",&saved->resolver_link,AT_SYMLINK_NOFOLLOW)||
       !S_ISLNK(saved->resolver_link.st_mode)||saved->resolver_link.st_uid||saved->resolver_link.st_gid||
       saved->resolver_link.st_nlink!=1||saved->resolver_link.st_dev!=st.st_dev)goto done;
    ssize_t length=readlinkat(etc,"resolv.conf",saved->resolver_target,sizeof(saved->resolver_target)-1);
    if(length<0||(size_t)length>=sizeof(saved->resolver_target)-1)goto done;
    saved->resolver_target[length]=0;
    if(strcmp(saved->resolver_target,"/run/asus/native-resolv.conf"))goto done;
    rc=0;
done:if(fd>=0)close(fd);if(etc>=0)close(etc);if(resolver>=0)close(resolver);close(parent);return rc;
}
static int preserved_equal(const struct preserved *a,const struct preserved *b) {
    return file_equal(&a->diagnostic,&b->diagnostic)&&file_equal(&a->token,&b->token)&&file_equal(&a->resolver,&b->resolver)&&
        !memcmp(&a->diagnostic_map,&b->diagnostic_map,sizeof(a->diagnostic_map))&&
        a->resolver_link.st_dev==b->resolver_link.st_dev&&a->resolver_link.st_ino==b->resolver_link.st_ino&&
        a->resolver_link.st_mode==b->resolver_link.st_mode&&!strcmp(a->resolver_target,b->resolver_target);
}
static int install_hardware_order(int root,int *created) {
    struct stat st;if(fstat(root,&st)||leon_diag_directory(root,st.st_dev))return -1;
    int rc=-1,fd=-1,dir=-1,etc=safe_dir(root,"etc",st.st_dev,0);if(etc<0)return -1;
    dir=safe_dir(etc,"modprobe.d",st.st_dev,1);if(dir<0)goto done;
    fd=openat(dir,HARDWARE_NAME,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0) {
        if(errno!=EEXIST||expected_file(dir,HARDWARE_NAME,st.st_dev,0644,hardware_payload,sizeof(hardware_payload)-1))goto done;
        rc=0;goto done;
    }
    *created=1;
    if(fchmod(fd,0644))goto done;
    size_t used=0;
    while(used<sizeof(hardware_payload)-1) {
        ssize_t n=write(fd,hardware_payload+used,sizeof(hardware_payload)-1-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto done;
        used+=(size_t)n;
    }
    if(fsync(fd)||fsync(dir)||expected_file(dir,HARDWARE_NAME,st.st_dev,0644,hardware_payload,sizeof(hardware_payload)-1))goto done;
    rc=0;
done:if(fd>=0)close(fd);if(dir>=0)close(dir);close(etc);return rc;
}

#ifndef HARDWARE_PROVISION_MAIN
#define HARDWARE_PROVISION_MAIN main
#endif
int HARDWARE_PROVISION_MAIN(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--install-hardware-order")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,payload_created=0,alias_created=0,volume_fd=-1;
    struct stat self,init,st;struct statfs fs;struct statvfs vfs;struct preserved before,after;
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
    stage="preserve-token-diagnostics-and-resolver";
    if(preserve(root,&context,&before))goto done;
    stage="preflight-both-config-and-private-insmod";
    if(hardware_preflight(root)||insmod_preflight(root))goto done;
    stage="install-private-insmod-alias";
    if(install_insmod(root,&alias_created))goto done;
    stage="install-exact-hardware-order";
    if(install_hardware_order(root,&payload_created))goto done;
    stage="sync-readback-and-preservation";
    if(syncfs(root)||recheck(&context)||hardware_installed(root)||insmod_preflight(root)||
       preserve(root,&context,&after)||!preserved_equal(&before,&after))goto done;
    int alias_parent=insmod_parent(root);struct stat root_st;
    if(alias_parent<0)goto done;
    int alias_rc=fstat(root,&root_st)||insmod_link(alias_parent,root_st.st_dev,0);close(alias_parent);
    if(alias_rc)goto done;
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
    if(rc)fprintf(stderr,"LEON_HARDWARE_ORDER_REFUSED stage=%s payload_created=%d alias_created=%d retained_for_review=true\n",stage,payload_created,alias_created);
    else printf("{\"schema\":1,\"status\":\"hardware_order_installed\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"payload_sha256\":\"%s\",\"payload_created\":%s,\"alias_created\":%s,\"token_diagnostics_resolver_unchanged\":true,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],HARDWARE_PAYLOAD_SHA,payload_created?"true":"false",alias_created?"true":"false");
    return rc;
}
