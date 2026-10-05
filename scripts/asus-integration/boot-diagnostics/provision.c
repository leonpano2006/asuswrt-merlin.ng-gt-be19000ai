/* SPDX-License-Identifier: GPL-2.0-or-later
 * Includes an immutable, hash-checked slot-proof v7 device guard snapshot.
 * Its main is unreachable and removed by --gc-sections. No device selectors.
 */
#define _GNU_SOURCE
#define main unused_frozen_slot_proof_main
#include "slot-device.c"
#undef main
#include "boot-diagnostics.h"
#include "resolver-payload.h"

static int same_file(int parent,const char *name,dev_t dev,mode_t mode,const void *want,size_t size) {
    int fd=openat(parent,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    struct stat st;int rc=-1;unsigned char data[LEON_DIAG_BYTES];
    if(size>sizeof(data)||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       st.st_dev!=dev||(st.st_mode&07777)!=mode||st.st_size!=(off_t)size||read_range(fd,data,size,0)||memcmp(data,want,size))goto done;
    rc=0;
done:close(fd);return rc;
}
static int provision_identity(int root,const struct context *context) {
    struct stat st;if(fstat(root,&st))return -1;
    int parent=leon_diag_parent_at(root);if(parent<0)return -1;
    char token[512];int n=snprintf(token,sizeof(token),
        "LEON_TRIAL_SLOT_V1\ngeneration %smetadata_sha256 %s\nstock_kernel_sha256 %s\nstock_rootfs_sha256 %s\n",
        SLOT_GENERATION,context->metadata_sha,SLOT_KERNEL_SHA,SLOT_ROOTFS_SHA);
    int rc=n<=0||(size_t)n>=sizeof(token)||same_file(parent,"root-generation",st.st_dev,0644,SLOT_GENERATION,sizeof(SLOT_GENERATION)-1)||
        same_file(parent,"trial-slot-proof",st.st_dev,0600,token,(size_t)n)?-1:0;
    close(parent);return rc;
}
static int initialize_diag(int root,int *created) {
    struct stat st;unsigned char zero[LEON_DIAG_BYTES]={0};int rc=-1;
    if(fstat(root,&st))return -1;
    int parent=leon_diag_parent_at(root);if(parent<0)return -1;
    int fd=openat(parent,LEON_DIAG_NAME,O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_CREAT|O_EXCL,0600);
    if(fd<0) {
        if(errno!=EEXIST)goto done;
        fd=leon_diag_open_at(root,0);
        if(fd<0||same_file(parent,LEON_DIAG_NAME,st.st_dev,0600,zero,sizeof(zero)))goto done;
    } else {
        *created=1;
        /* Allocate by writing all zero bytes, never fallocate/unwritten extents. */
        if(fchmod(fd,0600))goto done;
        size_t used=0;while(used<sizeof(zero)) {
            ssize_t n=pwrite(fd,zero+used,sizeof(zero)-used,(off_t)used);
            if(n<0&&errno==EINTR)continue;
            if(n<=0)goto done;
            used+=(size_t)n;
        }
    }
    if(fsync(fd)||fsync(parent)||syncfs(root)||leon_diag_file(fd,st.st_dev)||
       same_file(parent,LEON_DIAG_NAME,st.st_dev,0600,zero,sizeof(zero)))goto done;
    rc=0;
done:if(fd>=0)close(fd);close(parent);return rc;
}
static int child_dir(int parent,const char *name,dev_t device,int create) {
    int made=0;
    if(create) {if(!mkdirat(parent,name,0755))made=1;else if(errno!=EEXIST)return -1;}
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    struct stat st;
    if(made && (fchmod(fd,0755)||fsync(fd)||fsync(parent))){close(fd);return -1;}
    if(fstat(fd,&st)||leon_diag_directory(fd,device)||(st.st_mode&07777)!=0755){close(fd);return -1;}
    return fd;
}
static int resolver_override(int root,int *created) {
    struct stat st;if(fstat(root,&st))return -1;
    const char *parts[]={"etc","systemd","system","leon-asus-resolver.path.d"};
    int dir=dup(root);if(dir<0)return -1;
    for(unsigned i=0;i<4;i++) {
        int next=child_dir(dir,parts[i],st.st_dev,i==3);close(dir);dir=next;if(dir<0)return -1;
    }
    const char *name="10-leon-ordering.conf";int rc=-1;
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0644);
    if(fd<0) {
        if(errno!=EEXIST||same_file(dir,name,st.st_dev,0644,resolver_payload,sizeof(resolver_payload)-1))goto done;
        rc=fsync(dir);goto done;
    }
    *created=1;
    if(fchmod(fd,0644))goto done;
    size_t used=0;while(used<sizeof(resolver_payload)-1) {
        ssize_t n=write(fd,resolver_payload+used,sizeof(resolver_payload)-1-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto done;
        used+=(size_t)n;
    }
    if(fsync(fd)||fsync(dir)||same_file(dir,name,st.st_dev,0644,resolver_payload,sizeof(resolver_payload)-1))goto done;
    rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
int main(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--initialize-diagnostics")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,diag_created=0,resolver_created=0,volume_fd=-1;
    struct stat self,init,st;struct statfs fs;struct statvfs vfs;
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
    mounted=1;context.mounted=1;
    close(volume_fd);volume_fd=-1;
    root=open(mountpoint,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root<0||fstatfs(root,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||fstatvfs(root,&vfs)||(vfs.f_flag&ST_RDONLY)||recheck(&context))goto done;
    stage="generation-and-existing-slot-proof";
    if(provision_identity(root,&context))goto done;
    stage="initialize-preallocated-diagnostics";
    if(initialize_diag(root,&diag_created))goto done;
    stage="fixed-resolver-ordering-override";
    if(resolver_override(root,&resolver_created))goto done;
    stage="sync-and-recheck";
    if(syncfs(root)||recheck(&context)||provision_identity(root,&context))goto done;
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
    if(rc)fprintf(stderr,"LEON_DIAGNOSTICS_REFUSED stage=%s diagnostic_created=%d resolver_created=%d retained_for_review=true\n",stage,diag_created,resolver_created);
    else printf("{\"schema\":1,\"status\":\"boot_diagnostics_initialized\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"diagnostic_created\":%s,\"resolver_created\":%s,\"diagnostic_bytes\":16384,\"initialized_extents_verified\":true,\"resolver_sha256\":\"%s\",\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],diag_created?"true":"false",resolver_created?"true":"false",RESOLVER_PAYLOAD_SHA);
    return rc;
}
