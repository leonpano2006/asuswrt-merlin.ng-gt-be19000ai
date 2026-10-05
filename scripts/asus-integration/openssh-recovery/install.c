/* SPDX-License-Identifier: GPL-2.0-or-later
 * Fixed, inactive p11 configuration overlay. Reuse the frozen stock2/device,
 * clean-ext4, shared-lock and prerequisite guards. Never run vendor code,
 * change accounts/keys, update boot metadata or enable a running service.
 */
#define BSP_UPDATE_MAIN unused_recovery_bsp_update_main
#include "bsp-provision.c"
#include "recovery-payload.h"
#include <linux/fs.h>
#include <sys/syscall.h>

struct recovery_saved { struct stat st; unsigned char digest[32]; };
static const char *const identity_paths[]={
    "etc/passwd","etc/shadow","etc/group","etc/gshadow","etc/machine-id",
    "etc/ssh/sshd_config","etc/pam.d/sshd",
    "etc/ssh/ssh_host_rsa_key","etc/ssh/ssh_host_rsa_key.pub",
    "etc/ssh/ssh_host_ecdsa_key","etc/ssh/ssh_host_ecdsa_key.pub",
    "etc/ssh/ssh_host_ed25519_key","etc/ssh/ssh_host_ed25519_key.pub",
    "var/lib/leon-asus-ssh/account","var/lib/leon-asus-ssh/device-identity",
    "var/lib/leon-asus-ssh/provision.lock"
};
#define IDENTITY_COUNT (sizeof(identity_paths)/sizeof(identity_paths[0]))
#define ENABLE_NAME "leon-asus-ssh-recovery.socket"
#define ENABLE_TARGET "/usr/lib/systemd/system/leon-asus-ssh-recovery.socket"

static int state_dir(int parent,dev_t device) {
    int fd=openat(parent,"leon-asus-ssh",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid||st.st_gid||st.st_dev!=device||
       ((st.st_mode&07777)!=0700&&(st.st_mode&07777)!=0755)) {close(fd);return -1;}
    return fd;
}
static int recovery_parent(int root,const char *path,int create,char name[NAME_MAX+1]) {
    char copy[512];struct stat st;
    if(strlen(path)>=sizeof(copy)||path[0]=='/'||fstat(root,&st)||leon_diag_directory(root,st.st_dev))return -1;
    strcpy(copy,path);char *save=NULL,*part=strtok_r(copy,"/",&save);
    int dir=dup(root);if(dir<0)return -1;
    for(;;) {
        if(!part||!strcmp(part,".")||!strcmp(part,"..")||strlen(part)>NAME_MAX) {close(dir);return -1;}
        char *next=strtok_r(NULL,"/",&save);
        if(!next){strcpy(name,part);return dir;}
        int fd=!strcmp(part,"leon-asus-ssh")?state_dir(dir,st.st_dev):safe_dir(dir,part,st.st_dev,create);
        close(dir);if(fd<0)return -1;dir=fd;part=next;
    }
}
static int identity_save(int root,const char *path,struct recovery_saved *out) {
    char name[NAME_MAX+1];int dir=recovery_parent(root,path,0,name);
    if(dir<0)return -1;
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);close(dir);
    struct stat volume,after;int rc=-1;unsigned char bytes[4096];
    if(fd<0)return -1;
    if(fstat(root,&volume)||fstat(fd,&out->st)||!S_ISREG(out->st.st_mode)||out->st.st_uid||
       out->st.st_dev!=volume.st_dev||out->st.st_nlink!=1||(out->st.st_mode&0022)||
       out->st.st_size<0||out->st.st_size>128*1024)goto done;
    struct sha256_state hash;sha256_init(&hash);off_t offset=0;
    while(offset<out->st.st_size) {
        size_t n=(size_t)(out->st.st_size-offset);if(n>sizeof(bytes))n=sizeof(bytes);
        if(read_range(fd,bytes,n,(uint64_t)offset))goto done;
        sha256_update(&hash,bytes,n);offset+=(off_t)n;
    }
    if(fstat(fd,&after)||after.st_size!=out->st.st_size||after.st_mtim.tv_sec!=out->st.st_mtim.tv_sec||
       after.st_mtim.tv_nsec!=out->st.st_mtim.tv_nsec)goto done;
    sha256_final(&hash,out->digest);rc=0;
done:explicit_bzero(bytes,sizeof(bytes));close(fd);return rc;
}
static int identity_equal(const struct recovery_saved *a,const struct recovery_saved *b) {
    return a->st.st_dev==b->st.st_dev&&a->st.st_ino==b->st.st_ino&&a->st.st_mode==b->st.st_mode&&
        a->st.st_uid==b->st.st_uid&&a->st.st_gid==b->st.st_gid&&a->st.st_nlink==b->st.st_nlink&&
        a->st.st_size==b->st.st_size&&a->st.st_mtim.tv_sec==b->st.st_mtim.tv_sec&&
        a->st.st_mtim.tv_nsec==b->st.st_mtim.tv_nsec&&!memcmp(a->digest,b->digest,sizeof(a->digest));
}
static int identity_all(int root,struct recovery_saved saved[IDENTITY_COUNT]) {
    for(unsigned i=0;i<IDENTITY_COUNT;i++)if(identity_save(root,identity_paths[i],&saved[i]))return -1;
    return 0;
}
static int enrolled_identity(int root) {
    static const char *const state_parts[]={"var","lib"};struct stat st;
    if(fstat(root,&st))return -1;
    int parent=parents(root,state_parts,2);if(parent<0)return -1;
    int state=state_dir(parent,st.st_dev);close(parent);if(state<0)return -1;
    const char account[]="LEON_SSH_ACCOUNT_V1 MastermixStudios 1000\n";
    int rc=expected_file(state,"account",st.st_dev,0600,account,sizeof(account)-1)||
        expected_file(state,"device-identity",st.st_dev,0600,"LEON_SSH_DEVICE_V1_OK\n",22);
    struct stat partial;
    if(!rc&&(!fstatat(state,"provision-in-progress",&partial,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT))rc=-1;
    close(state);if(rc)return -1;
    static const char *const ssh_parts[]={"etc","ssh"};
    int ssh=parents(root,ssh_parts,2);if(ssh<0)return -1;
    int fd=openat(ssh,"ssh_host_ed25519_key.pub",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);close(ssh);
    char key[2048];struct stat pub;rc=-1;
    if(fd<0)return -1;
    if(fstat(fd,&pub)||!S_ISREG(pub.st_mode)||pub.st_uid||pub.st_gid||pub.st_nlink!=1||
       pub.st_dev!=st.st_dev||(pub.st_mode&07777)!=0644||pub.st_size<=0||pub.st_size>=(off_t)sizeof(key)||
       read_range(fd,key,(size_t)pub.st_size,0))goto done;
    size_t n=sizeof(recovery_host_public)-1;
    if((size_t)pub.st_size<=n||memcmp(key,recovery_host_public,n)||
       (key[n]!=' '&&key[n]!='\n'))goto done;
    rc=0;
done:close(fd);return rc;
}
static int recovery_file(int dir,const char *name,dev_t device,const struct recovery_payload *p,mode_t mode,struct stat *out) {
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    int rc=-1;
    if(fstat(fd,out)||!S_ISREG(out->st_mode)||out->st_uid||out->st_gid||out->st_nlink!=1||
       out->st_dev!=device||(out->st_mode&07777)!=mode||out->st_size!=(off_t)p->size||
       hash_fd(fd,p->size,p->sha))goto done;
    rc=0;
done:close(fd);return rc;
}
static int target_preflight(int root,const struct recovery_payload *p) {
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat st,leaf;
    int dir=recovery_parent(root,p->path,1,name);if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name),rc=-1;
    if(n<0||(size_t)n>=sizeof(temp)||fstat(root,&st))goto done;
    if(!fstatat(dir,temp,&leaf,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(fstatat(dir,name,&leaf,AT_SYMLINK_NOFOLLOW))rc=errno==ENOENT?0:-1;
    else rc=recovery_file(dir,name,st.st_dev,p,0644,&leaf);
done:close(dir);return rc;
}
static int install_target(int root,const struct recovery_payload *p,unsigned *published,unsigned *temporary) {
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat volume,st,again;
    int dir=recovery_parent(root,p->path,0,name),fd=-1,rc=-1;
    if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name);
    if(n<0||(size_t)n>=sizeof(temp)||fstat(root,&volume))goto done;
    if(!fstatat(dir,temp,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(!recovery_file(dir,name,volume.st_dev,p,0644,&st)) {rc=0;goto done;}
    if(!fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    fd=openat(dir,temp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)goto done;
    (*temporary)++;if(fchmod(fd,0600))goto done;
    size_t used=0;
    while(used<p->size) {ssize_t got=write(fd,p->data+used,p->size-used);if(got<0&&errno==EINTR)continue;if(got<=0)goto done;used+=(size_t)got;}
    if(fsync(fd)||recovery_file(dir,temp,volume.st_dev,p,0600,&st)||fstat(fd,&again)||
       again.st_dev!=st.st_dev||again.st_ino!=st.st_ino||fchmod(fd,0644)||fsync(fd)||
       recovery_file(dir,temp,volume.st_dev,p,0644,&st))goto done;
    /* Do not replace a target created concurrently by an uncooperative writer. */
    if(syscall(SYS_renameat2,dir,temp,dir,name,RENAME_NOREPLACE))goto done;
    (*published)++;
    if(fsync(dir)||recovery_file(dir,name,volume.st_dev,p,0644,&again)||again.st_dev!=st.st_dev||again.st_ino!=st.st_ino)goto done;
    rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
static int enable_dir(int root,int create) {
    const char *const parts[]={"etc","systemd","system"};struct stat st;
    if(fstat(root,&st))return -1;
    int parent=parents(root,parts,3);if(parent<0)return -1;
    int dir=safe_dir(parent,"sys-subsystem-net-devices-br0.device.wants",st.st_dev,create);close(parent);return dir;
}
static int enable_link(int root,int allow_missing) {
    struct stat volume,st;char target[sizeof(ENABLE_TARGET)+8];
    int dir=enable_dir(root,allow_missing);if(dir<0)return -1;
    int rc=-1;if(fstat(root,&volume))goto done;
    if(fstatat(dir,ENABLE_NAME,&st,AT_SYMLINK_NOFOLLOW)){rc=allow_missing&&errno==ENOENT?0:-1;goto done;}
    if(!S_ISLNK(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||st.st_dev!=volume.st_dev)goto done;
    ssize_t n=readlinkat(dir,ENABLE_NAME,target,sizeof(target)-1);
    if(n<0||(size_t)n>=sizeof(target)-1)goto done;
    target[n]=0;rc=strcmp(target,ENABLE_TARGET)?-1:0;
done:close(dir);return rc;
}
static int install_recovery(int root,unsigned *published,unsigned *temporary,int *mode_changed,int *enabled) {
    if(enable_link(root,1))return -1;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)if(target_preflight(root,&recovery_payloads[i]))return -1;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)if(install_target(root,&recovery_payloads[i],published,temporary))return -1;
    static const char *const parts[]={"var","lib"};struct stat volume,st;
    if(fstat(root,&volume))return -1;
    int parent=parents(root,parts,2);if(parent<0)return -1;
    int state=state_dir(parent,volume.st_dev);close(parent);if(state<0)return -1;
    int rc=fstat(state,&st);
    if(!rc&&(st.st_mode&07777)!=0755) {rc=fchmod(state,0755);if(!rc)*mode_changed=1;}
    if(!rc)rc=fsync(state)||fstat(state,&st)||(st.st_mode&07777)!=0755;
    close(state);if(rc)return -1;
    int dir=enable_dir(root,0);if(dir<0)return -1;
    if(!symlinkat(ENABLE_TARGET,dir,ENABLE_NAME))*enabled=1;
    else if(errno!=EEXIST){close(dir);return -1;}
    rc=fsync(dir)||enable_link(root,0);close(dir);return rc?-1:0;
}

#ifndef RECOVERY_INSTALL_MAIN
#define RECOVERY_INSTALL_MAIN main
#endif
int RECOVERY_INSTALL_MAIN(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--install-native-recovery")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,volume_fd=-1,mode_changed=0,enabled=0;
    unsigned published=0,temporary=0;
    struct stat self,init,st;struct statfs fs;struct statvfs vfs;struct update_state before,after;
    struct recovery_saved identity_before[IDENTITY_COUNT],identity_after[IDENTITY_COUNT];
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
    stage="preserve-existing-device-and-native-identity";
    if(update_preserve(root,&context,&before)||enrolled_identity(root)||identity_all(root,identity_before))goto done;
    stage="install-independent-key-config-and-device-socket";
    if(install_recovery(root,&published,&temporary,&mode_changed,&enabled))goto done;
    stage="sync-readback-and-preservation";
    if(syncfs(root)||recheck(&context)||update_preserve(root,&context,&after)||!update_preserved_equal(&before,&after)||
       enrolled_identity(root)||identity_all(root,identity_after)||enable_link(root,0))goto done;
    for(unsigned i=0;i<IDENTITY_COUNT;i++)if(!identity_equal(&identity_before[i],&identity_after[i]))goto done;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++) {
        char name[NAME_MAX+1];int dir=recovery_parent(root,recovery_payloads[i].path,0,name);struct stat leaf,volume;
        if(dir<0)goto done;
        int failed=fstat(root,&volume)||recovery_file(dir,name,volume.st_dev,&recovery_payloads[i],0644,&leaf);close(dir);if(failed)goto done;
    }
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
    if(rc)fprintf(stderr,"LEON_RECOVERY_INSTALL_REFUSED stage=%s temporary=%u published=%u mode_changed=%d enabled=%d retained_for_review=true\n",stage,temporary,published,mode_changed,enabled);
    else printf("{\"schema\":1,\"status\":\"native_recovery_staged\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"published\":%u,\"mode_changed\":%s,\"socket_link_created\":%s,\"native_identity_unchanged\":true,\"prerequisites_unchanged\":true,\"package_database_updated\":false,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],published,mode_changed?"true":"false",enabled?"true":"false");
    return rc;
}
