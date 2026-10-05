/* SPDX-License-Identifier: GPL-2.0-or-later
 * Inspect the frozen seven rescue leaf preflights and one socket link.
 * The builder changes only the inherited own-p11 mount predicates rw->ro.
 * Never call the included installer or its preservation/publication routines.
 */
#define RECOVERY_INSTALL_MAIN unused_frozen_rescue_install_main
#include "install.c"
#include "clean-superblock.h"

static int diag_clean(int fd,unsigned char sb[static 1024]) {
    if(read_range(fd,sb,1024,1024)||sb[56]!=0x53||sb[57]!=0xef||
       memcmp(sb+104,slot_parts[10].uuid,16)||sb[24]!=2||sb[25]||sb[26]||sb[27]||
       !leon_p11_superblock_clean(sb))return -1;
    return 0;
}

/* Paths come exclusively from the immutable payload header, never argv.
 * Only nofollow metadata is emitted. Unexpected symlink targets are not read.
 */
static const char *diag_kind(mode_t mode) {
    return S_ISDIR(mode)?"directory":S_ISREG(mode)?"regular":
        S_ISLNK(mode)?"symlink":S_ISBLK(mode)?"block":
        S_ISCHR(mode)?"character":S_ISFIFO(mode)?"fifo":
        S_ISSOCK(mode)?"socket":"other";
}
static void diag_stat(unsigned index,const char *role,const char *path,int error,
        const struct stat *st,dev_t device,mode_t expected) {
    printf("{\"record\":\"nofollow_metadata\",\"index\":%u,\"role\":\"%s\",\"path\":\"/%s\",\"errno\":%d,\"exists\":%s",
        index,role,path,error,error?"false":"true");
    if(!error)printf(",\"type\":\"%s\",\"mode\":\"%04o\",\"uid\":%u,\"gid\":%u,\"dev_major\":%u,\"dev_minor\":%u,\"inode\":%llu,\"nlink\":%llu,\"size\":%lld,\"same_device\":%s,\"root_owner\":%s,\"expected_mode\":\"%04o\",\"mode_matches\":%s",
        diag_kind(st->st_mode),(unsigned)(st->st_mode&07777),(unsigned)st->st_uid,
        (unsigned)st->st_gid,major(st->st_dev),minor(st->st_dev),
        (unsigned long long)st->st_ino,(unsigned long long)st->st_nlink,
        (long long)st->st_size,st->st_dev==device?"true":"false",
        !st->st_uid&&!st->st_gid?"true":"false",(unsigned)expected,
        (st->st_mode&07777)==expected?"true":"false");
    puts("}");
}
static void diag_leaf(int dir,unsigned index,const char *role,const char *prefix,
        const char *name,dev_t device,mode_t mode) {
    char path[1024];struct stat st;
    int n=snprintf(path,sizeof(path),"%s%s%s",prefix,*prefix?"/":"",name);
    if(n<=0||(size_t)n>=sizeof(path))return;
    errno=0;int rc=fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW),error=rc?errno:0;
    diag_stat(index,role,path,error,&st,device,mode);
}
static int diag_path(int root,unsigned index,const char *path,mode_t mode,int regular) {
    char copy[512],prefix[512]="";struct stat volume;
    if(strlen(path)>=sizeof(copy)||path[0]=='/'||fstat(root,&volume))return -1;
    strcpy(copy,path);char *save=NULL,*part=strtok_r(copy,"/",&save);
    int dir=dup(root);if(dir<0)return -1;
    unsigned parents_seen=0;
    for(;;) {
        if(!part||!strcmp(part,".")||!strcmp(part,"..")||strlen(part)>NAME_MAX) {close(dir);return -1;}
        char *next=strtok_r(NULL,"/",&save);
        if(!next) {
            diag_leaf(dir,index,"leaf",prefix,part,volume.st_dev,mode);
            if(regular) {
                char temp[NAME_MAX+1];int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",part);
                if(n<=0||(size_t)n>=sizeof(temp)){close(dir);return -1;}
                diag_leaf(dir,index,"exclusive_temp_must_be_absent",prefix,temp,volume.st_dev,0600);
            }
            close(dir);return 0;
        }
        if(++parents_seen>8){close(dir);return -1;}
        size_t used=strlen(prefix),need=strlen(part)+(used?1:0);
        if(used+need>=sizeof(prefix)){close(dir);return -1;}
        if(used)strcat(prefix,"/");
        strcat(prefix,part);
        struct stat st;errno=0;
        int stat_rc=fstatat(dir,part,&st,AT_SYMLINK_NOFOLLOW),error=stat_rc?errno:0;
        diag_stat(index,"parent",prefix,error,&st,volume.st_dev,0755);
        /* Missing/wrong parents are the diagnostic result, not an execution
         * error. Stop traversal without following a symlink or other device. */
        if(stat_rc||!S_ISDIR(st.st_mode)||st.st_uid||st.st_gid||
           st.st_dev!=volume.st_dev||(st.st_mode&07777)!=0755) {
            printf("{\"record\":\"traversal_stopped\",\"index\":%u,\"path\":\"/%s\",\"deeper_metadata_skipped\":true}\n",index,prefix);
            close(dir);return 0;
        }
        errno=0;int fd=openat(dir,part,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        error=fd<0?errno:0;
        if(fd<0) {
            printf("{\"record\":\"parent_open_refused\",\"index\":%u,\"path\":\"/%s\",\"errno\":%d}\n",index,prefix,error);
            close(dir);return 0;
        }
        struct stat after;
        if(fstat(fd,&after)||!candidate_stat_unchanged(&st,&after)) {close(fd);close(dir);return -1;}
        close(dir);dir=fd;part=next;
    }
}

int main(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--inspect-fixed-uplink-rescue-preflights")||
       !slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,volume_fd=-1;
    unsigned failed=0;struct stat self,init,st;struct statfs fs;struct statvfs vfs;
    unsigned char initial[1024],current[1024];char volume_path[64];
    if(setrlimit(RLIMIT_CORE,&limit)||prctl(PR_SET_DUMPABLE,0)||clearenv())return 125;
    umask(077);alarm(120);stage="stock-root-and-native-namespace";
    if(getuid()||geteuid()||stat("/proc/self/ns/mnt",&self)||stat("/proc/1/ns/mnt",&init)||
       self.st_dev!=init.st_dev||self.st_ino!=init.st_ino||stat("/",&st)||major(st.st_dev)!=179||minor(st.st_dev)!=6||
       statfs("/",&fs)||fs.f_type!=SQUASHFS_MAGIC||statvfs("/",&vfs)||!(vfs.f_flag&ST_RDONLY))goto done;
    stage="shared-identity-provision-lock";
    lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       (st.st_mode&07777)!=0600||flock(lock,LOCK_EX|LOCK_NB)||recheck(&context))goto done;
    stage="first-full-clean-superblock";
    volume_fd=block_open(11,slot_parts[10].sectors*UINT64_C(512));
    if(volume_fd<0||diag_clean(volume_fd,initial))goto done;
    snprintf(volume_path,sizeof(volume_path),"/proc/self/fd/%d",volume_fd);
    stage="private-namespace";
    if(!mkdtemp(mountpoint))goto done;
    created=1;
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))goto done;
    stage="second-full-clean-superblock-before-readonly-mount";
    if(diag_clean(volume_fd,current)||memcmp(initial,current,sizeof(initial)))goto done;
    stage="private-readonly-noload-mount";
    if(mount(volume_path,mountpoint,"ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))goto done;
    mounted=1;context.mounted=1;
    root=open(mountpoint,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root<0||fstat(root,&st)||major(st.st_dev)!=179||minor(st.st_dev)!=11||
       leon_diag_directory(root,st.st_dev)||fstatfs(root,&fs)||fs.f_type!=EXT4_SUPER_MAGIC||
       fstatvfs(root,&vfs)||!(vfs.f_flag&ST_RDONLY)||recheck(&context))goto done;
    stage="fixed-file-and-link-metadata";
    if(RECOVERY_PAYLOAD_COUNT!=7||RECOVERY_LINK_COUNT!=1)goto done;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++) {
        const struct recovery_payload *p=&recovery_payloads[i];struct candidate_leaf saved={0};
        if(p->old_sha||p->old_size||diag_path(root,i,p->path,p->mode,1))goto done;
        errno=0;int result=target_preflight(root,p,&saved),error=errno;
        if(result)failed++;
        printf("{\"record\":\"actual_preflight\",\"kind\":\"regular\",\"index\":%u,\"path\":\"/%s\",\"result\":%d,\"errno\":%d,\"present\":%s,\"already_identical\":%s,\"errno_may_be_inherited_from_predicate\":true}\n",
            i,p->path,result,error,saved.present?"true":"false",saved.already_new?"true":"false");
    }
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++) {
        const struct candidate_link *p=&recovery_links[i];struct stat leaf;int present=0;
        if(diag_path(root,7+i,p->path,0777,0))goto done;
        errno=0;int result=candidate_link_check(root,p,1,&present,&leaf),error=errno;
        if(result)failed++;
        printf("{\"record\":\"actual_preflight\",\"kind\":\"fixed_symlink\",\"index\":%u,\"path\":\"/%s\",\"result\":%d,\"errno\":%d,\"present\":%s,\"errno_may_be_inherited_from_predicate\":true}\n",
            7+i,p->path,result,error,present?"true":"false");
    }
    if(fflush(stdout)||ferror(stdout)||recheck(&context))goto done;
    stage="full-clean-superblock-before-unmount";
    if(diag_clean(volume_fd,current)||memcmp(initial,current,sizeof(initial)))goto done;
    close(root);root=-1;
    if(umount2(mountpoint,0))goto done;
    mounted=0;context.mounted=0;
    if(recheck(&context))goto done;
    stage="full-clean-superblock-after-unmount";
    if(diag_clean(volume_fd,current)||memcmp(initial,current,sizeof(initial)))goto done;
    rc=0;
done:
    if(root>=0)close(root);
    if(mounted&&umount2(mountpoint,0))rc=1;
    if(created&&rmdir(mountpoint))rc=1;
    if(volume_fd>=0)close(volume_fd);
    if(lock>=0)close(lock);
    if(rc)fprintf(stderr,"LEON_RESCUE_PREFLIGHT_DIAGNOSIS_REFUSED stage=%s failed_preflights=%u writes_to_p11=false armed=false rebooted=false\n",stage,failed);
    else {
        printf("{\"schema\":1,\"status\":\"fixed_rescue_preflight_metadata_inspected\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"payload_count\":7,\"link_count\":1,\"failed_preflights\":%u,\"writes_to_p11\":false,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],failed);
        if(fflush(stdout)||ferror(stdout))rc=1;
    }
    return rc;
}
