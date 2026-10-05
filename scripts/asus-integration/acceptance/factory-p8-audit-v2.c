/* SPDX-License-Identifier: GPL-2.0-or-later
 * Fixed stock2/p8 factory-leaf audit. Build beside a pinned copy named frozen/.
 * v2 mounts private RAM tmpfs over the existing /tmp before creating a directory.
 * Only temporary lock/directory state is created. No device or factory writes,
 * filesystem recovery, subprocess execution, or factory contents are exported.
 */
#define main frozen_forensics_main
#include "frozen/coordinator.c"
#undef main

/* The included historical entry point has no usable export implementation. */
int forensic_export(int root) { (void)root; return -1; }

#define FACTORY_DEVICE "/dev/mmcblk0p8"
#define FACTORY_MAX 196608U
static int factory_failure_errno;
static const char factory_boot[] = "00000000-0000-4000-8000-000000000022\n";
static const unsigned char factory_uuid[16] = {
    0xb3,0x3c,0x1d,0x3a,0xf5,0xa1,0x4b,0xeb,0xb0,0xfe,0xed,0xfd,0xec,0xba,0x95,0x7d
};

static void factory_hash(const unsigned char *data, size_t size, char out[65]) {
    struct sha256_state hash; unsigned char digest[32];
    sha256_init(&hash); sha256_update(&hash,data,(unsigned)size); sha256_final(&hash,digest);
    for(unsigned i=0;i<32;i++)snprintf(out+2*i,3,"%02x",digest[i]);
}

static int factory_gpt(void) {
    int fd=open("/dev/mmcblk0",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK),rc=-1,sector=0;
    struct stat st; uint64_t size=0; unsigned char data[17408]; char hash[65];
    if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISBLK(st.st_mode)||major(st.st_rdev)!=179||minor(st.st_rdev)||
       ioctl(fd,BLKGETSIZE64,&size)||size!=UINT64_C(31347965952)||
       ioctl(fd,BLKSSZGET,&sector)||sector!=512)goto done;
    if(pread(fd,data,17408,0)!=17408)goto done;
    factory_hash(data,17408,hash);
    if(strcmp(hash,"a3d196fc60df1a2bec67518dfed09e6221a28174ef46b52960a01b01ad618c43"))goto done;
    if(pread(fd,data,16896,(off_t)UINT64_C(31347949056))!=16896)goto done;
    factory_hash(data,16896,hash);
    if(strcmp(hash,"6ab2bc3a8ad5ff4d500cce84fe202e1ecef818c3da2455db095621e1fc87f86a"))goto done;
    rc=0;
done:close(fd);return rc;
}

static int factory_device(void) {
    if(exact("/proc/sys/kernel/random/boot_id",factory_boot)||
       exact("/sys/class/block/mmcblk0p8/dev","179:8\n")||
       exact("/sys/class/block/mmcblk0p8/start","1232896\n")||
       exact("/sys/class/block/mmcblk0p8/size","40960\n"))return -1;
    int fd=open(FACTORY_DEVICE,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    struct stat st; uint64_t size=0; unsigned char sb[1024];
    if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISBLK(st.st_mode)||major(st.st_rdev)!=179||minor(st.st_rdev)!=8||
       ioctl(fd,BLKGETSIZE64,&size)||size!=UINT64_C(20971520)||
       pread(fd,sb,sizeof(sb),1024)!=(ssize_t)sizeof(sb)||
       sb[56]!=0x53||sb[57]!=0xef||memcmp(sb+104,factory_uuid,16)) {
        close(fd);return -1;
    }
    return fd;
}

static bool factory_flag(const char *flags,const char *wanted) {
    size_t want=strlen(wanted);
    for(const char *p=flags;*p;) {
        size_t n=strcspn(p,",");if(n==want&&!memcmp(p,wanted,n))return true;
        p+=n;if(*p)p++;
    }
    return false;
}

/* Parent mount IDs are pinned. CLONE_NEWNS assigns fresh child mount IDs,
 * so child checks require the same complete semantic rows with remapped IDs.
 * Only the child's fixed readonly bind is an accepted additional p8 view.
 */
static int factory_mount_view(const char *allowed,bool private_ns,bool covered_tmp,dev_t fresh_tmp) {
    static const char *baseline[2]={
        "19 15 179:8 / /tmp/mnt/defaults rw,relatime - ext4 /dev/defaults rw\n",
        "24 23 179:8 / /tmp/mnt/defaults rw,relatime - ext4 /dev/defaults rw\n"
    };
    static const char baseline_tail[]="179:8 / /tmp/mnt/defaults rw,relatime - ext4 /dev/defaults rw\n";
    static const char cover[]="25 11 0:16 / /tmp rw,relatime - tmpfs tmpfs rw\n";
    static const char cover_tail[]="0:16 / /tmp rw,relatime - tmpfs tmpfs rw\n";
    FILE *f=fopen("/proc/self/mountinfo","re");if(!f)return -1;
    char *line=NULL;size_t cap=0;unsigned lines=0,found=0,seen=0,covers=0,base_count=0,fresh_count=0;int rc=-1;
    while(getline(&line,&cap,f)>0) {
        unsigned id,parent,maj,min;char root[PATH_MAX],path[PATH_MAX],flags[256];
        if(++lines>4096||strlen(line)>16384||
           sscanf(line,"%u %u %u:%u %4095s %4095s %255s",&id,&parent,&maj,&min,root,path,flags)!=7)goto done;
        char *tail=strchr(line,' ');if(!tail||(tail=strchr(tail+1,' '))==NULL)goto done;tail++;
        if(!(private_ns?strcmp(tail,cover_tail):strcmp(line,cover))&&++covers!=1)goto done;
        char *split=strstr(line," - ");char type[64],source[PATH_MAX],super[256];
        if(!split||sscanf(split+3,"%63s %4095s %255s",type,source,super)!=3)goto done;
        if(!strcmp(path,"/tmp")&&strcmp(tail,cover_tail)) {
            if(!private_ns||covered_tmp||!fresh_tmp||++fresh_count!=1||maj||
               makedev(maj,min)!=fresh_tmp||strcmp(root,"/")||strcmp(type,"tmpfs")||strcmp(source,"tmpfs")||
               !factory_flag(flags,"rw")||!factory_flag(flags,"nodev")||
               !factory_flag(flags,"nosuid")||!factory_flag(flags,"noexec")||!factory_flag(super,"rw"))goto done;
        }
        if(maj==179&&min==8) {
            if(private_ns&&!strcmp(tail,baseline_tail)) {if(++base_count>2)goto done;continue;}
            if(!private_ns&&!strcmp(line,baseline[0])) {if(seen&1U)goto done;seen|=1U;continue;}
            if(!private_ns&&!strcmp(line,baseline[1])) {if(seen&2U)goto done;seen|=2U;continue;}
            if(!allowed||++found!=1||strcmp(root,"/")||strcmp(path,allowed)||
               !strstr(line," - ext4 ")||!factory_flag(flags,"ro")||
               !factory_flag(flags,"nodev")||!factory_flag(flags,"nosuid")||!factory_flag(flags,"noexec"))goto done;
        }
    }
    if(!ferror(f)&&(private_ns?base_count==2:seen==3U)&&
       covers==(covered_tmp?1U:0U)&&fresh_count==(fresh_tmp?1U:0U)&&found==(allowed?1U:0U))rc=0;
done:free(line);fclose(f);return rc;
}

/* Claim the MAC only for a wholly printable, terminated key=value token list. */
static bool factory_tokens(const unsigned char *data,size_t size,bool *match) {
    static const char key[]="et0macaddr",value[]="02:00:00:F0:00:01";
    unsigned count=0;bool exact_value=false;
    if(!size||(data[size-1]!=0&&data[size-1]!='\n'))return false;
    for(size_t begin=0;begin<size;) {
        size_t end=begin;while(end<size&&data[end]&&data[end]!='\n')end++;
        if(end==size)return false;
        size_t stop=end;if(stop>begin&&data[stop-1]=='\r'&&data[end]=='\n')stop--;
        if(stop>begin) {
            size_t eq=begin;
            for(size_t i=begin;i<stop;i++)if(data[i]<32||data[i]>126)return false;
            while(eq<stop&&data[eq]!='=')eq++;
            if(eq==begin||eq==stop)return false;
            for(size_t i=begin;i<eq;i++) {
                unsigned char c=data[i];
                if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
                     c=='_'||c==':'||c=='.'||c=='/'||c=='-'))return false;
            }
            if(eq-begin==sizeof(key)-1&&!memcmp(data+begin,key,sizeof(key)-1)) {
                count++;exact_value=stop-eq-1==sizeof(value)-1&&!memcmp(data+eq+1,value,sizeof(value)-1);
            }
        }
        begin=end+1;
    }
    *match=count==1&&exact_value;return true;
}

static int factory_child(int block) {
    int source_root=-1,tmp_root=-1,root=-1,wl=-1,leaf=-1,rc=-1,failure_errno=0;
    const char *failure_stage=NULL;
    bool private_ns=false,temp_created=false,tmp_mounted=false,view_created=false,bind_mounted=false;
    bool structured=false,match=false;dev_t fresh_tmp=0;
    char temporary[]="/tmp/leon-factory-p8-private.XXXXXX",view[PATH_MAX],source[64];
    struct stat before,after;struct statfs fs;struct statvfs vfs;
    unsigned char *data=NULL;size_t size=0,used=0;char hash[65];
#define FACTORY_CALL(label,expression) do {stage=(label);if((expression)){failure_errno=errno;goto done;}}while(0)
    FACTORY_CALL("private-namespace-unshare",unshare(CLONE_NEWNS));
    private_ns=true;
    FACTORY_CALL("private-namespace-propagation",mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    FACTORY_CALL("private-namespace-chdir",chdir("/"));
    stage="copied-baseline-mount-check";if(factory_mount_view(NULL,true,true,0))goto done;
    /* Only the child's copied cover is detached; parent mounts stay unchanged. */
    FACTORY_CALL("copied-tmp-cover-detach",umount2("/tmp",MNT_DETACH));
    stage="revealed-baseline-mount-check";if(factory_mount_view(NULL,true,false,0))goto done;
    FACTORY_CALL("revealed-p8-root-open",(source_root=open("/tmp/mnt/defaults",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0);
    FACTORY_CALL("revealed-p8-root-stat",fstat(source_root,&before));
    FACTORY_CALL("revealed-p8-root-statfs",fstatfs(source_root,&fs));
    stage="revealed-p8-root-identity";
    if(major(before.st_dev)!=179||minor(before.st_dev)!=8||before.st_ino!=2||fs.f_type!=EXT4_SUPER_MAGIC)goto done;
    /* Mount over the EXISTING /tmp directory before creating anything. Its
     * lower stock filesystem may be read-only. Only this private tmpfs changes.
     * Holding source_root keeps the covered p8 root available for the bind.
     */
    FACTORY_CALL("private-tmpfs-mount",mount("tmpfs","/tmp","tmpfs",MS_NODEV|MS_NOSUID|MS_NOEXEC,"mode=0700,size=1048576"));
    tmp_mounted=true;
    FACTORY_CALL("private-tmpfs-root-open",(tmp_root=open("/tmp",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0);
    FACTORY_CALL("private-tmpfs-root-stat",fstat(tmp_root,&before));
    FACTORY_CALL("private-tmpfs-root-statfs",fstatfs(tmp_root,&fs));
    FACTORY_CALL("private-tmpfs-root-statvfs",fstatvfs(tmp_root,&vfs));
    stage="private-tmpfs-identity";
    if(major(before.st_dev)||!minor(before.st_dev)||before.st_uid||(before.st_mode&07777)!=0700||
       fs.f_type!=TMPFS_MAGIC||(vfs.f_flag&ST_RDONLY))goto done;
    fresh_tmp=before.st_dev;
    stage="private-tmpfs-mount-check";if(factory_mount_view(NULL,true,false,fresh_tmp))goto done;
    FACTORY_CALL("private-tmpdir-create",!mkdtemp(temporary));temp_created=true;
    stage="private-bind-path";
    if(snprintf(view,sizeof(view),"%s/view",temporary)>=(int)sizeof(view))goto done;
    FACTORY_CALL("private-bind-directory-create",mkdir(view,0700));view_created=true;
    snprintf(source,sizeof(source),"/proc/self/fd/%d",source_root);
    FACTORY_CALL("private-bind-mount",mount(source,view,NULL,MS_BIND,NULL));bind_mounted=true;
    /* Change only this bind's VFS flags. No leaf is opened via the RW source. */
    FACTORY_CALL("private-bind-remount-readonly",mount(NULL,view,NULL,MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL));
    close(source_root);source_root=-1;
    FACTORY_CALL("readonly-auditor-root-open",(root=open(view,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0);
    FACTORY_CALL("readonly-auditor-root-stat",fstat(root,&before));
    FACTORY_CALL("readonly-auditor-root-statfs",fstatfs(root,&fs));
    FACTORY_CALL("readonly-auditor-root-statvfs",fstatvfs(root,&vfs));
    stage="readonly-auditor-root-identity";
    if(major(before.st_dev)!=179||minor(before.st_dev)!=8||before.st_ino!=2||
       fs.f_type!=EXT4_SUPER_MAGIC||!(vfs.f_flag&ST_RDONLY))goto done;
    stage="readonly-bind-mount-check";if(factory_mount_view(view,true,false,fresh_tmp))goto done;
    FACTORY_CALL("fixed-wl-directory-open",(wl=openat(root,"wl",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0);
    FACTORY_CALL("fixed-factory-leaf-open",(leaf=openat(wl,"nvram.nvm",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK))<0);
    FACTORY_CALL("fixed-factory-leaf-stat",fstat(leaf,&before));
    stage="fixed-factory-leaf-identity";
    if(!S_ISREG(before.st_mode)||major(before.st_dev)!=179||minor(before.st_dev)!=8||
       before.st_size<=0||before.st_size>FACTORY_MAX)goto done;
    size=(size_t)before.st_size;
    FACTORY_CALL("factory-buffer-allocation",(data=malloc(size))==NULL);
    stage="bounded-factory-leaf-read";
    while(used<size) {
        ssize_t n=read(leaf,data+used,size-used);if(n<0&&errno==EINTR)continue;
        if(n<=0){if(n<0)failure_errno=errno;goto done;}used+=(size_t)n;
    }
    unsigned char extra;ssize_t n;do{n=read(leaf,&extra,1);}while(n<0&&errno==EINTR);
    if(n){if(n<0)failure_errno=errno;goto done;}
    FACTORY_CALL("factory-leaf-final-stat",fstat(leaf,&after));
    stage="factory-leaf-stability";
    if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||
       before.st_mode!=after.st_mode||before.st_uid!=after.st_uid||before.st_gid!=after.st_gid||
       before.st_nlink!=after.st_nlink||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||
       before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)goto done;
    factory_hash(data,size,hash);structured=factory_tokens(data,size,&match);rc=0;
done:
    if(rc)failure_stage=stage;
    if(data){volatile unsigned char *wipe=data;for(size_t i=0;i<size;i++)wipe[i]=0;free(data);}
    if(leaf>=0)close(leaf);if(wl>=0)close(wl);if(root>=0)close(root);
    if(source_root>=0)close(source_root);if(tmp_root>=0)close(tmp_root);close(block);
#define FACTORY_CLEAN(label,expression) do {if((expression)){if(!rc){failure_stage=(label);failure_errno=errno;}rc=-1;}}while(0)
    if(bind_mounted) {
        int failed=umount2(view,0);
        if(failed){if(!rc){failure_stage="private-bind-release";failure_errno=errno;}rc=-1;}
        else bind_mounted=false;
    }
    if(!bind_mounted&&view_created)FACTORY_CLEAN("private-bind-directory-remove",rmdir(view));
    if(!bind_mounted&&temp_created)FACTORY_CLEAN("private-tmpdir-remove",rmdir(temporary));
    if(tmp_mounted) {
        int failed=umount2("/tmp",0);
        if(failed){if(!rc){failure_stage="private-tmpfs-release";failure_errno=errno;}rc=-1;}
        else tmp_mounted=false;
    }
    if(private_ns&&factory_mount_view(NULL,true,false,0)) {
        if(!rc){failure_stage="released-baseline-mount-check";failure_errno=0;}rc=-1;
    }
    if(rc){stage=failure_stage?failure_stage:stage;factory_failure_errno=failure_errno;return rc;}
    stage="private-bind-and-tmpfs-released";
    int written=dprintf(1,"{\"schema\":1,\"auditor_version\":2,\"boot_id\":\"00000000-0000-4000-8000-000000000022\","
            "\"leaf\":\"/wl/nvram.nvm\",\"bytes\":%zu,\"uid\":%u,\"gid\":%u,"
            "\"mode\":\"%04o\",\"inode\":%llu,\"mtime_seconds\":%lld,\"sha256\":\"%s\","
            "\"private_readonly_bind\":true,\"no_fs_recovery\":true,\"private_mount_released\":true,\"token_structure\":%s",
            size,(unsigned)before.st_uid,(unsigned)before.st_gid,before.st_mode&07777,
            (unsigned long long)before.st_ino,(long long)before.st_mtim.tv_sec,hash,structured?"true":"false");
    if(written<0||(structured&&dprintf(1,",\"unique_enrolled_et0macaddr\":%s",match?"true":"false")<0)||dprintf(1,"}\n")<0) {
        stage="audit-summary-output";factory_failure_errno=errno;return -1;
    }
    return 0;
#undef FACTORY_CLEAN
#undef FACTORY_CALL
}

int main(int argc,char **argv) {
    struct rlimit no_core={0,0};char mountpoint[]="/tmp/leon-factory-p8-audit.XXXXXX";
    int result=1,lock=-1,block=-1;bool created=false;struct stat st;
    if(argc!=2||strcmp(argv[1],"--audit-p8-readonly"))return 64;
    if(getuid()||geteuid()||setrlimit(RLIMIT_CORE,&no_core)||prctl(PR_SET_DUMPABLE,0)||clearenv())return 125;
    umask(077);alarm(180);stage="exclusive-identity-lock";
    lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||
       (st.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB))goto done;
    if(device_preflight())goto done;
    stage="fixed-boot-gpt-and-p8";
    if(factory_gpt()||(block=factory_device())<0||factory_mount_view(NULL,false,true,0)||
       leon_p11_clear_view(NULL)||!mkdtemp(mountpoint))goto done;
    created=true;pid_t parent=getpid(),child=fork();if(child<0)goto done;
    if(!child) {
        alarm(30);if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(125);
        int rc=factory_child(block);
        if(rc)dprintf(2,"LEON_FACTORY_REFUSED stage=%s errno=%d\n",stage,factory_failure_errno);_exit(rc?1:0);
    }
    close(block);block=-1;
    int status;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    stage="child-completion";if(waited!=child||!WIFEXITED(status)||WEXITSTATUS(status))goto done;
    stage="private-mount-released";
    if(exact("/proc/sys/kernel/random/boot_id",factory_boot)||factory_gpt()||
       factory_mount_view(NULL,false,true,0)||mount_identity()||leon_p11_clear_view(NULL))goto done;
    result=0;
done:
    if(block>=0)close(block);if(created&&rmdir(mountpoint))result=1;if(lock>=0)close(lock);
    dprintf(2,result?"LEON_FACTORY_REFUSED stage=%s\n":
            "LEON_FACTORY_COMPLETE stage=%s readonly_bind=true no_fs_recovery=true guest_exec=false\n",stage);
    return result;
}
