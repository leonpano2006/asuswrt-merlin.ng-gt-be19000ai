/* Fixed-device e2fsck preen transaction; never mounts or provisions p11. */
#define _GNU_SOURCE
static int leon_recovery_allow_dirty;
#define main unused_frozen_slot_proof_main
#include "slot-device-dirty.c"
#undef main
#include "recovery-run.h"
struct recovery_child {int tool,volume,lock;char path[64];};
static void recovery_exec(void *opaque) {
    struct recovery_child *c=opaque;
    /* Keep the exact block inode and flock alive across exec and parent death. */
    if(fcntl(c->volume,F_SETFD,0)||fcntl(c->lock,F_SETFD,0))_exit(125);
    char *const args[]={"e2fsck","-p",c->path,NULL};
    char *const env[]={"LC_ALL=C","PATH=/usr/sbin:/sbin:/usr/bin:/bin",NULL};
    fexecve(c->tool,args,env);_exit(125);
}
int main(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--recover-p11")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    struct leon_recovery_result child={0};struct recovery_child descriptors={-1,-1,-1,{0}};
    int rc=1;struct stat self,init,st;struct statfs fs;struct statvfs vfs;
    if(setrlimit(RLIMIT_CORE,&limit)||prctl(PR_SET_DUMPABLE,0)||clearenv())return 125;
    umask(077);alarm(300);stage="stock-root-and-native-namespace";
    if(getuid()||geteuid()||stat("/proc/self/ns/mnt",&self)||stat("/proc/1/ns/mnt",&init)||
       self.st_dev!=init.st_dev||self.st_ino!=init.st_ino||stat("/",&st)||major(st.st_dev)!=179||minor(st.st_dev)!=6||
       statfs("/",&fs)||fs.f_type!=SQUASHFS_MAGIC||statvfs("/",&vfs)||!(vfs.f_flag&ST_RDONLY))goto done;
    stage="shared-identity-provision-lock";
    descriptors.lock=open("/tmp/leon-device-identity.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(descriptors.lock<0||fstat(descriptors.lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       (st.st_mode&07777)!=0600||flock(descriptors.lock,LOCK_EX|LOCK_NB))goto done;
    leon_recovery_allow_dirty=1;
    if(recheck(&context))goto done;
    stage="private-unchanged-mount-view";
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||recheck(&context))goto done;
    stage="pinned-stock-e2fsck";
    descriptors.tool=open("/usr/sbin/e2fsck",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(descriptors.tool<0||fstat(descriptors.tool,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||
       st.st_nlink!=1||(st.st_mode&07777)!=0755||st.st_size!=240060||major(st.st_dev)!=179||minor(st.st_dev)!=6||
       fstatfs(descriptors.tool,&fs)||fs.f_type!=SQUASHFS_MAGIC||
       hash_fd(descriptors.tool,240060,"445fa52992ec66f2bd60d033b2994da65da56102d4713ec34703399919788883"))goto done;
    stage="filesystem-uuid-enrolled-fd";
    descriptors.volume=block_open(11,slot_parts[10].sectors*UINT64_C(512));
    unsigned char sb[120];
    if(descriptors.volume<0||read_range(descriptors.volume,sb,sizeof(sb),1024)||sb[56]!=0x53||sb[57]!=0xef||memcmp(sb+104,slot_parts[10].uuid,16))goto done;
    snprintf(descriptors.path,sizeof(descriptors.path),"/proc/self/fd/%d",descriptors.volume);
    if(recheck(&context))goto done;
    stage="single-preen-child";
    /* No parent alarm may release the lock before a killed D-state child is
     * reaped. The child also inherits the lock if the coordinator disappears. */
    alarm(0);
    if(leon_recovery_run(recovery_exec,&descriptors,120000,&child))goto done;
    alarm(300);leon_recovery_allow_dirty=0;
    stage="strict-clean-storage-recheck";
    if(recheck(&context))goto done;
    rc=0;
done:
    if(descriptors.volume>=0)close(descriptors.volume);
    if(descriptors.tool>=0)close(descriptors.tool);
    if(descriptors.lock>=0)close(descriptors.lock);
    if(child.bytes){fputs("LEON_RECOVERY_E2FSCK_OUTPUT_BEGIN\n",stderr);fwrite(child.output,1,child.bytes,stderr);fputs("\nLEON_RECOVERY_E2FSCK_OUTPUT_END\n",stderr);}
    if(rc)fprintf(stderr,"LEON_RECOVERY_REFUSED stage=%s started=%u reaped=%d timed_out=%d status=%d retries=0 mounted=false provisioned=false\n",stage,child.started,child.reaped,child.timed_out,child.status);
    else printf("{\"schema\":1,\"status\":\"p11_preen_completed_and_frozen_clean_gates_passed\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"e2fsck_exit\":%d,\"child_starts\":1,\"retries\":0,\"mounted\":false,\"provisioned\":false,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],WEXITSTATUS(child.status));
    return rc;
}
