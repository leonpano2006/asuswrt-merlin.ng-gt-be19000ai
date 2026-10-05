/* SPDX-License-Identifier: GPL-2.0-or-later
 * SOURCE-ONLY focused fixture. Never call production main/device guards.
 * The only runtime fault seam wraps the actual included write calls; fixture
 * seeding uses the original write function after the macro is undefined.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
static ssize_t fixture_write(int fd,const void *bytes,size_t size);
#define write fixture_write
#define RECOVERY_INSTALL_MAIN unused_candidate_production_main
#include "install.c"
#undef write
#include "fixture-inputs.h"

struct fixture_snapshot {
    struct recovery_saved identity[IDENTITY_COUNT];
    struct stat checks[RECOVERY_CHECK_COUNT],native_rule,old_timer;
};
struct fixture_case {
    int root,rc;
    char path[256];
    struct stat root_st;
    struct fixture_snapshot before,after;
    struct candidate_leaf leaves[RECOVERY_PAYLOAD_COUNT];
    struct candidate_link_state links[RECOVERY_LINK_COUNT];
    unsigned additions,replacements,temporary,links_created,boundary_calls;
};
static struct fixture_case *active_case;
static int fault_armed,fault_calls,fault_fd=-1;
static size_t fault_bytes;
static struct stat fault_inode;
#define FAULT_ROW 4U

static int fixture_boundary_recheck(void *unused) {
    (void)unused;
    if(!active_case)return -1;
    active_case->boundary_calls++;
    return 0;
}
static ssize_t fixture_write(int fd,const void *bytes,size_t size) {
    const struct recovery_payload *p=&recovery_payloads[FAULT_ROW];
    if(!fault_armed||!active_case)return write(fd,bytes,size);
    if(!fault_calls&&bytes==p->data) {
        char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat leaf;
        int dir=recovery_parent(active_case->root,p->path,0,name);
        if(dir<0){errno=EIO;return -1;}
        int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name);
        int bad=n<=0||(size_t)n>=sizeof(temp)||fstat(fd,&fault_inode)||
            fstatat(dir,temp,&leaf,AT_SYMLINK_NOFOLLOW)||
            !candidate_same_inode(&fault_inode,&leaf)||!S_ISREG(leaf.st_mode)||
            leaf.st_uid||leaf.st_gid||leaf.st_nlink!=1||
            (leaf.st_mode&07777)!=0600||leaf.st_dev!=active_case->root_st.st_dev;
        close(dir);
        if(bad){errno=EIO;return -1;}
        fault_fd=fd;size_t short_size=size/2;if(!short_size)short_size=1;
        ssize_t got=write(fd,bytes,short_size);
        if(got<=0)return got;
        fault_calls=1;fault_bytes=(size_t)got;return got;
    }
    if(fault_calls==1&&fd==fault_fd&&bytes==p->data+fault_bytes) {
        struct stat now;
        if(fstat(fd,&now)||!candidate_same_inode(&now,&fault_inode)){errno=EIO;return -1;}
        fault_calls=2;errno=EIO;return -1;
    }
    return write(fd,bytes,size);
}
static int fixture_dirs(int root,const char *path) {
    char copy[512];struct stat st;
    if(strlen(path)>=sizeof(copy)||fstat(root,&st))return -1;
    strcpy(copy,path);char *save=NULL,*part=strtok_r(copy,"/",&save);
    int dir=dup(root);if(dir<0)return -1;
    for(;part;part=strtok_r(NULL,"/",&save)) {
        if(!strcmp(part,".")||!strcmp(part,"..")){close(dir);return -1;}
        int next=safe_dir(dir,part,st.st_dev,1);close(dir);dir=next;
        if(dir<0)return -1;
    }
    close(dir);return 0;
}
static int fixture_parent_dirs(int root,const char *path) {
    char copy[512];if(strlen(path)>=sizeof(copy))return -1;
    strcpy(copy,path);char *slash=strrchr(copy,'/');
    if(!slash)return 0;
    *slash=0;return fixture_dirs(root,copy);
}
static int fixture_seed_bytes(int root,const char *path,const void *data,size_t size,mode_t mode) {
    char name[NAME_MAX+1];int dir=-1,fd=-1,rc=-1;
    if(fixture_parent_dirs(root,path))return -1;
    dir=recovery_parent(root,path,0,name);if(dir<0)return -1;
    fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)goto done;
    size_t used=0;
    while(used<size) {
        ssize_t got=write(fd,(const unsigned char *)data+used,size-used);
        if(got<0&&errno==EINTR)continue;
        if(got<=0)goto done;
        used+=(size_t)got;
    }
    if(fchmod(fd,mode)||fsync(fd)||fsync(dir))goto done;
    rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
static int fixture_seed_input(int root,const struct fixture_input *input) {
    int in=open(input->source,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK),out=-1,dir=-1,rc=-1;
    char name[NAME_MAX+1];struct stat st;unsigned char bytes[65536];
    if(in<0)return -1;
    if(fstat(in,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
       st.st_size!=(off_t)input->size||hash_fd(in,input->size,input->sha)||
       fixture_parent_dirs(root,input->target))goto done;
    dir=recovery_parent(root,input->target,0,name);if(dir<0)goto done;
    out=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(out<0)goto done;
    size_t used=0;
    while(used<input->size) {
        size_t n=input->size-used;if(n>sizeof(bytes))n=sizeof(bytes);
        if(read_range(in,bytes,n,used))goto done;
        size_t part=0;
        while(part<n) {
            ssize_t got=write(out,bytes+part,n-part);
            if(got<0&&errno==EINTR)continue;
            if(got<=0)goto done;
            part+=(size_t)got;
        }
        used+=n;
    }
    if(fchmod(out,input->mode)||fsync(out)||fsync(dir))goto done;
    rc=0;
done:if(out>=0)close(out);if(dir>=0)close(dir);close(in);return rc;
}
static int fixture_seed_link(int root,const struct candidate_link *p) {
    char name[NAME_MAX+1];
    if(fixture_parent_dirs(root,p->path))return -1;
    int dir=recovery_parent(root,p->path,0,name);if(dir<0)return -1;
    int rc=symlinkat(p->target,dir,name)||fsync(dir);close(dir);return rc?-1:0;
}
static int fixture_snapshot(int root,struct fixture_snapshot *out) {
    return enrolled_identity(root)||identity_all(root,out->identity)||
        dummy0_original_rule_matches(root,&out->native_rule)||enable_link(root,0)||
        candidate_checks(root,out->checks)||
        candidate_link_check(root,&recovery_old_timer,0,NULL,&out->old_timer)?-1:0;
}
static int fixture_unchanged(const struct fixture_snapshot *before,const struct fixture_snapshot *after) {
    if(!candidate_stat_unchanged(&before->native_rule,&after->native_rule)||
       !candidate_stat_unchanged(&before->old_timer,&after->old_timer))return -1;
    for(unsigned i=0;i<IDENTITY_COUNT;i++)
        if(!identity_equal(&before->identity[i],&after->identity[i]))return -1;
    for(unsigned i=0;i<RECOVERY_CHECK_COUNT;i++)
        if(!candidate_stat_unchanged(&before->checks[i],&after->checks[i]))return -1;
    return 0;
}
static int fixture_new_case(struct fixture_case *c) {
    memset(c,0,sizeof(*c));c->root=-1;
    strcpy(c->path,"/tmp/leon-v15-fixture-XXXXXX");
    if(!mkdtemp(c->path))return -1;
    c->root=open(c->path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(c->root<0||fchmod(c->root,0755)||fstat(c->root,&c->root_st))return -1;
    if(fixture_dirs(c->root,"var/lib/leon-asus-ssh"))return -1;
    for(unsigned i=0;i<FIXTURE_INPUT_COUNT;i++)
        if(fixture_seed_input(c->root,&fixture_inputs[i]))return -1;
    for(unsigned i=0;i<IDENTITY_COUNT;i++) {
        const char *path=identity_paths[i];const char synthetic[]="synthetic fixture identity only\n";
        const void *bytes=synthetic;size_t size=sizeof(synthetic)-1;mode_t mode=0644;
        if(!strcmp(path,"etc/shadow")||!strcmp(path,"etc/gshadow")||
           (strstr(path,"_key")&&!strstr(path,".pub"))||strstr(path,"var/lib/leon-asus-ssh/"))mode=0600;
        const char account[]="LEON_SSH_ACCOUNT_V1 MastermixStudios 1000\n";
        const char identity[]="LEON_SSH_DEVICE_V1_OK\n";
        char public_key[sizeof(recovery_host_public)+1];
        memcpy(public_key,recovery_host_public,sizeof(recovery_host_public)-1);
        public_key[sizeof(recovery_host_public)-1]='\n';
        if(!strcmp(path,"var/lib/leon-asus-ssh/account")){bytes=account;size=sizeof(account)-1;}
        if(!strcmp(path,"var/lib/leon-asus-ssh/device-identity")){bytes=identity;size=sizeof(identity)-1;}
        if(!strcmp(path,"etc/ssh/ssh_host_ed25519_key.pub")){bytes=public_key;size=sizeof(recovery_host_public);}
        if(fixture_seed_bytes(c->root,path,bytes,size,mode))return -1;
    }
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(fixture_parent_dirs(c->root,recovery_payloads[i].path))return -1;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(fixture_parent_dirs(c->root,recovery_links[i].path))return -1;
    if(fixture_seed_link(c->root,&recovery_old_timer)||fixture_snapshot(c->root,&c->before))return -1;
    return 0;
}
static int fixture_run_actual_region(struct fixture_case *c) {
    int root=c->root,rc=1;unsigned published=0,replaced=0,temporary=0,enabled=0;
    struct context context={NULL,NULL,0};
    struct candidate_leaf leaves[RECOVERY_PAYLOAD_COUNT]={0};
    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};
    active_case=c;
    /* This macro exists only around the byte-identical copied main region.
     * It never alters the included frozen guard definition or its call sites. */
#define recheck fixture_boundary_recheck
#include "candidate-preflight-publish.inc"
#undef recheck
    rc=0;
done:
    c->rc=rc;c->additions=published;c->replacements=replaced;c->temporary=temporary;c->links_created=enabled;
    memcpy(c->leaves,leaves,sizeof(leaves));memcpy(c->links,links,sizeof(links));active_case=NULL;
    return rc;
}
static int fixture_actual_success_loops(struct fixture_case *c) {
    int root=c->root,rc=1;
    struct stat *checks_before=c->before.checks,*checks_after=c->after.checks;
    struct recovery_saved *identity_before=c->before.identity,*identity_after=c->after.identity;
    struct candidate_leaf *leaves=c->leaves;
    struct candidate_link_state *links=c->links;
#include "candidate-final-loops.inc"
    rc=0;
done:return rc;
}
static int fixture_leaf_absent(int root,const char *path) {
    char name[NAME_MAX+1];struct stat st;int dir=recovery_parent(root,path,0,name);
    if(dir<0)return -1;
    int rc=fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW);int error=errno;close(dir);
    return rc&&error==ENOENT?0:-1;
}
static int fixture_old_leaves(int root,struct stat old[2]) {
    struct stat volume;if(fstat(root,&volume))return -1;
    for(unsigned i=0;i<2;i++) {
        char name[NAME_MAX+1];const struct recovery_payload *p=&recovery_payloads[i];
        int dir=recovery_parent(root,p->path,0,name);if(dir<0)return -1;
        int rc=candidate_old_file(dir,name,volume.st_dev,p,&old[i]);close(dir);if(rc)return -1;
    }
    return 0;
}
static int fixture_no_additions(struct fixture_case *c) {
    for(unsigned i=2;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(fixture_leaf_absent(c->root,recovery_payloads[i].path))return -1;
    return 0;
}
static int fixture_no_temps(struct fixture_case *c) {
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++) {
        char path[512];
        int n=snprintf(path,sizeof(path),"%s.%s",recovery_payloads[i].path,
                       i<2?"leon-candidate-v15-update":"leon-recovery-tmp");
        if(n<=0||(size_t)n>=sizeof(path)||fixture_leaf_absent(c->root,path))return -1;
    }
    return 0;
}
static int fixture_negative_link(void) {
    struct fixture_case c;struct stat old[2],after[2];
    if(fixture_new_case(&c)||fixture_old_leaves(c.root,old))return -1;
    struct candidate_link wrong=recovery_links[1];wrong.target="/usr/lib/systemd/system/incorrect-fixture.timer";
    if(fixture_seed_link(c.root,&wrong)||!fixture_run_actual_region(&c)||
       c.additions||c.replacements||c.temporary||c.links_created||c.boundary_calls||
       fixture_snapshot(c.root,&c.after)||fixture_unchanged(&c.before,&c.after)||
       fixture_no_additions(&c)||fixture_no_temps(&c)||fixture_old_leaves(c.root,after)||
       !candidate_stat_unchanged(&old[0],&after[0])||!candidate_stat_unchanged(&old[1],&after[1]))return -1;
    if(fixture_leaf_absent(c.root,recovery_links[0].path))return -1;
    close(c.root);puts("{\"case\":\"last-link-preflight-refusal\",\"pass\":true,\"publications\":0,\"hardware_guard_entered\":false}");return 0;
}
static int fixture_negative_old_hash(void) {
    struct fixture_case c;if(fixture_new_case(&c))return -1;
    char name[NAME_MAX+1];int dir=recovery_parent(c.root,recovery_payloads[1].path,0,name);
    if(dir<0)return -1;
    int fd=openat(dir,name,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);close(dir);if(fd<0)return -1;
    unsigned char changed=0;
    if(pwrite(fd,&changed,1,0)!=1||fsync(fd)){close(fd);return -1;}close(fd);
    struct recovery_payload corrupted=recovery_payloads[1];corrupted.sha=FIXTURE_CORRUPT_RC_SHA;
    corrupted.size=recovery_payloads[1].old_size;
    struct stat corrupt_before,corrupt_after;
    dir=recovery_parent(c.root,corrupted.path,0,name);if(dir<0)return -1;
    int bad=recovery_file(dir,name,c.root_st.st_dev,&corrupted,0755,&corrupt_before);close(dir);
    if(bad)return -1;
    if(!fixture_run_actual_region(&c)||c.additions||c.replacements||c.temporary||c.links_created||
       c.boundary_calls||fixture_snapshot(c.root,&c.after)||fixture_unchanged(&c.before,&c.after)||
       fixture_no_additions(&c)||fixture_no_temps(&c))return -1;
    dir=recovery_parent(c.root,corrupted.path,0,name);if(dir<0)return -1;
    bad=recovery_file(dir,name,c.root_st.st_dev,&corrupted,0755,&corrupt_after)||
        !candidate_stat_unchanged(&corrupt_before,&corrupt_after);close(dir);if(bad)return -1;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(fixture_leaf_absent(c.root,recovery_links[i].path))return -1;
    close(c.root);puts("{\"case\":\"old-rc-hash-preflight-refusal\",\"pass\":true,\"publications\":0,\"hardware_guard_entered\":false}");return 0;
}
static int fixture_success(void) {
    struct fixture_case c;struct stat old[2];if(fixture_new_case(&c)||fixture_old_leaves(c.root,old))return -1;
    if(fixture_run_actual_region(&c)||c.additions!=8||c.replacements!=2||c.temporary!=10||
       c.links_created!=2||c.boundary_calls!=1||fixture_snapshot(c.root,&c.after)||
       fixture_unchanged(&c.before,&c.after)||fixture_actual_success_loops(&c)||fixture_no_temps(&c))return -1;
    for(unsigned i=0;i<2;i++)
        if(candidate_same_inode(&old[i],&c.leaves[i].published))return -1;
    struct stat new_files[RECOVERY_PAYLOAD_COUNT],new_links[RECOVERY_LINK_COUNT];
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)new_files[i]=c.leaves[i].published;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)new_links[i]=c.links[i].published;
    /* Explicit exact-new no-op after success, never a retry after failure. */
    if(fixture_run_actual_region(&c)||c.additions||c.replacements||c.temporary||c.links_created||
       c.boundary_calls!=2||fixture_snapshot(c.root,&c.after)||fixture_unchanged(&c.before,&c.after)||
       fixture_actual_success_loops(&c)||fixture_no_temps(&c))return -1;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(!candidate_stat_unchanged(&new_files[i],&c.leaves[i].published))return -1;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(!candidate_stat_unchanged(&new_links[i],&c.links[i].published))return -1;
    close(c.root);puts("{\"case\":\"two-replace-eight-add-two-link-success\",\"pass\":true,\"verified_new_noop_preserves_inodes\":true,\"identity16_and_check7_inodes_unchanged\":true,\"hardware_guard_entered\":false}");return 0;
}
static int fixture_interrupt(void) {
    struct fixture_case c;struct stat old[2],after[2];
    if(fixture_new_case(&c)||fixture_old_leaves(c.root,old))return -1;
    fault_armed=1;fault_calls=0;fault_bytes=0;fault_fd=-1;
    int got=fixture_run_actual_region(&c);fault_armed=0;
    if(!got||fault_calls!=2||!fault_bytes||c.additions!=2||c.replacements||c.temporary!=3||
       c.links_created||c.boundary_calls!=1||fixture_snapshot(c.root,&c.after)||
       fixture_unchanged(&c.before,&c.after)||fixture_old_leaves(c.root,after)||
       !candidate_stat_unchanged(&old[0],&after[0])||!candidate_stat_unchanged(&old[1],&after[1]))return -1;
    for(unsigned i=2;i<4;i++) {
        char name[NAME_MAX+1];struct stat leaf;int dir=recovery_parent(c.root,recovery_payloads[i].path,0,name);
        if(dir<0)return -1;
        int bad=recovery_file(dir,name,c.root_st.st_dev,&recovery_payloads[i],0644,&leaf)||
            !candidate_same_inode(&leaf,&c.leaves[i].published);close(dir);if(bad)return -1;
    }
    for(unsigned i=4;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(fixture_leaf_absent(c.root,recovery_payloads[i].path))return -1;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(fixture_leaf_absent(c.root,recovery_links[i].path))return -1;
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat retained;
    int dir=recovery_parent(c.root,recovery_payloads[FAULT_ROW].path,0,name);if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name);
    int bad=n<=0||(size_t)n>=sizeof(temp)||fstatat(dir,temp,&retained,AT_SYMLINK_NOFOLLOW)||
        !candidate_same_inode(&retained,&fault_inode)||!S_ISREG(retained.st_mode)||
        retained.st_uid||retained.st_gid||retained.st_nlink!=1||
        (retained.st_mode&07777)!=0600||retained.st_size!=(off_t)fault_bytes;
    close(dir);if(bad)return -1;
    close(c.root);puts("{\"case\":\"short-write-eio-retains-temp-and-partial\",\"pass\":true,\"temporary_retained\":true,\"automatic_retry\":false,\"hardware_guard_entered\":false}");return 0;
}
int main(int argc,char **argv) {
    (void)argv;
    if(argc!=1||getuid()||geteuid())return 77;
    alarm(90);
    if(RECOVERY_PAYLOAD_COUNT!=10||RECOVERY_LINK_COUNT!=2||RECOVERY_CHECK_COUNT!=6||
       IDENTITY_COUNT!=16||recovery_payloads[FAULT_ROW].old_sha||recovery_payloads[FAULT_ROW].size<2)return 78;
    if(fixture_negative_link()||fixture_negative_old_hash()||fixture_success()||fixture_interrupt()) {
        fprintf(stderr,"LEON_V15_FIXTURE_FAILED stage=%s device_accessed=false\n",stage);return 1;
    }
    puts("{\"status\":\"focused_changed_orchestration_cases_passed\",\"scenario_groups\":3,\"case_variants\":4,\"device_accessed\":false,\"production_main_executed\":false,\"automatic_retry\":false,\"armed\":false}");
    return 0;
}
