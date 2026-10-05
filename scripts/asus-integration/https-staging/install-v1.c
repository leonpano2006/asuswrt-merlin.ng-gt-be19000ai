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
#define ENABLE_NAME "leon-asus-trial-snapshot.timer"
#define ENABLE_TARGET "/usr/lib/systemd/system/leon-asus-trial-snapshot.timer"

static int state_dir(int parent,dev_t device) {
    int fd=openat(parent,"leon-asus-ssh",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid||st.st_gid||st.st_dev!=device||
       (st.st_mode&07777)!=0755) {close(fd);return -1;}
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
static int dummy0_original_rule_matches(int root,struct stat *out) {
    char name[NAME_MAX+1];struct stat volume;
    int dir=recovery_parent(root,recovery_original_rule.path,0,name);if(dir<0)return -1;
    int rc=fstat(root,&volume)||recovery_file(dir,name,volume.st_dev,&recovery_original_rule,0644,out);
    close(dir);return rc?-1:0;
}


/* SPDX-License-Identifier: GPL-2.0-or-later
 * SOURCE-ONLY replacement transplant for the v15 installer plan.
 * Requires the proposed descriptor layout and frozen recovery_parent/file().
 * Not a standalone program, no CLI, no build or execution performed.
 */
static int candidate_temp_name(const char *name,char temp[NAME_MAX+1]) {
    int n=snprintf(temp,NAME_MAX+1,"%s.leon-candidate-v15-update",name);
    return n<=0||n>NAME_MAX?-1:0;
}
static int candidate_same_inode(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;
}
static int candidate_old_file(int dir,const char *name,dev_t device,
        const struct recovery_payload *p,struct stat *out) {
    if(!p->old_sha||!p->old_size)return -1;
    struct recovery_payload old=*p;old.sha=p->old_sha;old.size=p->old_size;old.data=NULL;
    return recovery_file(dir,name,device,&old,p->mode,out);
}
/* All calls below precede any candidate leaf staging/publication. Require
 * existing parents: recovery_parent(create=0) performs no mkdir/chmod. */
static int candidate_replace_preflight(int root,const struct recovery_payload *p,
        struct candidate_leaf *saved) {
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat volume,leaf;
    int dir=recovery_parent(root,p->path,0,name),rc=-1;if(dir<0)return -1;
    if(!p->old_sha||!p->old_size||!p->data||!p->size||p->size>16*1024*1024||
       (p->mode!=0644&&p->mode!=0755)||candidate_temp_name(name,temp)||fstat(root,&volume))goto done;
    if(!fstatat(dir,temp,&leaf,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    saved->present=1;saved->already_new=0;
    if(!recovery_file(dir,name,volume.st_dev,p,p->mode,&saved->before))saved->already_new=1;
    else if(candidate_old_file(dir,name,volume.st_dev,p,&saved->before))goto done;
    rc=0;
done:close(dir);return rc;
}
/* Adapt immutable native-v2 bsp_update() transaction to one exact descriptor.
 * The accepted-new branch is a verified no-op. No arbitrary target can be
 * replaced, no failed temp is removed, and no retries are introduced. */
static int candidate_replace(int root,const struct recovery_payload *p,
        struct candidate_leaf *saved,unsigned *replaced,unsigned *temporary) {
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat volume,old,again,tmp;
    int dir=recovery_parent(root,p->path,0,name),fd=-1,rc=-1;if(dir<0)return -1;
    if(candidate_temp_name(name,temp)||fstat(root,&volume))goto done;
    if(!fstatat(dir,temp,&tmp,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(saved->already_new) {
        if(recovery_file(dir,name,volume.st_dev,p,p->mode,&again)||
           !candidate_same_inode(&saved->before,&again))goto done;
        saved->published=again;rc=0;goto done;
    }
    if(candidate_old_file(dir,name,volume.st_dev,p,&old)||
       !candidate_same_inode(&saved->before,&old))goto done;
    fd=openat(dir,temp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)goto done;
    (*temporary)++;if(fchmod(fd,0600))goto done;
    size_t used=0;
    while(used<p->size) {
        ssize_t n=write(fd,p->data+used,p->size-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto done;
        used+=(size_t)n;
    }
    if(fsync(fd)||recovery_file(dir,temp,volume.st_dev,p,0600,&tmp)||
       fstat(fd,&again)||!candidate_same_inode(&again,&tmp))goto done;
    if(fchmod(fd,p->mode)||fsync(fd)||recovery_file(dir,temp,volume.st_dev,p,p->mode,&tmp)||
       candidate_old_file(dir,name,volume.st_dev,p,&again)||
       !candidate_same_inode(&old,&again)||!candidate_same_inode(&saved->before,&again))goto done;
    /* Same-volume rename replaces only the twice-verified old inode.
     * The shared lock excludes cooperating writers; no claim is made that
     * renameat provides a kernel compare-and-swap against hostile writers. */
    if(renameat(dir,temp,dir,name))goto done;
    (*replaced)++;
    if(fsync(dir)||recovery_file(dir,name,volume.st_dev,p,p->mode,&again)||
       !candidate_same_inode(&again,&tmp))goto done;
    saved->published=again;rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}

/* SOURCE-ONLY integration blocks; these depend on the frozen installer
 * includes, proposed payload header and immutable replacement transplant.
 * This file is not a standalone program and has not been compiled. */
struct candidate_link_state { int present; struct stat before,published; };
static int candidate_stat_unchanged(const struct stat *a,const struct stat *b) {
    return candidate_same_inode(a,b)&&a->st_mode==b->st_mode&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&
        a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&
        a->st_mtim.tv_nsec==b->st_mtim.tv_nsec;
}
static int candidate_checks(int root,struct stat saved[RECOVERY_CHECK_COUNT]) {
    struct stat volume;if(fstat(root,&volume))return -1;
    for(unsigned i=0;i<RECOVERY_CHECK_COUNT;i++) {
        const struct recovery_payload *p=&recovery_checks[i];
        char name[NAME_MAX+1];int dir=recovery_parent(root,p->path,0,name);
        if(dir<0)return -1;
        int bad=recovery_file(dir,name,volume.st_dev,p,p->mode,&saved[i]);
        close(dir);if(bad)return -1;
    }
    return 0;
}
static int candidate_link_check(int root,const struct candidate_link *p,int allow_missing,
        int *present,struct stat *out) {
    char name[NAME_MAX+1],target[512];struct stat volume,after;
    int dir=recovery_parent(root,p->path,0,name),rc=-1;if(dir<0)return -1;
    if(present)*present=0;
    if(fstat(root,&volume)||strlen(p->target)>=sizeof(target))goto done;
    if(fstatat(dir,name,out,AT_SYMLINK_NOFOLLOW)) {
        if(allow_missing&&errno==ENOENT)rc=0;
        goto done;
    }
    if(!S_ISLNK(out->st_mode)||out->st_uid||out->st_gid||out->st_nlink!=1||
       out->st_dev!=volume.st_dev||(out->st_mode&07777)!=0777||
       out->st_size!=(off_t)strlen(p->target))goto done;
    ssize_t n=readlinkat(dir,name,target,sizeof(target));
    if(n<0||(size_t)n!=strlen(p->target)||memcmp(target,p->target,(size_t)n)||
       fstatat(dir,name,&after,AT_SYMLINK_NOFOLLOW)||!candidate_stat_unchanged(out,&after))goto done;
    if(present)*present=1;
    rc=0;
done:close(dir);return rc;
}
static int candidate_link_publish(int root,const struct candidate_link *p,
        struct candidate_link_state *saved,unsigned *created) {
    struct stat again;int present=0;
    if(candidate_link_check(root,p,1,&present,&again))return -1;
    if(saved->present) {
        if(!present||!candidate_stat_unchanged(&saved->before,&again))return -1;
        saved->published=again;return 0;
    }
    char name[NAME_MAX+1];int dir=recovery_parent(root,p->path,0,name),rc=-1;
    if(dir<0)return -1;
    if(!symlinkat(p->target,dir,name))(*created)++;
    else if(errno!=EEXIST)goto done;
    /* EEXIST never replaces a link; only the fixed exact link is accepted. */
    if(fsync(dir)||candidate_link_check(root,p,0,NULL,&again))goto done;
    saved->published=again;rc=0;
done:close(dir);return rc;
}

/* One fixed ASUS-private symlink correction; never a global /bin/sh change.
 * Included after the frozen candidate_link helpers. All parents are existing,
 * root-owned, same-volume and traversed without following symlinks.
 */
static const struct candidate_link private_sh_old={
    "usr/share/asus/commands/sbin/sh","/usr/libexec/asus/vendor/bin/memaccess"};
static const struct candidate_link private_sh_new={
    "usr/share/asus/commands/sbin/sh","/usr/libexec/asus/ash"};
static const struct candidate_link private_sh_temp={
    "usr/share/asus/commands/sbin/sh.leon-network-v16-update","/usr/libexec/asus/ash"};
struct private_sh_state { int already_new; struct stat before,published; };

static int private_sh_temp_absent(int root) {
    char name[NAME_MAX+1];struct stat st;
    int dir=recovery_parent(root,private_sh_temp.path,0,name),rc=-1;
    if(dir<0)return -1;
    if(fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT)rc=0;
    close(dir);return rc;
}
static int private_sh_preflight(int root,struct private_sh_state *saved) {
    if(private_sh_temp_absent(root))return -1;
    saved->already_new=0;
    if(!candidate_link_check(root,&private_sh_new,0,NULL,&saved->before)) {
        saved->already_new=1;return 0;
    }
    return candidate_link_check(root,&private_sh_old,0,NULL,&saved->before);
}
static int private_sh_publish(int root,struct private_sh_state *saved,
        unsigned *replaced,unsigned *temporary) {
    struct stat current,tmp,again;char name[NAME_MAX+1],temp[NAME_MAX+1];
    const struct candidate_link *expected=saved->already_new?&private_sh_new:&private_sh_old;
    if(private_sh_temp_absent(root)||
       candidate_link_check(root,expected,0,NULL,&current)||
       !candidate_stat_unchanged(&saved->before,&current))return -1;
    if(saved->already_new){saved->published=current;return 0;}
    int dir=recovery_parent(root,private_sh_new.path,0,name),rc=-1;
    if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-network-v16-update",name);
    if(n<=0||(size_t)n>=sizeof(temp)||
       symlinkat(private_sh_new.target,dir,temp))goto done;
    (*temporary)++;
    /* A partial result remains for review. No cleanup, adoption or retry. */
    if(fsync(dir)||candidate_link_check(root,&private_sh_temp,0,NULL,&tmp)||
       candidate_link_check(root,&private_sh_old,0,NULL,&again)||
       !candidate_stat_unchanged(&saved->before,&again))goto done;
    /* The shared device lock excludes cooperating writers. This is not a
     * kernel compare-and-swap against hostile concurrent root writers. */
    if(renameat(dir,temp,dir,name))goto done;
    (*replaced)++;
    if(fsync(dir)||candidate_link_check(root,&private_sh_new,0,NULL,&again)||
       !candidate_same_inode(&tmp,&again))goto done;
    saved->published=again;rc=0;
done:close(dir);return rc;
}
static int private_sh_preserved(int root,const struct private_sh_state *saved) {
    struct stat after;
    return private_sh_temp_absent(root)||
        candidate_link_check(root,&private_sh_new,0,NULL,&after)||
        !candidate_stat_unchanged(&saved->published,&after)?-1:0;
}

static int target_preflight(int root,const struct recovery_payload *p,struct candidate_leaf *saved) {
    if(p->old_sha)return candidate_replace_preflight(root,p,saved);
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat volume,leaf;
    int dir=recovery_parent(root,p->path,0,name);if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name),rc=-1;
    if(p->old_size||!p->data||!p->size||p->size>16*1024*1024||
       (p->mode!=0644&&p->mode!=0755)||n<=0||(size_t)n>=sizeof(temp)||fstat(root,&volume))goto done;
    if(!fstatat(dir,temp,&leaf,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    saved->present=0;saved->already_new=0;
    if(fstatat(dir,name,&leaf,AT_SYMLINK_NOFOLLOW)) {
        if(errno==ENOENT)rc=0;
    } else if(!recovery_file(dir,name,volume.st_dev,p,p->mode,&saved->before)) {
        saved->present=1;saved->already_new=1;rc=0;
    }
done:close(dir);return rc;
}
static int install_target(int root,const struct recovery_payload *p,struct candidate_leaf *saved,
        unsigned *published,unsigned *temporary) {
    char name[NAME_MAX+1],temp[NAME_MAX+1];struct stat volume,st,again;
    int dir=recovery_parent(root,p->path,0,name),fd=-1,rc=-1;
    if(dir<0)return -1;
    int n=snprintf(temp,sizeof(temp),"%s.leon-recovery-tmp",name);
    if(p->old_sha||p->old_size||n<0||(size_t)n>=sizeof(temp)||fstat(root,&volume))goto done;
    if(!fstatat(dir,temp,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(!recovery_file(dir,name,volume.st_dev,p,p->mode,&st)) {
        if(saved->present&&!candidate_stat_unchanged(&saved->before,&st))goto done;
        saved->published=st;rc=0;goto done;
    }
    if(saved->present||!fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    fd=openat(dir,temp,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)goto done;
    (*temporary)++;if(fchmod(fd,0600))goto done;
    size_t used=0;
    while(used<p->size) {ssize_t got=write(fd,p->data+used,p->size-used);if(got<0&&errno==EINTR)continue;if(got<=0)goto done;used+=(size_t)got;}
    if(fsync(fd)||recovery_file(dir,temp,volume.st_dev,p,0600,&st)||fstat(fd,&again)||
       again.st_dev!=st.st_dev||again.st_ino!=st.st_ino||fchmod(fd,p->mode)||fsync(fd)||
       recovery_file(dir,temp,volume.st_dev,p,p->mode,&st))goto done;
    /* Keep the frozen additive publication primitive; never replace a target. */
    if(syscall(SYS_renameat2,dir,temp,dir,name,RENAME_NOREPLACE))goto done;
    (*published)++;
    if(fsync(dir)||recovery_file(dir,name,volume.st_dev,p,p->mode,&again)||again.st_dev!=st.st_dev||again.st_ino!=st.st_ino)goto done;
    saved->published=again;rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
static int enable_dir(int root,int create) {
    const char *const parts[]={"etc","systemd","system"};struct stat st;
    if(fstat(root,&st))return -1;
    int parent=parents(root,parts,3);if(parent<0)return -1;
    int dir=safe_dir(parent,"timers.target.wants",st.st_dev,create);close(parent);return dir;
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
static int install_recovery(int root,struct candidate_leaf saved[RECOVERY_PAYLOAD_COUNT],
        struct candidate_link_state links[RECOVERY_LINK_COUNT],unsigned *published,unsigned *replaced,
        unsigned *temporary,unsigned *enabled) {
    /* Main completed every read-only file/link preflight before this call. */
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(!recovery_payloads[i].old_sha&&install_target(root,&recovery_payloads[i],&saved[i],published,temporary))return -1;
    /* Fixed header order: helper2->3 then RC6->7; never a p11 guardian. */
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if(recovery_payloads[i].old_sha&&candidate_replace(root,&recovery_payloads[i],&saved[i],replaced,temporary))return -1;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(candidate_link_publish(root,&recovery_links[i],&links[i],enabled))return -1;
    return 0;
}

/* The one proven missing parent. All ancestors remain existing-only.
 * A valid existing directory is never chmod'ed. Missing permits creation of
 * this fixed name only, after every payload/prerequisite preflight and recheck.
 */
#define HTTPS_SCRIPTS_PARENT "usr/libexec/asus/scripts"
#define HTTPS_HELPER HTTPS_SCRIPTS_PARENT "/gencert.sh"
struct https_scripts_parent { int present; struct stat ancestor,before,published; };
static int https_scripts_parent_preflight(int root,struct https_scripts_parent *saved) {
    char name[NAME_MAX+1];struct stat volume,after;
    int dir=recovery_parent(root,HTTPS_SCRIPTS_PARENT,0,name),fd=-1,rc=-1;
    if(dir<0)return -1;
    if(RECOVERY_PAYLOAD_COUNT!=2||RECOVERY_LINK_COUNT!=2||strcmp(recovery_payloads[0].path,HTTPS_HELPER)||
       strcmp(recovery_links[1].path,"usr/share/asus/commands/sbin/gencert.sh")||
       strcmp(recovery_links[1].target,"/usr/libexec/asus/scripts/gencert.sh")||
       fstat(root,&volume)||fstat(dir,&saved->ancestor))goto done;
    saved->present=0;
    if(fstatat(dir,name,&saved->before,AT_SYMLINK_NOFOLLOW)) {
        if(errno==ENOENT)rc=0;
        goto done;
    }
    fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0||leon_diag_directory(fd,volume.st_dev)||fstat(fd,&after)||
       (after.st_mode&07777)!=0755||!candidate_stat_unchanged(&saved->before,&after))goto done;
    saved->present=1;rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
static int https_scripts_parent_publish(int root,struct https_scripts_parent *saved,unsigned *created) {
    char name[NAME_MAX+1];struct stat volume,ancestor,current;
    int dir=recovery_parent(root,HTTPS_SCRIPTS_PARENT,0,name),fd=-1,rc=-1;
    if(dir<0)return -1;
    if(fstat(root,&volume)||fstat(dir,&ancestor)||!candidate_same_inode(&saved->ancestor,&ancestor))goto done;
    if(saved->present) {
        fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0||leon_diag_directory(fd,volume.st_dev)||fstat(fd,&current)||
           (current.st_mode&07777)!=0755||!candidate_same_inode(&saved->before,&current))goto done;
        saved->published=current;rc=0;goto done;
    }
    /* Refuse a raced appearance rather than accepting an un-preflighted node. */
    if(!fstatat(dir,name,&current,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
    if(mkdirat(dir,name,0700))goto done;
    (*created)++;
    fd=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0||fstat(fd,&current)||!S_ISDIR(current.st_mode)||current.st_uid||current.st_gid||
       current.st_dev!=volume.st_dev||(current.st_mode&07777)!=0700||
       fstatat(dir,name,&saved->published,AT_SYMLINK_NOFOLLOW)||
       !candidate_stat_unchanged(&current,&saved->published)||fchmod(fd,0755)||
       fsync(fd)||fsync(dir)||fstat(fd,&saved->published)||
       (saved->published.st_mode&07777)!=0755||leon_diag_directory(fd,volume.st_dev)||
       fstatat(dir,name,&current,AT_SYMLINK_NOFOLLOW)||
       !candidate_stat_unchanged(&saved->published,&current))goto done;
    rc=0;
done:if(fd>=0)close(fd);close(dir);return rc;
}
static int https_scripts_parent_preserved(int root,const struct https_scripts_parent *saved) {
    struct https_scripts_parent after={0};
    if(https_scripts_parent_preflight(root,&after)||!after.present||
       !candidate_same_inode(&saved->ancestor,&after.ancestor)||
       !candidate_same_inode(&saved->published,&after.before))return -1;
    return 0;
}

#ifndef RECOVERY_INSTALL_MAIN
#define RECOVERY_INSTALL_MAIN main
#endif
int RECOVERY_INSTALL_MAIN(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--install-native-https-helper-v1")||!slot_hex(argv[2])||!boot_valid(argv[3]))return 64;
    struct rlimit limit={0,0};struct context context={argv[2],argv[3],0};
    int rc=1,lock=-1,root=-1,created=0,mounted=0,volume_fd=-1,mode_changed=0;
    unsigned enabled=0,replaced=0,sh_replaced=0,directories_created=0;
    unsigned published=0,temporary=0;
    struct stat self,init,st;struct statfs fs;struct statvfs vfs;struct update_state before,after;
    struct recovery_saved identity_before[IDENTITY_COUNT],identity_after[IDENTITY_COUNT];
    struct stat original_rule_before,original_rule_after,old_timer_before,old_timer_after;
    struct stat checks_before[RECOVERY_CHECK_COUNT],checks_after[RECOVERY_CHECK_COUNT];
    struct candidate_leaf leaves[RECOVERY_PAYLOAD_COUNT]={0};
    struct candidate_link_state links[RECOVERY_LINK_COUNT]={0};
    struct private_sh_state sh={0};
    struct https_scripts_parent scripts_parent={0};
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
    if(update_preserve(root,&context,&before)||enrolled_identity(root)||identity_all(root,identity_before)||dummy0_original_rule_matches(root,&original_rule_before)||enable_link(root,0)||
       candidate_checks(root,checks_before)||candidate_link_check(root,&recovery_old_timer,0,NULL,&old_timer_before))goto done;
    stage="all-fixed-candidate-file-and-link-preflights";
    if(https_scripts_parent_preflight(root,&scripts_parent))goto done;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++)
        if((i!=0||scripts_parent.present)&&target_preflight(root,&recovery_payloads[i],&leaves[i]))goto done;
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++)
        if(candidate_link_check(root,&recovery_links[i],i==1,&links[i].present,&links[i].before))goto done;
    if(private_sh_preflight(root,&sh)||!sh.already_new)goto done;
    /* Same immutable physical recheck under the same lock, before publication. */
    if(recheck(&context))goto done;
    stage="publish-fixed-https-scripts-parent";
    if(https_scripts_parent_publish(root,&scripts_parent,&directories_created))goto done;
    stage="publish-fixed-inactive-https-helper";
    if(install_recovery(root,leaves,links,&published,&replaced,&temporary,&enabled))goto done;
    if(private_sh_publish(root,&sh,&sh_replaced,&temporary))goto done;
    stage="sync-readback-and-preservation";
    if(syncfs(root)||recheck(&context)||update_preserve(root,&context,&after)||!update_preserved_equal(&before,&after)||
       enrolled_identity(root)||identity_all(root,identity_after)||enable_link(root,0)||dummy0_original_rule_matches(root,&original_rule_after)||
       !candidate_stat_unchanged(&original_rule_before,&original_rule_after)||candidate_checks(root,checks_after)||
       candidate_link_check(root,&recovery_old_timer,0,NULL,&old_timer_after)||!candidate_stat_unchanged(&old_timer_before,&old_timer_after))goto done;
    for(unsigned i=0;i<RECOVERY_CHECK_COUNT;i++)
        if(!candidate_stat_unchanged(&checks_before[i],&checks_after[i]))goto done;
    for(unsigned i=0;i<IDENTITY_COUNT;i++)if(!identity_equal(&identity_before[i],&identity_after[i]))goto done;
    for(unsigned i=0;i<RECOVERY_PAYLOAD_COUNT;i++) {
        char name[NAME_MAX+1];int dir=recovery_parent(root,recovery_payloads[i].path,0,name);struct stat leaf,volume;
        if(dir<0)goto done;
        int failed=fstat(root,&volume)||recovery_file(dir,name,volume.st_dev,&recovery_payloads[i],recovery_payloads[i].mode,&leaf)||
            !candidate_same_inode(&leaves[i].published,&leaf);close(dir);if(failed)goto done;
    }
    for(unsigned i=0;i<RECOVERY_LINK_COUNT;i++) {
        struct stat leaf;
        if(candidate_link_check(root,&recovery_links[i],0,NULL,&leaf)||
           !candidate_same_inode(&links[i].published,&leaf))goto done;
    }
    if(private_sh_preserved(root,&sh))goto done;
    if(https_scripts_parent_preserved(root,&scripts_parent))goto done;
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
    if(rc)fprintf(stderr,"LEON_HTTPS_HELPER_V1_INSTALL_REFUSED stage=%s temporary=%u additions=%u replacements=%u mode_changed=%d links=%u sh_replaced=%u directories_created=%u retained_for_review=true armed=false rebooted=false\n",stage,temporary,published,replaced,mode_changed,enabled,sh_replaced,directories_created);
    else printf("{\"schema\":1,\"status\":\"native_https_helper_v1_staged\",\"boot_id\":\"%s\",\"metadata_sha256\":\"%s\",\"additions_published\":%u,\"replacements_published\":%u,\"temporary_created\":%u,\"links_created\":%u,\"private_sh_links_replaced\":%u,\"directories_created\":%u,\"mode_changed\":false,\"native_identity_unchanged\":true,\"known_preserved_leaf_inodes_unchanged\":true,\"prerequisites_unchanged\":true,\"package_database_updated\":false,\"armed\":false,\"rebooted\":false,\"boot_committed\":false}\n",argv[3],argv[2],published,replaced,temporary,enabled,sh_replaced,directories_created);
    return rc;
}
