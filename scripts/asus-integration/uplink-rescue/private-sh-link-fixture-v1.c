/* Isolated filesystem safety cases. No device guards or vendor execution. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "fixture-helpers.h"
#include "private-sh-link-update-v1.c.inc"

static const char *const objects[]={".","usr","usr/share","usr/share/asus",
    "usr/share/asus/commands","usr/share/asus/commands/sbin","canary",
    "usr/share/asus/commands/sbin/sh",
    "usr/share/asus/commands/sbin/sh.leon-network-v16-update"};
struct view { int exists[9];struct stat st[9];char links[9][512];char canary[64]; };
/* Independent filesystem observation: no production predicate is used here. */
static void observe(int root,struct view *v) {
    memset(v,0,sizeof(*v));
    for(unsigned i=0;i<9;i++) {
        if(fstatat(root,objects[i],&v->st[i],AT_SYMLINK_NOFOLLOW)) {assert(errno==ENOENT);continue;}
        v->exists[i]=1;
        if(S_ISLNK(v->st[i].st_mode)) {
            ssize_t n=readlinkat(root,objects[i],v->links[i],sizeof(v->links[i])-1);
            assert(n>0&&(size_t)n<sizeof(v->links[i])-1);v->links[i][n]=0;
        }
    }
    int fd=openat(root,"canary",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);assert(fd>=0);
    ssize_t n=read(fd,v->canary,sizeof(v->canary)-1);assert(n==21);assert(!close(fd));
    assert(!strcmp(v->canary,"keep unrelated bytes\n"));
}
static int same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static void unchanged(const struct view *a,const struct view *b,unsigned end) {
    for(unsigned i=0;i<end;i++) {
        assert(a->exists[i]==b->exists[i]);
        if(a->exists[i])assert(same_stat(&a->st[i],&b->st[i])&&!strcmp(a->links[i],b->links[i]));
    }
    assert(!strcmp(a->canary,b->canary));
}
static int new_case(const char *base,const char *name,const char *target,int with_temp) {
    char path[PATH_MAX];int n=snprintf(path,sizeof(path),"%s/%s.XXXXXX",base,name);
    assert(n>0&&(size_t)n<sizeof(path)&&mkdtemp(path));
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);assert(root>=0);
    int parent=dup(root);assert(parent>=0);
    for(unsigned i=1;i<=5;i++) {
        const char *leaf=strrchr(objects[i],'/');leaf=leaf?leaf+1:objects[i];
        assert(!mkdirat(parent,leaf,0755));
        int next=openat(parent,leaf,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);assert(next>=0);
        assert(!fchmod(next,0755)&&!close(parent));parent=next;
    }
    assert(!symlinkat(target,parent,"sh"));
    if(with_temp)assert(!symlinkat("/unrelated-retained-temp",parent,"sh.leon-network-v16-update"));
    assert(!close(parent));
    int fd=openat(root,"canary",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);assert(fd>=0);
    assert(write(fd,"keep unrelated bytes\n",21)==21&&!fsync(fd)&&!close(fd));return root;
}
static int apply(int root,struct private_sh_state *state,unsigned *replaced,unsigned *temporary) {
    if(private_sh_preflight(root,state))return -1;
    return private_sh_publish(root,state,replaced,temporary);
}
int main(int argc,char **argv) {
    assert(argc==2&&argv[1][0]=='/'&&getuid()==0&&geteuid()==0&&getgid()==0);umask(0077);
    struct view before,after,noop;struct private_sh_state state={0};unsigned replaced=0,temporary=0;
    int root=new_case(argv[1],"exact-old",private_sh_old.target,0);observe(root,&before);
    assert(!apply(root,&state,&replaced,&temporary)&&replaced==1&&temporary==1&&!private_sh_preserved(root,&state));
    observe(root,&after);unchanged(&before,&after,5);
    /* Publishing changes the containing directory's timestamps. Its identity,
     * ownership/mode and the unrelated regular canary must remain intact. */
    assert(before.st[5].st_dev==after.st[5].st_dev&&before.st[5].st_ino==after.st[5].st_ino&&
           before.st[5].st_mode==after.st[5].st_mode&&before.st[5].st_uid==after.st[5].st_uid&&
           before.st[5].st_gid==after.st[5].st_gid&&same_stat(&before.st[6],&after.st[6]));
    assert(after.exists[7]&&!after.exists[8]&&!strcmp(after.links[7],private_sh_new.target));
    assert(after.st[7].st_uid==0&&after.st[7].st_gid==0&&(after.st[7].st_mode&07777)==0777);
    assert(!same_stat(&before.st[7],&after.st[7]));
    state=(struct private_sh_state){0};replaced=temporary=0;
    assert(!apply(root,&state,&replaced,&temporary)&&state.already_new&&replaced==0&&temporary==0&&!private_sh_preserved(root,&state));
    observe(root,&noop);unchanged(&after,&noop,9);assert(!close(root));
    puts("LAB_PRIVATE_SH_EXACT_REPLACE_AND_NEW_NOOP_PASS");
    root=new_case(argv[1],"foreign-target","/unreviewed-shell",0);observe(root,&before);
    state=(struct private_sh_state){0};replaced=temporary=0;
    assert(apply(root,&state,&replaced,&temporary)&&replaced==0&&temporary==0);
    observe(root,&after);unchanged(&before,&after,9);assert(!close(root));
    puts("LAB_PRIVATE_SH_FOREIGN_TARGET_REFUSED_UNCHANGED_PASS");
    root=new_case(argv[1],"preexisting-temp",private_sh_old.target,1);observe(root,&before);
    state=(struct private_sh_state){0};replaced=temporary=0;
    assert(apply(root,&state,&replaced,&temporary)&&replaced==0&&temporary==0);
    observe(root,&after);unchanged(&before,&after,9);assert(!close(root));
    puts("LAB_PRIVATE_SH_EXISTING_TEMP_REFUSED_UNCHANGED_PASS");return 0;
}
