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
