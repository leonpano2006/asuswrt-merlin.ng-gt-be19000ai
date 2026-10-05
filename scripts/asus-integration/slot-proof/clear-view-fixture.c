/* SPDX-License-Identifier: GPL-2.0-or-later
 * Redirect every /proc and /sys access into a new synthetic directory tree.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
static char base[]="/tmp/slot-clear-view.XXXXXX";
static unsigned calls,fail_at,cases;
static int fail_process,vanish_process,swap_minor=11;
static const char *mapped(const char *p) {
    static char path[PATH_MAX];
    if(!strcmp(p,"/proc"))snprintf(path,sizeof(path),"%s/proc",base);
    else if(!strcmp(p,"/proc/self/mountinfo"))snprintf(path,sizeof(path),"%s/self",base);
    else if(!strcmp(p,"/proc/swaps"))snprintf(path,sizeof(path),"%s/swaps",base);
    else if(!strcmp(p,"/sys/class/block/mmcblk0p11/holders"))snprintf(path,sizeof(path),"%s/holders",base);
    else if(!strncmp(p,"/proc/2",7))snprintf(path,sizeof(path),"%s%s",base,p);
    else assert(!"Unexpected fixture path");
    return path;
}
static DIR *cv_opendir(const char *p) {return opendir(mapped(p));}
static struct dirent *cv_readdir(DIR *d) {if(++calls==fail_at){errno=EIO;return NULL;}return readdir(d);}
static FILE *cv_fopen(const char *p,const char *mode) {
    if(!strcmp(p,"/proc/2/mountinfo")) {
        if(fail_process){errno=EIO;return NULL;}
        if(vanish_process){assert(unlink(mapped(p))==0);assert(rmdir(mapped("/proc/2"))==0);errno=ENOENT;return NULL;}
    }
    return fopen(mapped(p),mode);
}
static int cv_lstat(const char *p,struct stat *st) {return lstat(mapped(p),st);}
static int cv_stat(const char *p,struct stat *st) {
    assert(!strcmp(p,"/dev/fixture-swap"));memset(st,0,sizeof(*st));st->st_mode=S_IFBLK|0600;st->st_rdev=makedev(179,(unsigned)swap_minor);return 0;
}
#define opendir cv_opendir
#define readdir cv_readdir
#define fopen cv_fopen
#define lstat cv_lstat
#define stat(path,buffer) cv_stat(path,buffer)
#include "p11-clear-view.h"
#undef opendir
#undef readdir
#undef fopen
#undef lstat
#undef stat
static void put(const char *relative,const char *value) {
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/%s",base,relative);FILE *f=fopen(path,"we");assert(f);assert(fputs(value,f)>=0);assert(fclose(f)==0);
}
static void check(const char *name,int expected,const char *allowed) {
    calls=0;int rc=leon_p11_clear_view(allowed);assert((rc==0)==expected);printf("PASS %s\n",name);cases++;
}
int main(void) {
    assert(mkdtemp(base));char path[PATH_MAX];
    const char *dirs[]={"proc","proc/2","holders"};
    for(unsigned i=0;i<3;i++){snprintf(path,sizeof(path),"%s/%s",base,dirs[i]);assert(mkdir(path,0700)==0);}
    const char *empty="1 0 179:6 / / ro - squashfs /dev/root ro\n";
    put("self",empty);put("proc/2/mountinfo",empty);put("swaps","Filename Type Size Used Priority\n");
    check("all_empty",1,NULL);unsigned total=calls;
    for(unsigned i=1;i<=total;i++){fail_at=i;check("readdir_error_fail_closed",0,NULL);}fail_at=0;
    put("self","1 0 179:11 / /private rw - ext4 /dev/mmcblk0p11 rw\n");
    check("self_mount_rejected",0,NULL);check("exact_private_self_allowed",1,"/private");check("wrong_private_path",0,"/wrong");
    put("self",empty);put("proc/2/mountinfo","1 0 179:11 / /other rw - ext4 /dev/mmcblk0p11 rw\n");check("other_namespace_rejected",0,NULL);
    put("proc/2/mountinfo",empty);fail_process=1;check("existing_process_read_failure",0,NULL);fail_process=0;
    put("holders/dm-0","");check("holder_rejected",0,NULL);snprintf(path,sizeof(path),"%s/holders/dm-0",base);assert(unlink(path)==0);
    put("swaps","Filename Type Size Used Priority\n/dev/fixture-swap partition 128 0 -2\n");check("p11_swap_rejected",0,NULL);
    swap_minor=12;check("other_swap_allowed",1,NULL);put("swaps","Filename Type Size Used Priority\n");
    vanish_process=1;check("vanished_process_enoent_allowed",1,NULL);vanish_process=0;
    const char *files[]={"self","swaps"};for(unsigned i=0;i<2;i++){snprintf(path,sizeof(path),"%s/%s",base,files[i]);assert(unlink(path)==0);}
    snprintf(path,sizeof(path),"%s/proc",base);assert(rmdir(path)==0);snprintf(path,sizeof(path),"%s/holders",base);assert(rmdir(path)==0);assert(rmdir(base)==0);
    printf("LEON_P11_CLEAR_VIEW_FIXTURE_PASS cases=%u\n",cases);return 0;
}
