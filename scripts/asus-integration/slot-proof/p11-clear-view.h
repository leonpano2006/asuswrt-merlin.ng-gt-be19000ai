/* SPDX-License-Identifier: GPL-2.0-or-later
 * Read-only, bounded p11 consumer scan for stock-side provisioning helpers.
 * NULL requires no p11 mount anywhere. A non-NULL path permits exactly one
 * p11 mount in THIS process namespace at that exact path; all other observed
 * process namespaces still must have none. Caller holds its shared lock and
 * independently verifies stock root, partition/GPT identity and all filesystems.
 * This observation is not an atomic exclusion of unrelated future mounters.
 */
#ifndef LEON_P11_CLEAR_VIEW_H
#define LEON_P11_CLEAR_VIEW_H
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int leon_p11_mount_view(const char *filename,const char *allowed) {
    FILE *f=fopen(filename,"re");if(!f)return -1;
    char *line=NULL;size_t cap=0;unsigned lines=0,found=0;int rc=-1;
    while(getline(&line,&cap,f)>0) {
        unsigned id,parent,maj,min;char root[PATH_MAX],path[PATH_MAX],flags[256];
        if(++lines>4096 || strlen(line)>16384 ||
           sscanf(line,"%u %u %u:%u %4095s %4095s %255s",&id,&parent,&maj,&min,root,path,flags)!=7)goto done;
        if(maj==179 && min==11) {
            if(!allowed || ++found!=1 || strcmp(root,"/") || strcmp(path,allowed) || !strstr(line," - ext4 "))goto done;
        }
    }
    if(!ferror(f) && found==(allowed?1U:0U))rc=0;
done:free(line);fclose(f);return rc;
}

static int leon_p11_holders_clear(void) {
    DIR *d=opendir("/sys/class/block/mmcblk0p11/holders");if(!d)return -1;
    int rc=0;
    for(;;) {
        errno=0;struct dirent *e=readdir(d);
        if(!e){if(errno)rc=-1;break;}
        if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")){rc=-1;break;}
    }
    closedir(d);return rc;
}

static int leon_p11_swaps_clear(void) {
    FILE *f=fopen("/proc/swaps","re");if(!f)return -1;
    char *line=NULL;size_t cap=0;int rc=-1;unsigned n=0;
    while(getline(&line,&cap,f)>0) {
        if(++n==1)continue;
        char path[PATH_MAX];struct stat st;
        if(n>4096 || strlen(line)>16384 || sscanf(line,"%4095s",path)!=1 || stat(path,&st))goto done;
        if((S_ISBLK(st.st_mode) && major(st.st_rdev)==179 && minor(st.st_rdev)==11) ||
           (major(st.st_dev)==179 && minor(st.st_dev)==11))goto done;
    }
    if(n && !ferror(f))rc=0;
done:free(line);fclose(f);return rc;
}

static int leon_p11_clear_view(const char *own_private_mountpoint) {
    if(own_private_mountpoint && own_private_mountpoint[0]!='/')return -1;
    if(leon_p11_mount_view("/proc/self/mountinfo",own_private_mountpoint) ||
       leon_p11_holders_clear() || leon_p11_swaps_clear())return -1;
    DIR *dir=opendir("/proc");if(!dir)return -1;
    int rc=0;unsigned total=0;
    for(;;) {
        errno=0;struct dirent *entry=readdir(dir);
        if(!entry){if(errno)rc=-1;break;}
        if(entry->d_name[0]<'0' || entry->d_name[0]>'9')continue;
        char *end;errno=0;unsigned long pid=strtoul(entry->d_name,&end,10);if(errno || *end)continue;
        if(pid==(unsigned long)getpid())continue;
        if(++total>65536){rc=-1;break;}
        char path[128];snprintf(path,sizeof(path),"/proc/%lu/mountinfo",pid);
        if(leon_p11_mount_view(path,NULL)) {
            char process[64];struct stat st;snprintf(process,sizeof(process),"/proc/%lu",pid);
            if(lstat(process,&st)<0 && errno==ENOENT)continue;
            rc=-1;break;
        }
    }
    closedir(dir);return rc;
}
#endif
