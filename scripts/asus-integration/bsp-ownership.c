/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Read-only BSP prerequisite check. It never repairs a missing prerequisite. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include "rc-storage.h"
#include "bsp-devices.h"
#include "bsp-boot-policy.h"
#include <limits.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>

static void die(const char *why) { perror(why); exit(125); }

static void native_mount(const char *path, const char *expected_uuid, int read_only)
{
    struct stat current, native, dev;
    char native_path[PATH_MAX], source[PATH_MAX] = "", uuid[64];
    struct mntent *entry;
    FILE *mounts;
    int pipefd[2], status, count = 0;
    ssize_t used = 0, n;
    pid_t child;
    if (lstat(path, &current)) die(path);
    /* A read-only defaults root may retain the stock0777 inode mode. */
    if (!S_ISDIR(current.st_mode) || current.st_uid || (!read_only && (current.st_mode & 0022))) { errno=EPERM; die(path); }
    if (snprintf(native_path,sizeof(native_path),"/proc/1/root%s",path)>=(int)sizeof(native_path)) exit(125);
    if (stat(native_path,&native)) die("native mount identity");
    if (current.st_dev!=native.st_dev || current.st_ino!=native.st_ino) { errno=EXDEV;die("mount not owned by native PID1"); }
    mounts=setmntent("/proc/self/mounts","r");
    if (!mounts) die("mount table");
    while ((entry=getmntent(mounts))) {
        if (strcmp(entry->mnt_dir,path)) continue;
        if (strcmp(entry->mnt_type,"ext4") || !!hasmntopt(entry,"ro")!=read_only) { errno=EXDEV;die("BSP mount type/mode"); }
        if (strlen(entry->mnt_fsname)>=sizeof(source)) exit(125);
        strcpy(source,entry->mnt_fsname);count++;
    }
    endmntent(mounts);
    if (count!=1 || stat(source,&dev) || !S_ISBLK(dev.st_mode) || current.st_dev!=dev.st_rdev) { errno=EXDEV;die("BSP mount/block identity"); }
    if (pipe2(pipefd,O_CLOEXEC)) die("UUID pipe");
    child=fork(); if (child<0) die("UUID fork");
    if (!child) {
        close(pipefd[0]);
        if (dup2(pipefd[1],STDOUT_FILENO)<0) _exit(126);
        close(pipefd[1]);
        unsetenv("LD_PRELOAD");unsetenv("LD_LIBRARY_PATH");
        execl("/usr/sbin/blkid","blkid","-p","-s","UUID","-o","value","--",source,(char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    while (used<(ssize_t)sizeof(uuid)-1) {
        n=read(pipefd[0],uuid+used,sizeof(uuid)-1-(size_t)used);
        if(n<0 && errno==EINTR) continue;
        if(n<0) die("UUID read");
        if(!n) break;
        used+=n;
    }
    close(pipefd[0]);
    while(waitpid(child,&status,0)<0) if(errno!=EINTR) die("UUID wait");
    if(!WIFEXITED(status) || WEXITSTATUS(status) || used!=37 || uuid[36]!='\n') {errno=EIO;die("BSP UUID reader");}
    uuid[36]=0;
    if(strcmp(uuid,expected_uuid)) {errno=EXDEV;die("BSP UUID differs from policy");}
}

static void reject_provisioning(void)
{
    static const struct { const char *path; enum leon_bsp_flag_kind kind; } flags[]={
        {"/proc/environment/mfg_nvram_mode", LEON_BSP_MANUFACTURING},
        {"/proc/brcm/blxparms/mfg_nvram_mode", LEON_BSP_MANUFACTURING},
        {"/proc/environment/mfg_nvram_mode_debug", LEON_BSP_MANUFACTURING},
        {"/proc/brcm/blxparms/mfg_nvram_mode_debug", LEON_BSP_MANUFACTURING},
        {"/proc/environment/write_defaults", LEON_BSP_DEFAULTS_WRITE_PERMISSION},
        {"/proc/environment/vol_resize_enable", LEON_BSP_VOLUME_RESIZE}
    };
    char value[4], word[256];
    size_t i;
    FILE *f=fopen("/proc/cmdline","r");
    if(!f) die("kernel command line");
    while(fscanf(f,"%255s",word)==1) if(!strcmp(word,"erase_psi") || !strncmp(word,"erase_psi=",10)) {errno=EPERM;die("erase_psi requires maintenance workflow");}
    fclose(f);
    for(i=0;i<sizeof(flags)/sizeof(flags[0]);i++) {
        f=fopen(flags[i].path,"r");
        if(!f) {if(errno==ENOENT) continue;die(flags[i].path);}
        size_t used=fread(value,1,sizeof(value),f);
        if(ferror(f)) {errno=EIO;die(flags[i].path);}
        if(!leon_bsp_flag_allowed(flags[i].kind,value,used)) {
            fprintf(stderr,"BSP provisioning flag refused: %s\n",flags[i].path);
            errno=EPERM;die("BSP provisioning request requires maintenance workflow");
        }
        fclose(f);
    }
}

static void devices(void)
{
    struct stat st;
    size_t i;
    FILE *f;
    char value[256];
    struct mntent *entry;
    int found=0;
    f=setmntent("/proc/self/mounts","r");if(!f)die("device mount table");
    while((entry=getmntent(f))) if(!strcmp(entry->mnt_dir,"/dev") && !strcmp(entry->mnt_type,"devtmpfs")) found++;
    endmntent(f);if(found!=1) {errno=EXDEV;die("native devtmpfs required");}
    if(lstat("/etc/hotplug2.rules",&st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode&0022)) {errno=EPERM;die("private event-only rules required");}
    f=fopen("/etc/hotplug2.rules","r");
    if(!f || !fgets(value,sizeof(value),f) || strcmp(value,"# ASUS_NATIVE_UDEV_CALLBACKS_V1\n")) {errno=EPERM;die("legacy hotplug2 device mutation rules refused");}
    while(fgets(value,sizeof(value),f))
        if(strstr(value,"makedev ") || strstr(value,"remove /dev/") || strstr(value,"exec /sbin/modprobe")) {errno=EPERM;die("hotplug2 must not own device nodes");}
    fclose(f);
    if(lstat("/run/udev/control",&st) || !S_ISSOCK(st.st_mode) || st.st_uid) {errno=ENODEV;die("native udev control socket required");}
    f=fopen("/proc/sys/kernel/hotplug","r");
    if(f) {
        if(fgets(value,sizeof(value),f) && strcmp(value,"\n")) {errno=EBUSY;die("legacy kernel hotplug helper still active");}
        fclose(f);
    } else if(errno!=ENOENT) die("kernel hotplug helper");
    for(i=0;i<sizeof(leon_bsp_nodes)/sizeof(leon_bsp_nodes[0]);i++) {
        if(lstat(leon_bsp_nodes[i].path,&st) || !S_ISCHR(st.st_mode) || st.st_uid || st.st_gid ||
           (st.st_mode&0777)!=0600 || major(st.st_rdev)!=leon_bsp_nodes[i].major_number || minor(st.st_rdev)!=leon_bsp_nodes[i].minor_number) {
            errno=ENODEV;die(leon_bsp_nodes[i].path);
        }
    }
}

static void nvram_template(const char *input,int from_defaults)
{
    static const char prefix[]="/rom/etc/wlan/nvram/";
    char source[PATH_MAX], generation[]="/run/asus/nvram-defaults.XXXXXX", target[PATH_MAX];
    struct stat st;
    const char *c;
    if(!from_defaults) {
        if(strncmp(input,prefix,sizeof(prefix)-1)) {errno=EINVAL;die("calibration template prefix");}
        for(c=input+sizeof(prefix)-1;*c;c++)
            if(!((*c>='a'&&*c<='z') || (*c>='A'&&*c<='Z') || (*c>='0'&&*c<='9') || *c=='-' || *c=='_' || *c=='.')) {errno=EINVAL;die("calibration template name");}
    }
    if(!realpath(input,source) || strcmp(input,source) || lstat(source,&st) || !S_ISREG(st.st_mode) || st.st_uid || (!from_defaults && (st.st_mode&0022))) {errno=EPERM;die("immutable calibration template");}
    /* Packaging supplies a real empty compatibility mountpoint, never the
     * stock dangling symlink into read-only defaults. All mounts stay private. */
    if(lstat("/mnt/nvram",&st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode&0022)) {errno=EPERM;die("private calibration mountpoint");}
    if(!mkdtemp(generation)) die("calibration view");
    if(snprintf(target,sizeof(target),"%s/nvram.nvm",generation)>=(int)sizeof(target)) exit(125);
    if(symlink(source,target)) die("calibration template reference");
    if(mount(generation,"/mnt/nvram",NULL,MS_BIND,NULL) ||
       mount(NULL,"/mnt/nvram",NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)) die("private read-only calibration view");
}

int main(int argc,char **argv)
{
    FILE *policy;
    char line[128],key[16],uuid[2][37],extra;
    unsigned int i;
    static const char *const names[]={"defaults","ai"};
    int template_requested=argc==3 && !strcmp(argv[1],"--nvram-template");
    int defaults_requested=argc==2 && !strcmp(argv[1],"--nvram-defaults");
    if(!template_requested && !defaults_requested && (argc!=2 || strcmp(argv[1],"--require"))) return 2;
    leon_rc_private_etc_require();
    leon_storage_require();
    if(leon_storage_secure_read("/etc/asus/bsp-storage-ownership.conf",&policy)) die("native BSP storage policy");
    if(!fgets(line,sizeof(line),policy) || strcmp(line,"ASUS_BSP_STORAGE_V1\n")) {errno=EINVAL;die("BSP storage policy version");}
    for(i=0;i<2;i++) {
        if(!fgets(line,sizeof(line),policy) || sscanf(line,"%15s %36s %c",key,uuid[i],&extra)!=2 || strcmp(key,names[i]) || !leon_storage_uuid_valid(uuid[i])) {errno=EINVAL;die("BSP UUID policy");}
    }
    if(fgets(line,sizeof(line),policy)) {errno=EINVAL;die("extra BSP policy field");}
    fclose(policy);
    native_mount("/mnt/defaults",uuid[0],1);
    native_mount("/ai",uuid[1],0);
    reject_provisioning();
    devices();
    if(template_requested) nvram_template(argv[2],0);
    if(defaults_requested) nvram_template("/mnt/defaults/wl/nvram.nvm",1);
    return 0;
}
