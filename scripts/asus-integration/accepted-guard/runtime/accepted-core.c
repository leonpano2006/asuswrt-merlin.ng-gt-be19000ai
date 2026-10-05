/* SPDX-License-Identifier: GPL-2.0-or-later
 * Small local core observation; no SSH/network/ASUS service health dependency.
 * Initial immutable identities are verified by unchanged full boot preflight.
 * This checks PID1 presence/namespace, not systemd DBus responsiveness.
 */
#define _GNU_SOURCE
#include "accepted-runtime.h"
#include "local-health.h"
#include "process-auth.h"
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#ifdef LEON_ACCEPTED_LOOP_FIXTURE
/* Hardware identity substitution only: fixture must verify actual dev/inode
 * against the declared ext4 loop/bind mounts. No health-bit override. */
int accepted_fixture_volume(const char *,unsigned);
#endif
static int volume(const char *path,unsigned minor_number){
 struct stat st;struct statfs fs;struct statvfs flags;
 if(stat(path,&st)||!S_ISDIR(st.st_mode)||st.st_uid||statfs(path,&fs)||fs.f_type!=0xef53||statvfs(path,&flags)||(flags.f_flag&ST_RDONLY))return -1;
#ifdef LEON_ACCEPTED_LOOP_FIXTURE
 return accepted_fixture_volume(path,minor_number);
#else
 return major(st.st_dev)!=179||minor(st.st_dev)!=minor_number?-1:0;
#endif
}
unsigned accepted_collect_core(const char *boot){(void)boot;unsigned bits=0;struct trial_process init;struct stat exe;
 if(!trial_process_read(1,&init)&&init.parent==0&&init.uid==0&&!trial_process_native(1)&&!stat("/proc/1/exe",&exe)&&S_ISREG(exe.st_mode)&&exe.st_uid==0)bits|=ACCEPT_CORE_PID1;
 if(!volume("/",11))bits|=ACCEPT_CORE_ROOT;
 if(!volume("/data",7)&&!volume("/jffs",9))bits|=ACCEPT_CORE_STORAGE;
 return bits<<ACCEPT_CORE_SHIFT;
}
unsigned accepted_collect_trial(const char *boot){return trial_collect_health(boot)|accepted_collect_core(boot);}
