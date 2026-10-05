/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "control.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc,char **argv){
 alarm(3);if(argc!=2||strcmp(argv[1],"--assert-armed")||getuid()||geteuid())return 125;
 struct leon_trial_control m={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1,.operation=LEON_TRIAL_ASSERT_ARMED};
 if(leon_trial_exchange(&m)||m.value!=40||strnlen(m.boot_id,sizeof(m.boot_id))!=36)return 125;
 char current[40];FILE *f=fopen("/proc/sys/kernel/random/boot_id","re");if(!f)return 125;
 size_t n=fread(current,1,sizeof(current),f);fclose(f);
 return n!=37||current[36]!='\n'||memcmp(m.boot_id,current,36)?125:0;
}
