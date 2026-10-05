/* SPDX-License-Identifier: GPL-2.0-or-later
 * Explicit native root command; transport is normally trusted SSH + sudo.
 * This program does not infer authorization from environment variables.
 */
#include "control.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static int uuid(const char *s){if(strlen(s)!=36)return 0;for(unsigned i=0;i<36;i++)if((i==8||i==13||i==18||i==23)?s[i]!='-':!strchr("0123456789abcdef",s[i]))return 0;return 1;}
static int boot_matches(const char *expected){char boot[40];FILE *f=fopen("/proc/sys/kernel/random/boot_id","re");if(!f)return 0;size_t n=fread(boot,1,sizeof(boot),f);fclose(f);return n==37&&boot[36]=='\n'&&!memcmp(boot,expected,36);}
static struct leon_trial_control request(unsigned op,const char *boot){struct leon_trial_control m={.magic=LEON_TRIAL_CONTROL_MAGIC,.version=1,.operation=op};strcpy(m.boot_id,boot);return m;}
int main(int argc,char **argv){
 alarm(12);if(argc!=4||getuid()||geteuid()||strcmp(argv[2],"--expected-boot-id")||!uuid(argv[3])||!boot_matches(argv[3]))return 125;
 int status_only=!strcmp(argv[1],"--status");if(!status_only&&strcmp(argv[1],"--accept-this-boot"))return 125;
 for(unsigned attempt=0;attempt<20;attempt++){
  struct leon_trial_control m=request(LEON_ACCEPT_STATUS,argv[3]);if(leon_trial_exchange(&m)||memcmp(m.boot_id,argv[3],37)||m.value>1)return 125;
  if(m.value||status_only){printf("LEON_ACCEPT_STATUS boot_id=%s accepted_this_boot=%u metadata_committed=2\n",argv[3],m.value);return 0;}
  m=request(LEON_ACCEPT_CHALLENGE,argv[3]);if(leon_trial_exchange(&m)||memcmp(m.boot_id,argv[3],37)||m.value!=20000||!m.sequence)return 125;
  m.operation=LEON_ACCEPT_THIS_BOOT;m.value=0;
  if(!leon_trial_exchange(&m)){if(memcmp(m.boot_id,argv[3],37)||m.value!=1)return 125;printf("LEON_ACCEPT_THIS_BOOT_OK boot_id=%s same_owner=true metadata_committed=2\n",argv[3]);return 0;}
  if(errno!=EAGAIN)return 125;
  struct timespec wait={.tv_nsec=200000000};nanosleep(&wait,NULL);
 }
 return 125;
}
