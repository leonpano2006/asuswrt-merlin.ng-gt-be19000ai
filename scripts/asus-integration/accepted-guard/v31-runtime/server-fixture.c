/* SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU-only process/socket fixture. NO hardware adapter is linked.
 * Always denies ASSERT_ARMED. Passing ACK is not a hardware ownership claim.
 */
#define _GNU_SOURCE
#include "control-server.h"
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(void){
 alarm(100);struct trial_control_state s={0};FILE *f=fopen("/proc/sys/kernel/random/boot_id","re");if(!f||!fgets(s.boot_id,sizeof(s.boot_id),f))return 125;fclose(f);s.boot_id[36]=0;
 int fd=trial_control_open();if(fd<0){perror("trial fixture socket");return 125;}
 puts("LAB_TRIAL_ACK_FIXTURE_READY");fflush(stdout);
 for(;;){struct pollfd p={.fd=fd,.events=POLLIN};if(poll(&p,1,1000)<0)return 125;struct timespec t;if(clock_gettime(CLOCK_BOOTTIME,&t))return 125;uint64_t now=(uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;if(p.revents&POLLIN&&trial_control_serve(fd,&s,now)){puts("LAB_TRIAL_ACK_NEW_AUTHENTICATED_SESSION_PASS");fflush(stdout);}}
}
