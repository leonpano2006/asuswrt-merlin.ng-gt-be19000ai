/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
int fixture_anchor(void){return 19;}
int notify_rc(const char *event)
{
 if(strcmp(event,"restart_wireless"))return -1;
 int fd=open("/run/dm-notify-events",O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);
 if(fd<0)return -1;
 int result=write(fd,"restart_wireless\n",17)==17?0:-1;close(fd);
 return result?result:kill(1,SIGUSR1);
}
