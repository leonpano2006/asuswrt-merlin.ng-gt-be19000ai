/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Event-only ASUS callback adapter. Native udev alone creates/removes nodes. */
#define _GNU_SOURCE
#include "rc-private-etc.h"
#include "rc-storage.h"
#include "rc-internal-storage.h"
#include <regex.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

struct callback { const char *name,*pattern; mode_t node_type; };
static const struct callback callbacks[]={
 {"asus_usb_interface","^[1-9]-[1-3][:.0-9]*$",0},
 {"asus_lp","^lp[0-9]+$",S_IFCHR},
 {"asus_tty","^tty(USB|ACM)[0-9]+$",S_IFCHR},
 {"asus_sg","^sg[0-9]+$",S_IFCHR},
 {"asus_sr","^sr[0-9]+$",S_IFBLK},
 {"asus_sd","^sd[a-z][0-9]*$",S_IFBLK},
 {"asus_mmc","^mmcblk[0-9]+p[0-9]+$",S_IFBLK},
 {"asus_usbbcm","^usbbcm$",0},
 {"hotplug","^(net|firmware|dump)$",0},
};

static int match(const char *pattern,const char *value)
{
    regex_t re;
    int result;
    if(regcomp(&re,pattern,REG_EXTENDED|REG_NOSUB)) return 0;
    result=regexec(&re,value,0,NULL,0)==0;
    regfree(&re);return result;
}

#ifndef LEON_DEVICE_EVENT_UNIT_TEST
static void await_node(const char *name,mode_t type)
{
    char path[96];
    struct stat st;
    struct timespec delay={.tv_nsec=100000000};
    unsigned int retry;
    if(snprintf(path,sizeof(path),"/dev/%s",name)>=(int)sizeof(path)) _exit(125);
    /* Kernel hotplug2 events precede udev completion; never create a node to
     * win that race. Remove callbacks retain the original no-node semantics. */
    for(retry=0;retry<50;retry++) {
        if(!lstat(path,&st) && (st.st_mode&S_IFMT)==type && st.st_uid==0) return;
        nanosleep(&delay,NULL);
    }
    errno=ETIMEDOUT;perror("Native udev node not ready for ASUS callback");_exit(125);
}
#endif

int main(int argc,char **argv)
{
    const struct callback *selected=NULL;
    size_t i;
    sigset_t mask;
    if(argc!=4 || strlen(argv[2])>63 || !match("^(add|remove|change|move|online|offline|bind|unbind)$",argv[3])) return 125;
    for(i=0;i<sizeof(callbacks)/sizeof(callbacks[0]);i++)
        if(!strcmp(argv[1],callbacks[i].name) && match(callbacks[i].pattern,argv[2])) selected=&callbacks[i];
    if(!selected) return 125;
    if(leon_internal_storage(argv[2])) return 125;
    if(strcmp(selected->name,"hotplug") && strcmp(argv[3],"add") && strcmp(argv[3],"remove")) return 125;
#ifdef LEON_DEVICE_EVENT_UNIT_TEST
    (void)mask;
    printf("%s %s %s type=%u\n",selected->name,argv[2],argv[3],(unsigned int)selected->node_type);
    return 0;
#else
    leon_rc_private_etc_require();
    leon_storage_require();
    if(selected->node_type && !strcmp(argv[3],"add")) await_node(argv[2],selected->node_type);
    if(setenv("ACTION",argv[3],1)) return 125;
    sigemptyset(&mask);
    if(sigprocmask(SIG_SETMASK,&mask,NULL)) return 125;
    if(!strcmp(selected->name,"hotplug"))
        execl("/usr/libexec/asus/rc","hotplug",argv[2],(char *)NULL);
    else
        execl("/usr/libexec/asus/rc",selected->name,argv[2],argv[3],(char *)NULL);
    perror("ASUS event callback exec");return 125;
#endif
}
