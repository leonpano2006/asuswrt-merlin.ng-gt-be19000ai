/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "common.h"
#include "identity.h"
#include "launch-identity.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc,char **argv)
{
    int executable=-1,library=-1;
    /* Match the vendor monitor's sole optional crash-backup directory. */
    if(argc>2 || (argc==2 && strcmp(argv[1],"/data")))goto fail;
    if(dm_context()||dm_verified_broker(0))goto fail;
    executable=dm_secure_open(DM_VENDOR_PATH,0);
    if(executable<0||dm_hash_fd(executable,DM_VENDOR_SHA,1))goto fail;
    library=dm_secure_open(DM_LIBRARY_PATH,0);
    if(library<0||dm_hash_fd(library,DM_LIBRARY_SHA,0))goto fail;
    close(library);library=-1;
    if(clearenv()||setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1)||
       setenv("LD_LIBRARY_PATH","/usr/$LIB/asus",1)||setenv("LD_PRELOAD",DM_LIBRARY_PATH,1))goto fail;
    argv[0]="debug_monitor";
    extern char **environ;
    fexecve(executable,argv,environ);
fail:
    fprintf(stderr,"ASUS_DM_BRIDGE launcher refused errno=%d\n",errno?errno:EPERM);
    if(library>=0)close(library);
    if(executable>=0)close(executable);
    return 125;
}
