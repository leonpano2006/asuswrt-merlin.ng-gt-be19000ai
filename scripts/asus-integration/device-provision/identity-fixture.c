/* SPDX-License-Identifier: GPL-2.0-or-later
 * Compile only for a disposable offline chroot. Input is synthetic crypt data.
 */
#define _GNU_SOURCE
#include "identity.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc,char **argv){
 if(argc!=2||strcmp(argv[1],"--fixture")||getuid()||geteuid())return 125;
 struct rlimit limit={0};if(setrlimit(RLIMIT_CORE,&limit)||prctl(PR_SET_DUMPABLE,0))return 125;umask(0077);
 char hash[256]={0};ssize_t n=read(0,hash,sizeof(hash));if(n<1||n>=(ssize_t)sizeof(hash)||hash[n-1]!='\n'||memchr(hash,0,n))return 125;hash[n-1]=0;
 uid_t uid=0;bool already=false;int rc=leon_identity_provision(hash,&uid,&already);explicit_bzero(hash,sizeof(hash));
 if(rc){fprintf(stderr,"LEON_PROVISION_FIXTURE_REFUSED errno=%d\n",errno);return 125;}
 return leon_identity_public_export(uid,already)?125:0;
}
