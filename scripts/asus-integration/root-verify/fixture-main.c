/* SPDX-License-Identifier: GPL-2.0-or-later; synthetic namespace only. */
#define _GNU_SOURCE
#include "verify.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){if(argc!=3||strcmp(argv[1],"--fixture"))return 64;char hash[256];if(!fgets(hash,sizeof(hash),stdin))return 64;size_t n=strlen(hash);if(!n||hash[n-1]!='\n')return 64;hash[n-1]=0;int root=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(root<0)return 125;struct rv_counts counts;int rc=rv_verify(root,hash,&counts);explicit_bzero(hash,sizeof(hash));close(root);if(!rc)printf("LAB_ROOT_PAYLOAD_FIXTURE_PASS entries=%u files=%u links=%u hardlinks=%u identity=%u\n",counts.entries,counts.regular,counts.symlinks,counts.hardlinks,counts.identity);return rc?125:0;}
