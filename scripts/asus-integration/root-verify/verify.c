/* SPDX-License-Identifier: GPL-2.0-or-later
 * Exact archive projection and narrow device-identity deltas. No mutation API.
 * All content reads are relative to directory FDs, without following links.
 */
#define _GNU_SOURCE
#include "verify.h"
#include "root-policy.h"
#include "sha256-compat.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
static struct stat observed[RV_COUNT];
static unsigned char seen[RV_COUNT];
static dev_t volume;
static const char *secret;
static struct rv_counts counts;
static int error(const char *path,const char *reason){
 /* Never report content or hashes, including the account/key exceptions. */
 dprintf(2,"LEON_ROOT_VERIFY_REFUSED path=%s reason=%s\n",path,reason);return -1;
}
static int safe_name(const char *s){for(;*s;s++)if((unsigned char)*s<32||(unsigned char)*s==127)return 0;return 1;}
static int lookup(const char *path){size_t low=0,high=RV_COUNT;while(low<high){size_t mid=(low+high)/2;int c=strcmp(path,rv_entries[mid].path);if(!c)return (int)mid;if(c<0)high=mid;else low=mid+1;}return -1;}
static int read_small(int fd,char **out,size_t *size){struct stat st;if(fstat(fd,&st)||st.st_size<0||st.st_size>65536)return -1;char *data=calloc(1,(size_t)st.st_size+1);if(!data)return -1;size_t n=0;while(n<(size_t)st.st_size){ssize_t x=pread(fd,data+n,(size_t)st.st_size-n,(off_t)n);if(x<0&&errno==EINTR)continue;if(x<=0){free(data);return -1;}n+=(size_t)x;}if(memchr(data,0,n)){explicit_bzero(data,n);free(data);return -1;}*out=data;*size=n;return 0;}
static int shadow_value(int fd){char *data=NULL;size_t n;int rc=-1;if(read_small(fd,&data,&n))return -1;
 size_t base=strlen(RV_SHADOW_BASE);if(n<=base||memcmp(data,RV_SHADOW_BASE,base))goto done;
 char *line=data+base;const char *prefix="MastermixStudios:";if(strncmp(line,prefix,strlen(prefix)))goto done;line+=strlen(prefix);
 size_t hs=strlen(secret);if(strncmp(line,secret,hs)||line[hs]!=':')goto done;line+=hs+1;
 char *end;errno=0;unsigned long day=strtoul(line,&end,10);if(errno||end==line||day<20000||day>(unsigned long)(time(NULL)/86400)+1||strcmp(end,":0:99999:7:::\n"))goto done;rc=0;
done:if(data){explicit_bzero(data,n);free(data);}return rc;}
static int digest_fd(int fd,const char *want,uint64_t bytes){struct sha256_state ctx;unsigned char buffer[65536],digest[32];char hex[65];uint64_t total=0;sha256_init(&ctx);for(;;){ssize_t n=read(fd,buffer,sizeof(buffer));if(n<0&&errno==EINTR)continue;if(n<0)return -1;if(!n)break;total+=(uint64_t)n;if(total>bytes)return -1;sha256_update(&ctx,buffer,(unsigned)n);}if(total!=bytes)return -1;sha256_final(&ctx,digest);for(unsigned i=0;i<32;i++)snprintf(hex+2*i,3,"%02x",digest[i]);return strcmp(hex,want)?-1:0;}
static int attrs(int parent,const char *name,const struct rv_entry *entry){
 char path[PATH_MAX];if(snprintf(path,sizeof(path),"/proc/self/fd/%d/%s",parent,name)>=(int)sizeof(path))return -1;
 char names[8192];ssize_t n=llistxattr(path,names,sizeof(names));if(n<0)return -1;unsigned found=0;
 for(size_t pos=0;pos<(size_t)n;){size_t len=strnlen(names+pos,(size_t)n-pos);if(!len||pos+len>=(size_t)n)return -1;const struct rv_attr *want=NULL;
  for(unsigned j=0;j<entry->attrs;j++)if(!strcmp(names+pos,rv_attrs[entry->attr_start+j].name)){want=&rv_attrs[entry->attr_start+j];break;}
  if(!want)return -1;unsigned char value[8192];ssize_t size=lgetxattr(path,names+pos,value,sizeof(value));if(size<0||(size_t)size!=want->size)return -1;
  if(!strncmp(want->name,"system.posix_acl_",17)){
   if(size<4||(size-4)%8||memcmp(value,want->data,4))return -1;
   for(ssize_t j=4;j<size;j+=8){if(memcmp(value+j,want->data+j,4))return -1;unsigned tag=value[j]|value[j+1]<<8;if((tag==2||tag==8)&&memcmp(value+j+4,want->data+j+4,4))return -1;}
  }else if(memcmp(value,want->data,(size_t)size))return -1;
  found++;pos+=len+1;
 }
 return found==entry->attrs?0:-1;
}
static int visit(int parent,const char *name,const char *path,unsigned depth){
 if(depth>64||!safe_name(path))return error("<unsafe-path>","path-bound");int index=lookup(path);if(index<0)return error(path,"unexpected-entry");if(seen[index])return error(path,"duplicate-entry");const struct rv_entry *e=&rv_entries[index];struct stat st,after;
 if(fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)||st.st_dev!=volume)return error(path,"stat-or-volume");
 if((st.st_mode&S_IFMT)!=e->type||(st.st_mode&07777)!=e->mode||st.st_uid!=e->uid||st.st_gid!=e->gid)return error(path,"type-owner-mode");
 if(!S_ISDIR(st.st_mode)&&st.st_nlink!=e->links)return error(path,"link-count");
 if(attrs(parent,name,e))return error(path,"extended-attributes");
 seen[index]=1;observed[index]=st;counts.entries++;if(e->identity)counts.identity++;
 if(S_ISLNK(st.st_mode)){char target[PATH_MAX];ssize_t n=readlinkat(parent,name,target,sizeof(target));if(n<0||(size_t)n!=strlen(e->target)||memcmp(target,e->target,(size_t)n))return error(path,"symlink-target");counts.symlinks++;return 0;}
 if(S_ISCHR(st.st_mode)||S_ISBLK(st.st_mode))return major(st.st_rdev)==e->major&&minor(st.st_rdev)==e->minor?0:error(path,"device-number");
 if(!S_ISDIR(st.st_mode)&&!S_ISREG(st.st_mode))return error(path,"unsupported-type");
 int fd=openat(parent,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|(S_ISDIR(st.st_mode)?O_DIRECTORY:0));if(fd<0)return error(path,"open");int rc=-1;
 if(fstat(fd,&after)||after.st_dev!=st.st_dev||after.st_ino!=st.st_ino)goto done;
 if(S_ISREG(st.st_mode)){
  if(e->special==1){if(shadow_value(fd))goto done;}
  else if(e->special==2){if(st.st_size<32||st.st_size>32768)goto done;}
  else if(e->special==3){char *pub=NULL;size_t length;if(read_small(fd,&pub,&length))goto done;size_t wanted=strlen(e->target);int bad=length<=wanted||memcmp(pub,e->target,wanted)||(pub[wanted]!=' '&&pub[wanted]!='\n')||pub[length-1]!='\n'||memchr(pub,'\n',length-1);free(pub);if(bad)goto done;}
  else if(e->special==4){
   /* Only the generated exact path has this policy. Slots may contain torn
    * records; bounded contents are diagnostic, never acceptance authority. */
   if(strcmp(e->path,"etc/leon/boot-diagnostics")||e->size!=16384||st.st_size!=16384)goto done;
   unsigned char data[16384];size_t used=0;while(used<sizeof(data)){ssize_t n=pread(fd,data+used,sizeof(data)-used,(off_t)used);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;used+=(size_t)n;}
  }
  else if(st.st_size<0||(uint64_t)st.st_size!=e->size||digest_fd(fd,e->digest,e->size))goto done;
  counts.regular++;counts.bytes+=(uint64_t)st.st_size;rc=0;
 }else{
  DIR *dir=fdopendir(fd);if(!dir)goto done;fd=-1;unsigned entries=0;errno=0;struct dirent *de;
  while((de=readdir(dir))){if(!strcmp(de->d_name,".")||!strcmp(de->d_name,".."))continue;if(++entries>RV_COUNT){closedir(dir);return error(path,"directory-bound");}char child[PATH_MAX];int n=snprintf(child,sizeof(child),!strcmp(path,".")?"%s":"%s/%s",!strcmp(path,".")?de->d_name:path,de->d_name);if(n<0||n>=(int)sizeof(child)||visit(dirfd(dir),de->d_name,child,depth+1)){closedir(dir);return -1;}errno=0;}
  int saved=errno;closedir(dir);if(saved)return error(path,"readdir");rc=0;
 }
 if(fd>=0&&(fstat(fd,&after)||after.st_dev!=st.st_dev||after.st_ino!=st.st_ino||after.st_size!=st.st_size||after.st_mtim.tv_sec!=st.st_mtim.tv_sec||after.st_mtim.tv_nsec!=st.st_mtim.tv_nsec))rc=-1;
done:if(fd>=0)close(fd);return rc?error(path,"payload-or-lifetime"):0;
}
int rv_verify(int root,const char *stock_hash,struct rv_counts *out){
 struct stat st;memset(seen,0,sizeof(seen));memset(&counts,0,sizeof(counts));if(fstat(root,&st)||!S_ISDIR(st.st_mode)||!stock_hash||strlen(stock_hash)>=256)return -1;volume=st.st_dev;secret=stock_hash;
 if(visit(root,".",".",0))return -1;
 for(unsigned i=0;i<RV_COUNT;i++){if(!seen[i])return error(rv_entries[i].path,"missing-entry");if(rv_entries[i].canonical>=0){if(observed[i].st_ino!=observed[rv_entries[i].canonical].st_ino)return error(rv_entries[i].path,"hardlink-inode");counts.hardlinks++;}}
 secret=NULL;*out=counts;return 0;
}
