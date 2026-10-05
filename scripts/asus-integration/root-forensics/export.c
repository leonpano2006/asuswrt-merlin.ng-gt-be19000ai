/* SPDX-License-Identifier: GPL-2.0-or-later
 * Fixed allowlist only; no guest execution, link following or filesystem writes.
 * stdout is a bounded ustar stream. Treat log contents as private evidence.
 */
#define _GNU_SOURCE
#include "export.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#define CAP (32U*1024U*1024U)
#define METACAP 131072U
static char metadata[METACAP];static size_t metaused;static uint64_t exported;static unsigned count;static dev_t volume;
/* Context contains only fixed allowlist paths, canonical machine/trace names,
 * or safe_name-validated journal names. Never include rejected raw dirents. */
static char reject_path[512];static const char *reject_stage;
static void context(const char *path,const char *stage){snprintf(reject_path,sizeof(reject_path),"%s",path);reject_stage=stage;errno=0;}
static int refused(void){int error=errno?errno:EIO;dprintf(2,"LEON_FORENSIC_EXPORT_REFUSED stage=%s path=%s errno=%d\n",reject_stage?reject_stage:"unknown",reject_path,error);errno=error;return -1;}
static int policy_error(int error){errno=error;return -1;}
static int note(const char *fmt,...){va_list ap;va_start(ap,fmt);int n=vsnprintf(metadata+metaused,METACAP-metaused,fmt,ap);va_end(ap);if(n<0||(size_t)n>=METACAP-metaused)return policy_error(ENOSPC);metaused+=(size_t)n;return 0;}
static int sendall(const void *data,size_t size){const char *p=data;while(size){ssize_t n=write(1,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;size-=(size_t)n;}return 0;}
static int header(const char *path,size_t size){unsigned char h[512]={0};size_t len=strlen(path);if(len>100){const char *s=strrchr(path,'/');if(!s||(size_t)(s-path)>155||strlen(s+1)>100)return -1;memcpy(h+345,path,(size_t)(s-path));strcpy((char *)h,s+1);}else memcpy(h,path,len);snprintf((char *)h+100,8,"%07o",0600);snprintf((char *)h+108,8,"%07o",0);snprintf((char *)h+116,8,"%07o",0);snprintf((char *)h+124,12,"%011lo",(unsigned long)size);snprintf((char *)h+136,12,"%011o",0);memset(h+148,' ',8);h[156]='0';memcpy(h+257,"ustar",5);memcpy(h+263,"00",2);unsigned sum=0;for(unsigned i=0;i<512;i++)sum+=h[i];snprintf((char *)h+148,7,"%06o",sum);h[155]=' ';return sendall(h,512);}
static int pad(size_t n){static const char zero[512]={0};return n%512?sendall(zero,512-n%512):0;}
static int safe_name(const char *s){if(!*s||!strcmp(s,".")||!strcmp(s,".."))return 0;size_t n=strlen(s);/* Only the final tilde of the already-allowed .journal~ suffix is eligible. */if(n>=9&&!strcmp(s+n-9,".journal~"))--n;for(size_t i=0;i<n;i++)if(!((s[i]>='a'&&s[i]<='z')||(s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')||strchr("._@-",s[i])))return 0;return 1;}
static int machine(const char *s){if(strlen(s)!=32)return 0;for(;*s;s++)if(!strchr("0123456789abcdef",*s))return 0;return 1;}
/* Intermediate components must be real root-owned non-writable directories. */
static int directory(int root,const char *path){context(path,"directory-open");char copy[256];if(strlen(path)>=sizeof(copy))return policy_error(ENAMETOOLONG);strcpy(copy,path);int fd=dup(root);if(fd<0)return -1;char *save,*part=strtok_r(copy,"/",&save);while(part){int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);int saved=errno;close(fd);errno=saved;if(next<0)return -1;struct stat st;if(fstat(next,&st)){saved=errno;close(next);errno=saved;return -1;}if(st.st_dev!=volume||st.st_uid||(st.st_mode&0022)){close(next);return policy_error(EPERM);}fd=next;part=strtok_r(NULL,"/",&save);}return fd;}
static int statnote(int parent,const char *name,const char *path){context(path,"metadata-stat");struct stat st;if(fstatat(parent,name,&st,AT_SYMLINK_NOFOLLOW)){if(errno==ENOENT)return note("path=%s missing\n",path);return -1;}return note("path=%s type=%o mode=%04o uid=%u gid=%u size=%lld nlink=%lu mtime=%lld\n",path,st.st_mode&S_IFMT,st.st_mode&07777,st.st_uid,st.st_gid,(long long)st.st_size,(unsigned long)st.st_nlink,(long long)st.st_mtim.tv_sec);}
static int fixedmeta(int root,const char *path){char copy[256];if(strlen(path)>=sizeof(copy))return -1;strcpy(copy,path);char *last=strrchr(copy,'/');if(!last)return -1;*last++=0;int d=directory(root,copy);if(d<0){if(errno==ENOENT)return note("path=%s parent-missing\n",path);return note("path=%s parent-refused errno=%d\n",path,errno);}int rc=statnote(d,last,path);close(d);return rc;}
static int file(int parent,const char *name,const char *path,size_t percap,unsigned exactmode){struct stat before,after;if(statnote(parent,name,path))return -1;context(path,"file-open");int fd=openat(parent,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);if(fd<0)return -1;int rc=-1;context(path,"file-stat");if(fstat(fd,&before))goto done;context(path,"file-policy");if(!S_ISREG(before.st_mode)||before.st_dev!=volume||before.st_uid||before.st_nlink!=1||(before.st_mode&0022)||before.st_size<0){errno=EPERM;goto done;}
 if(exactmode&&((before.st_mode&07777)!=exactmode||before.st_gid||(uint64_t)before.st_size>percap)){errno=EPERM;goto done;}
 if((uint64_t)before.st_size>percap||(uint64_t)before.st_size>CAP-exported){rc=note("path=%s skipped-size-cap bytes=%lld\n",path,(long long)before.st_size);goto done;}
 context(path,"file-count");if(++count>128){errno=E2BIG;goto done;}context(path,"tar-header");if(header(path,(size_t)before.st_size))goto done;char buf[65536];off_t off=0;while(off<before.st_size){size_t want=(size_t)(before.st_size-off);if(want>sizeof(buf))want=sizeof(buf);context(path,"file-read");ssize_t n=pread(fd,buf,want,off);if(n<0&&errno==EINTR)continue;if(n<=0){if(!n)errno=EIO;goto done;}context(path,"tar-write");if(sendall(buf,(size_t)n))goto done;off+=n;}
 context(path,"file-recheck");if(fstat(fd,&after))goto done;if(after.st_dev!=before.st_dev||after.st_ino!=before.st_ino||after.st_size!=before.st_size||after.st_mtim.tv_sec!=before.st_mtim.tv_sec||after.st_mtim.tv_nsec!=before.st_mtim.tv_nsec){errno=ESTALE;goto done;}context(path,"tar-padding");if(pad((size_t)off))goto done;exported+=(uint64_t)off;rc=0;
done:{int saved=errno;close(fd);errno=saved;}return rc;}
static int fixedfile(int root,const char *path,size_t limit){context(path,"fixed-file-path");char copy[256];if(strlen(path)>=sizeof(copy))return policy_error(ENAMETOOLONG);strcpy(copy,path);char *last=strrchr(copy,'/');*last++=0;int d=directory(root,copy);if(d<0)return errno==ENOENT?note("path=%s parent-missing\n",path):-1;struct stat st;int rc;if(fstatat(d,last,&st,AT_SYMLINK_NOFOLLOW)&&errno==ENOENT)rc=note("path=%s missing\n",path);else rc=file(d,last,path,limit,0);int saved=errno;close(d);errno=saved;return rc;}
static int journals(int root){int fd=directory(root,"var/log/journal");if(fd<0)return errno==ENOENT?note("path=var/log/journal missing\n"):-1;context("var/log/journal","journal-fdopendir");DIR *dir=fdopendir(fd);if(!dir){int saved=errno;close(fd);errno=saved;return -1;}unsigned dirs=0;int rc=-1;for(;;){context("var/log/journal","journal-readdir");struct dirent *de=readdir(dir);if(!de){if(errno)goto done;break;}if(!strcmp(de->d_name,".")||!strcmp(de->d_name,".."))continue;if(++dirs>32){reject_stage="journal-directory-count";errno=E2BIG;goto done;}if(!machine(de->d_name)){if(note("journal-root ignored-non-machine-name\n"))goto done;continue;}
 char path[256];snprintf(path,sizeof(path),"var/log/journal/%s",de->d_name);if(statnote(dirfd(dir),de->d_name,path))goto done;int child=directory(root,path);if(child<0)goto done;context(path,"journal-fdopendir");DIR *sub=fdopendir(child);if(!sub){int saved=errno;close(child);errno=saved;goto done;}unsigned entries=0;int subrc=0;for(;;){context(path,"journal-readdir");struct dirent *e=readdir(sub);if(!e){if(errno)subrc=-1;break;}if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;if(++entries>256){reject_stage="journal-entry-count";subrc=policy_error(E2BIG);break;}if(!safe_name(e->d_name)){reject_stage="journal-entry-name";subrc=policy_error(EINVAL);break;}size_t n=strlen(e->d_name);if(!((n>=8&&!strcmp(e->d_name+n-8,".journal"))||(n>=9&&!strcmp(e->d_name+n-9,".journal~"))))continue;char full[512];if(snprintf(full,sizeof(full),"%s/%s",path,e->d_name)>=(int)sizeof(full)){reject_stage="journal-path-length";subrc=policy_error(ENAMETOOLONG);break;}if(file(dirfd(sub),e->d_name,full,CAP,0)){subrc=-1;break;}}
 {int saved=errno;closedir(sub);errno=saved;}if(subrc)goto done;
 }rc=0;done:{int saved=errno;closedir(dir);errno=saved;}return rc;}
/* Only the bounded root-init trace format is eligible. Unrelated diagnostic
 * names are never opened; even their contents cannot enter the tar stream. */
static int trace_name(const char *name){
 if(strlen(name)!=36+sizeof(".root-init.log")-1||strcmp(name+36,".root-init.log"))return 0;
 for(unsigned i=0;i<36;++i){
  if(i==8||i==13||i==18||i==23){if(name[i]!='-')return 0;}
  else if(!strchr("0123456789abcdef",name[i]))return 0;
 }
 return 1;
}
static int root_traces(int root){
 const char *path="var/lib/leon-boot/diagnostics";
 int fd=directory(root,path);if(fd<0)return errno==ENOENT?note("path=%s missing\n",path):-1;
 context(path,"trace-directory-policy");struct stat st;if(fstat(fd,&st)){int saved=errno;close(fd);errno=saved;return -1;}if(st.st_gid||(st.st_mode&07777)!=0700){close(fd);return policy_error(EPERM);}
 context(path,"trace-fdopendir");DIR *dir=fdopendir(fd);if(!dir){int saved=errno;close(fd);errno=saved;return -1;}
 unsigned entries=0;int rc=-1;
 for(;;){
  context(path,"trace-readdir");struct dirent *de=readdir(dir);if(!de){if(errno)goto done;break;}
  if(!strcmp(de->d_name,".")||!strcmp(de->d_name,".."))continue;
  if(++entries>16){reject_stage="trace-entry-count";errno=E2BIG;goto done;}
  if(!trace_name(de->d_name)){if(note("root-init-trace ignored-noncanonical-name\n"))goto done;continue;}
  char full[160];if(snprintf(full,sizeof(full),"%s/%s",path,de->d_name)>=(int)sizeof(full)){reject_stage="trace-path-length";errno=ENAMETOOLONG;goto done;}
  if(file(dirfd(dir),de->d_name,full,8192,0600))goto done;
 }
 rc=0;
done:{int saved=errno;closedir(dir);errno=saved;}return rc;
}
/* Fixed 16KiB diagnostic file is intentionally exported even if one slot is
 * torn. The offline CRC parser, not the exporter, classifies record validity. */
static int fixed_diagnostics(int root){
 const char *path="etc/leon/boot-diagnostics";int parent=directory(root,"etc/leon");
 if(parent<0)return errno==ENOENT?note("path=%s parent-missing\n",path):-1;
 context(path,"fixed-diagnostics-stat");struct stat st;int rc=-1;
 if(fstatat(parent,"boot-diagnostics",&st,AT_SYMLINK_NOFOLLOW)){
  if(errno==ENOENT)rc=note("path=%s missing\n",path);
 }else if(st.st_size==16384)rc=file(parent,"boot-diagnostics",path,16384,0600);
 else {reject_stage="fixed-diagnostics-size";errno=EINVAL;}
 {int saved=errno;close(parent);errno=saved;}return rc;
}
int forensic_export(int root){context(".","root-stat");struct stat st;if(fstat(root,&st))return refused();if(!S_ISDIR(st.st_mode)){errno=ENOTDIR;return refused();}volume=st.st_dev;metaused=0;exported=0;count=0;context("metadata.txt","metadata-buffer");if(note("LEON_P11_FORENSICS_V1 readonly_noload=true guest_execution=false journal_cap=%u\n",CAP))return refused();
 const char *paths[]={"var/log/journal","var/lib/leon-asus-ssh","var/lib/leon-asus-ssh/account","var/lib/leon-asus-ssh/device-identity","var/lib/leon-asus-ssh/applied","var/lib/leon-boot","var/lib/leon-boot/diagnostics","etc/leon","etc/leon/root-generation","etc/leon/trial-slot-proof","etc/machine-id"};for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);i++)if(fixedmeta(root,paths[i]))return refused();
 if(fixedfile(root,"etc/leon/root-generation",4096)||fixedfile(root,"etc/leon/trial-slot-proof",65536)||fixed_diagnostics(root)||root_traces(root)||journals(root))return refused();
 const char *logs[]={"var/log/boot.log","var/log/syslog","var/log/kern.log"};for(unsigned i=0;i<3;i++)if(fixedfile(root,logs[i],1024*1024))return refused();
 context("metadata.txt","metadata-tar-write");if(note("exported_files=%u exported_bytes=%llu\n",count,(unsigned long long)exported)||header("metadata.txt",metaused)||sendall(metadata,metaused)||pad(metaused))return refused();static const char end[1024]={0};context("metadata.txt","tar-end");return sendall(end,sizeof(end))?refused():0;}
