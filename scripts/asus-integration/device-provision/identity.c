/* SPDX-License-Identifier: GPL-2.0-or-later
 * Device-local identity transaction. Adapted from reviewed native SSH0.4
 * single-entry shadow/key initialization; no native SSH service-control path.
 * Partial state is preserved and refused, never automatically regenerated.
 */
#define _GNU_SOURCE
#include "identity.h"
#define ssh_request_valid __attribute__((unused)) ssh_request_valid
#include "validate.h"
#undef ssh_request_valid
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define STATE "/var/lib/leon-asus-ssh"
static const char *const names[]={"ssh_host_rsa_key","ssh_host_ecdsa_key","ssh_host_ed25519_key"};
static int directory(const char *path,bool create,mode_t mode){struct stat st;if(create&&mkdir(path,mode)&&errno!=EEXIST)return -1;if(lstat(path,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0022)){errno=EPERM;return -1;}return 0;}
static int sync_dir(const char *path){int fd=open(path,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);if(fd<0)return -1;int result=fsync(fd),saved=errno;close(fd);errno=saved;return result;}
static int read_file(const char *path,char **data,size_t *size){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);struct stat st;if(fd<0)return -1;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0022)||st.st_size<0||st.st_size>1048576){close(fd);errno=EPERM;return -1;}
 char *buffer=calloc(1,(size_t)st.st_size+1);if(!buffer){close(fd);return -1;}size_t used=0;
 while(used<(size_t)st.st_size){ssize_t n=read(fd,buffer+used,(size_t)st.st_size-used);if(n<0&&errno==EINTR)continue;if(n<=0){explicit_bzero(buffer,(size_t)st.st_size);free(buffer);close(fd);return -1;}used+=(size_t)n;}
 close(fd);if(memchr(buffer,0,used)){explicit_bzero(buffer,used);free(buffer);return -1;}*data=buffer;*size=used;return 0;
}
static int atomic_file(const char *path,const char *data,size_t length,mode_t mode,gid_t group,bool exclusive){
 char temporary[PATH_MAX],parent[PATH_MAX];int rc=-1,saved;
 if(snprintf(temporary,sizeof(temporary),"%s.tmp.XXXXXX",path)>=(int)sizeof(temporary)){errno=ENAMETOOLONG;return -1;}strcpy(parent,path);char *slash=strrchr(parent,'/');if(!slash)return -1;*slash=0;
 int fd=mkstemp(temporary);if(fd<0)return -1;
 if(fchmod(fd,mode)||fchown(fd,0,group))goto done;
 for(size_t pos=0;pos<length;){ssize_t n=write(fd,data+pos,length-pos);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;pos+=(size_t)n;}
 if(fsync(fd))goto done;
 if(exclusive){if(link(temporary,path)||unlink(temporary))goto done;}else if(rename(temporary,path))goto done;
 rc=sync_dir(parent);
done:saved=errno;close(fd);if(rc)unlink(temporary);errno=saved;return rc;
}
static int command(char *const args[],char *out,size_t cap){
 int pipefd[2],status;size_t used=0;if(out&&pipe2(pipefd,O_CLOEXEC))return -1;
 pid_t pid=fork();if(pid<0){if(out){close(pipefd[0]);close(pipefd[1]);}return -1;}
 if(!pid){int null=open("/dev/null",O_RDWR|O_CLOEXEC);if(null<0||dup2(null,0)<0||dup2(null,2)<0)_exit(125);if(out){close(pipefd[0]);if(dup2(pipefd[1],1)<0)_exit(125);close(pipefd[1]);}else if(dup2(null,1)<0)_exit(125);if(null>2)close(null);alarm(30);execv(args[0],args);_exit(127);}
 if(out){close(pipefd[1]);while(used<cap-1){ssize_t n=read(pipefd[0],out+used,cap-1-used);if(n<0&&errno==EINTR)continue;if(n<0){kill(pid,SIGKILL);break;}if(!n)break;used+=(size_t)n;}close(pipefd[0]);out[used]=0;if(used==cap-1)kill(pid,SIGKILL);}
 while(waitpid(pid,&status,0)<0)if(errno!=EINTR)return -1;
 if(!WIFEXITED(status)||WEXITSTATUS(status)||(out&&used==cap-1)){errno=EIO;return -1;}return 0;
}
int leon_identity_hash_valid(const char *hash){return hash&&strnlen(hash,256)<256&&ssh_hash_valid(hash);}
static int account(uid_t *uid,gid_t *gid){
 char *text=NULL;size_t size;unsigned matches=0;int result=-1;if(read_file("/etc/passwd",&text,&size))return -1;
 char *save;for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
  if(strncmp(line,LEON_SSH_ADMIN ":",sizeof(LEON_SSH_ADMIN)))continue;
  char *fields[7],*cursor=line;for(unsigned i=0;i<7;++i){fields[i]=strsep(&cursor,":");if(!fields[i])goto done;}
  if(cursor||strcmp(fields[0],LEON_SSH_ADMIN)||strcmp(fields[1],"x")||strcmp(fields[5],"/home/" LEON_SSH_ADMIN)||strcmp(fields[6],"/bin/bash"))goto done;
  char *end;errno=0;unsigned long u=strtoul(fields[2],&end,10);if(errno||*end||u<1000||u>=65534)goto done;unsigned long g=strtoul(fields[3],&end,10);if(errno||*end||g>UINT_MAX)goto done;*uid=u;*gid=g;if(++matches!=1)goto done;
 }
 result=matches==1?0:1;
done:free(text);return result;
}
static int home_ready(uid_t uid,gid_t gid){struct stat st;return lstat("/home/" LEON_SSH_ADMIN,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&0022)?-1:0;}
static int sudo_member(gid_t gid){char *text;size_t size;if(read_file("/etc/group",&text,&size))return -1;char *save;int result=-1;unsigned matches=0;
 for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save))if(!strncmp(line,"sudo:",5)){if(++matches!=1){result=-1;break;}char *cursor=line,*f[4];for(unsigned i=0;i<4;++i){f[i]=strsep(&cursor,":");if(!f[i])goto done;}if(cursor)goto done;char *end;unsigned long group=strtoul(f[2],&end,10);if(*end||group>UINT_MAX)goto done;if(group==gid)result=0;char *s2;for(char *user=strtok_r(f[3],",",&s2);user;user=strtok_r(NULL,",",&s2))if(!strcmp(user,LEON_SSH_ADMIN))result=0;}
done:free(text);return result;}
static int selected_shadow(const char *hash,bool update){
 char *old=NULL,*next=NULL;size_t size=0,used=0;struct stat st;int result=-1,found=0,saved;
 if(lckpwdf())return -1;
 if(lstat("/etc/shadow",&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0027)||read_file("/etc/shadow",&old,&size))goto done;
 next=calloc(1,size+256);if(!next)goto done;
 for(char *line=old;line<old+size;){char *end=memchr(line,'\n',(size_t)(old+size-line));if(!end)goto done;size_t length=(size_t)(end-line)+1;
  if(!strncmp(line,LEON_SSH_ADMIN ":",sizeof(LEON_SSH_ADMIN))){char *sep=memchr(line+sizeof(LEON_SSH_ADMIN),':',length-sizeof(LEON_SSH_ADMIN));if(!sep||++found!=1)goto done;
   if(!update&&((size_t)(sep-line-sizeof(LEON_SSH_ADMIN))!=strlen(hash)||memcmp(line+sizeof(LEON_SSH_ADMIN),hash,strlen(hash))))goto done;
   memcpy(next+used,line,sizeof(LEON_SSH_ADMIN));used+=sizeof(LEON_SSH_ADMIN);memcpy(next+used,hash,strlen(hash));used+=strlen(hash);memcpy(next+used,sep,(size_t)(end+1-sep));used+=(size_t)(end+1-sep);
  }else{memcpy(next+used,line,length);used+=length;}line=end+1;
 }
 if(found!=1)goto done;
 result=!update?0:atomic_file("/etc/shadow",next,used,st.st_mode&0777,st.st_gid,false);
done:saved=errno;if(old){explicit_bzero(old,size);free(old);}if(next){explicit_bzero(next,size+256);free(next);}ulckpwdf();errno=saved;return result;
}
static int public_part(const char *text,char output[2048]){size_t a=strcspn(text," \t\r\n"),b;if(!a||a>40||text[a]!=' ')return -1;const char *key=text+a+1;b=strcspn(key," \t\r\n");if(b<16||a+1+b>=2048||!ssh_chars(key,b,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="))return -1;memcpy(output,text,a+1+b);output[a+1+b]=0;return 0;}
static int key_pair(const char *private,char public_out[2048]){
 char pubpath[PATH_MAX],derived[4096],*pub;size_t size;struct stat st;
 if(snprintf(pubpath,sizeof(pubpath),"%s.pub",private)>=(int)sizeof(pubpath))return -1;
 if(lstat(private,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600)return -1;
 if(lstat(pubpath,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0644||read_file(pubpath,&pub,&size))return -1;
 int rc=public_part(pub,public_out);free(pub);if(rc)return -1;
 char *args[]={"/usr/bin/ssh-keygen","-y","-f",(char *)private,NULL};if(command(args,derived,sizeof(derived)))return -1;char canonical[2048];return public_part(derived,canonical)||strcmp(canonical,public_out)?-1:0;
}
static int exact_marker(const char *path,const char *expected){char *data;size_t size;struct stat st;if(lstat(path,&st)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||read_file(path,&data,&size))return -1;int rc=size==strlen(expected)&&!memcmp(data,expected,size)?0:-1;free(data);return rc;}
static int staging_absent(void){
 DIR *d=opendir("/etc/ssh");if(!d)return -1;int rc=0;struct dirent *e;while((e=readdir(d)))if(!strncmp(e->d_name,".leon-device-init.",18)){rc=-1;break;}closedir(d);return rc;
}
static int no_partial(void){
 struct stat st;if(!lstat("/home/" LEON_SSH_ADMIN,&st)||errno!=ENOENT)return -1;const char *markers[]={STATE "/account",STATE "/device-identity",STATE "/provision-in-progress"};for(unsigned i=0;i<3;++i)if(!lstat(markers[i],&st)||errno!=ENOENT)return -1;
 for(unsigned i=0;i<3;++i)for(unsigned pub=0;pub<2;++pub){char path[128];snprintf(path,sizeof(path),"/etc/ssh/%s%s",names[i],pub?".pub":"");if(!lstat(path,&st)||errno!=ENOENT)return -1;}
 return staging_absent();
}
static int create_keys(void){
 char staging[]="/etc/ssh/.leon-device-init.XXXXXX",nested[PATH_MAX];if(!mkdtemp(staging))return -1;
 snprintf(nested,sizeof(nested),"%s/etc",staging);if(mkdir(nested,0700))return -1;snprintf(nested,sizeof(nested),"%s/etc/ssh",staging);if(mkdir(nested,0700))return -1;
 char *args[]={"/usr/bin/ssh-keygen","-A","-f",staging,NULL};if(command(args,NULL,0))return -1;
 for(unsigned i=0;i<3;++i){char source[PATH_MAX],pub[PATH_MAX],key[2048];snprintf(source,sizeof(source),"%s/etc/ssh/%s",staging,names[i]);if(snprintf(pub,sizeof(pub),"%s.pub",source)>=(int)sizeof(pub)||chmod(source,0600)||chmod(pub,0644)||key_pair(source,key))return -1;}
 for(unsigned i=0;i<3;++i)for(unsigned pub=0;pub<2;++pub){char source[PATH_MAX],target[128];snprintf(source,sizeof(source),"%s/etc/ssh/%s%s",staging,names[i],pub?".pub":"");snprintf(target,sizeof(target),"/etc/ssh/%s%s",names[i],pub?".pub":"");if(link(source,target)||unlink(source))return -1;int fd=open(target,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;int result=fsync(fd),saved=errno;close(fd);errno=saved;if(result)return -1;}
 if(rmdir(nested))return -1;
 snprintf(nested,sizeof(nested),"%s/etc",staging);if(rmdir(nested)||rmdir(staging)||sync_dir("/etc/ssh"))return -1;return 0;
}
int leon_identity_provision(const char *hash,uid_t *uid,bool *already){
 if(getuid()||geteuid()||!leon_identity_hash_valid(hash)){errno=EPERM;return -1;}
 const char *dirs[]={"/etc","/etc/ssh","/var","/var/lib","/home"};for(unsigned i=0;i<5;++i)if(directory(dirs[i],false,0))return -1;
 if(directory(STATE,true,0755))return -1;
 int lock=open(STATE "/provision.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);if(lock<0)return -1;struct stat st;if(fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||flock(lock,LOCK_EX|LOCK_NB)){close(lock);return -1;}
 gid_t gid;int existing=account(uid,&gid),rc=-1;char marker[128],key[2048];*already=false;
 if(existing==0){
  snprintf(marker,sizeof(marker),"LEON_SSH_ACCOUNT_V1 %s %u\n",LEON_SSH_ADMIN,(unsigned)*uid);
  if(exact_marker(STATE "/account",marker)||exact_marker(STATE "/device-identity","LEON_SSH_DEVICE_V1_OK\n")||!lstat(STATE "/provision-in-progress",&st)||errno!=ENOENT||sudo_member(gid)||home_ready(*uid,gid)||selected_shadow(hash,false)||staging_absent())goto done;
  for(unsigned i=0;i<3;++i){char path[128];snprintf(path,sizeof(path),"/etc/ssh/%s",names[i]);if(key_pair(path,key))goto done;}*already=true;rc=0;goto done;
 }
 if(existing!=1||no_partial())goto done;
 if(atomic_file(STATE "/provision-in-progress","LEON_DEVICE_PROVISION_V1\n",25,0600,0,true))goto done;
 char *args[]={"/usr/sbin/useradd","--create-home","--no-log-init","--shell","/bin/bash","--groups","sudo",LEON_SSH_ADMIN,NULL};if(command(args,NULL,0)||account(uid,&gid)||sudo_member(gid)||home_ready(*uid,gid)||selected_shadow(hash,true))goto done;
 if(create_keys())goto done;
 snprintf(marker,sizeof(marker),"LEON_SSH_ACCOUNT_V1 %s %u\n",LEON_SSH_ADMIN,(unsigned)*uid);
 if(atomic_file(STATE "/account",marker,strlen(marker),0600,0,true))goto done;
 if(atomic_file(STATE "/device-identity","LEON_SSH_DEVICE_V1_OK\n",22,0600,0,true))goto done;
 if(unlink(STATE "/provision-in-progress")||sync_dir(STATE))goto done;
 rc=0;
done:close(lock);return rc;
}
int leon_identity_public_export(uid_t uid,bool already){
 /* Complete verification before any success output. Only public material. */
 char keys[3][2048],fingerprints[3][81];
 for(unsigned i=0;i<3;++i){
  char path[128],fingerprint[2048];snprintf(path,sizeof(path),"/etc/ssh/%s",names[i]);
  if(key_pair(path,keys[i]))return -1;
  strcat(path,".pub");char *args[]={"/usr/bin/ssh-keygen","-l","-E","sha256","-f",path,NULL};
  if(command(args,fingerprint,sizeof(fingerprint)))return -1;
  char *fp=strstr(fingerprint,"SHA256:");if(!fp)return -1;size_t length=strcspn(fp," \t\r\n");
  if(length<8||length>80)return -1;
  memcpy(fingerprints[i],fp,length);fingerprints[i][length]=0;
 }
 printf("{\"schema\":1,\"status\":\"%s\",\"account\":\"%s\",\"uid\":%u}\n",already?"already-initialized":"initialized",LEON_SSH_ADMIN,(unsigned)uid);
 for(unsigned i=0;i<3;++i)printf("public_key %s\nfingerprint %s\n",keys[i],fingerprints[i]);
 return fflush(stdout);
}
