/* Fixture only: dynamic-loader trace. Never execute static vendor programs. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static double monotonic(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(1);return t.tv_sec+t.tv_nsec/1e9;}
static int run(const char *abi,const char *kind,const char *target,const char *plugin,int negative){
 const char *loader=!strcmp(abi,"armel")?"/lib/ld-linux.so.3":"/lib/ld-linux-aarch64.so.1";
 int fd=open("/run/asus-loader-output",O_RDWR|O_CREAT|O_TRUNC,0600),status=0;pid_t pid;char *out;struct stat st;double start=monotonic();
 if(fd<0)return 1;
 pid=fork();if(pid<0)return 1;
 if(pid==0){
  char *app[]={ (char *)target,NULL};char *dso[]={ (char *)loader,"--inhibit-cache",(char *)target,NULL};
  if(dup2(fd,1)<0||dup2(fd,2)<0)_exit(121);close(fd);
  setenv("LD_TRACE_LOADED_OBJECTS","1",1);setenv("LD_WARN","1",1);setenv("LD_BIND_NOW","1",1);setenv("LD_LIBRARY_PATH","/usr/$LIB/asus",1);
  if(strcmp(plugin,"-"))setenv("LD_PRELOAD",plugin,1);else unsetenv("LD_PRELOAD");
  if(!strcmp(kind,"application"))execv(target,app);else execv(loader,dso);_exit(122);
 }
 for(;;){pid_t got=waitpid(pid,&status,WNOHANG);if(got==pid)break;if(got<0&&errno!=EINTR)return 1;if(monotonic()-start>10){kill(pid,SIGKILL);waitpid(pid,&status,0);fprintf(stderr,"TIMEOUT %s\n",target);return 1;}struct timespec nap={0,1000000};nanosleep(&nap,NULL);}
 if(fstat(fd,&st)||st.st_size<1||st.st_size>1048576)return 1;
 out=calloc(1,(size_t)st.st_size+1);if(!out)return 1;if(lseek(fd,0,SEEK_SET)<0||read(fd,out,(size_t)st.st_size)!=st.st_size)return 1;close(fd);
 int missing=strstr(out,"undefined symbol")||strstr(out,"not found")||strstr(out,"error while loading")||strstr(out,"cannot open shared");
 int bad=!WIFEXITED(status)||WEXITSTATUS(status)!=0||(!negative&&missing)||(negative&&!strstr(out,"undefined symbol: leon_absent_negative_control"))||(!negative&&!strstr(out,"=> ")&&!strstr(out,"ld-linux")&&!strstr(out,"statically linked"));
 if(bad)fprintf(stderr,"FAIL %s %s status=%d\n%s",target,plugin,status,out);free(out);return bad;
}
int main(int argc,char **argv){
 if(argc!=3)return 2;FILE *f=fopen(argv[1],"r");if(!f)return 2;char *line=NULL;size_t size=0;unsigned count=0;double start=monotonic();
 while(getline(&line,&size,f)>0){char *save=NULL,*abi=strtok_r(line,"|\n",&save),*kind=strtok_r(NULL,"|\n",&save),*target=strtok_r(NULL,"|\n",&save),*plugin=strtok_r(NULL,"|\n",&save);if(!abi||!kind||!target||!plugin||run(abi,kind,target,plugin,0))return 1;count++;if(count%100==0){printf("LAB_ASUS_RUNTIME_TRACE_PROGRESS_count=%u\n",count);fflush(stdout);}}
 free(line);fclose(f);if(count!=(unsigned)strtoul(argv[2],NULL,10))return 1;
 printf("LAB_ASUS_RUNTIME_ALL_LOADER_SCOPES_PASS_count=%u elapsed=%.2f\n",count,monotonic()-start);
 if(run("armel","application","/usr/libexec/leon-lab/asus-runtime/canary","-",0)||run("armel","library","/usr/libexec/leon-lab/asus-runtime/unresolved.so","-",1))return 1;
 puts("LAB_ASUS_RUNTIME_NO_MAIN_CTORS_AND_NEGATIVE_CONTROL_PASS");return 0;
}
