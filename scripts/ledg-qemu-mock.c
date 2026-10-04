/* Test only. Never deploy this library to a router. All hardware writes blocked. */
typedef unsigned int size_t;
extern int strcmp(const char *, const char *);
extern long strtol(const char *, char **, int);
extern char *getenv(const char *);
extern int printf(const char *, ...);
extern void _exit(int);
#include "nvram-fixture.h"
char *nvram_get(const char *k) {
 if (!strcmp(k,"re_mode")) return getenv("TEST_RE_MODE");
 if (!strcmp(k,"ledg_scheme")) return getenv("TEST_SCHEME");
 if (!strcmp(k,"x_Setting")) return "1";
 if (!strcmp(k,"productid")) return "GT-BE19000AI";
 for(unsigned int n=0;n<sizeof(fixture)/sizeof(fixture[0]);n++) if(!strcmp(k,fixture[n][0]))return fixture[n][1];
 return (void*)0;
}
char *nvram_safe_get(const char*k){char *v=nvram_get(k);return v?v:"";}
int nvram_get_int(const char*k){char *v=nvram_get(k);return v?strtol(v,0,10):0;}
char *nvram_default_get(const char*k){return nvram_safe_get(k);}
int nvram_set(const char*k,const char*v){printf("MOCK_NVRAM_SET %s=%s\n",k,v);return 0;}
int nvram_set_int(const char*k,int v){printf("MOCK_NVRAM_SET_INT %s=%d\n",k,v);return 0;}
int nvram_unset(const char*k){printf("MOCK_NVRAM_UNSET %s\n",k);return 0;}
int nvram_commit(void){printf("MOCK_COMMIT\n");return 0;}
int file_lock(const char*k){printf("MOCK_LOCK %s\n",k);return 1;}
void file_unlock(int x){(void)x;}
int _eval(char**a,char*p,int t,int*pid){(void)p;(void)t;(void)pid;printf("MOCK_EXEC");for(int i=0;a&&a[i]&&i<16;i++)printf(" [%s]",a[i]);printf("\n");return 0;}
int doSystem(const char *f,...){printf("MOCK_SYSTEM %s\n",f);return 0;}
int system(const char *f){printf("MOCK_SYSTEM %s\n",f);return 0;}
int notify_rc(const char *s){printf("MOCK_NOTIFY %s\n",s);return 0;}
int notify_rc_and_wait_2min(const char *s){printf("MOCK_NOTIFY %s\n",s);return 0;}
void *fopen(const char*p,const char*m){printf("MOCK_FOPEN %s %s\n",p,m);return (void*)0;}
int open(const char*p,int f,...){printf("MOCK_OPEN %s\n",p);return -1;}
int open64(const char*p,int f,...){return open(p,f);}
int ioctl(int f,unsigned long r,...){printf("MOCK_IOCTL %lu\n",r);return -1;}
int f_write(const char*p,const void*b,int n,unsigned int flags,unsigned int mode){printf("MOCK_F_WRITE %s size=%d\n",p,n);return n;}
int setitimer(int which,const long *v,void*old){(void)which;(void)old;printf("MOCK_TIMER %ld %ld %ld %ld\n",v[0],v[1],v[2],v[3]);return 0;}
int usleep(unsigned int u){(void)u;return 0;}
int pause(void){printf("MOCK_DONE\n");extern int fflush(void*);fflush((void*)0);_exit(0);}
