/* SPDX-License-Identifier: GPL-2.0-only
 * Offline QEMU regression of raw ARM64 / ARM EABI pidfd semantics.
 * Freestanding: no host glibc or wrapper can emulate a missing syscall.
 * Only private child processes, pipes and descriptors are modified.
 */
typedef unsigned long usize;
typedef long long s64;
typedef unsigned long long u64;
#ifdef __aarch64__
#define ABI "arm64"
#define NR_WRITE 64
#define NR_READ 63
#define NR_CLOSE 57
#define NR_EXIT 94
#define NR_GETPID 172
#define NR_OPENAT 56
#define NR_FCNTL 25
#define NR_CLONE 220
#define NR_WAITID 95
#define NR_PIPE2 59
#define NR_PPOLL 73
#define NR_SETUID 146
#define NR_PRLIMIT 261
#define SIGINFO_PAD int padding;
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
 __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");return x0;
}
#else
#ifdef __ARM_PCS_VFP
#define ABI "armhf"
#else
#define ABI "armel"
#endif
#define NR_WRITE 4
#define NR_READ 3
#define NR_CLOSE 6
#define NR_EXIT 248
#define NR_GETPID 20
#define NR_OPENAT 322
#define NR_FCNTL 221
#define NR_CLONE 120
#define NR_WAITID 280
#define NR_PIPE2 359
#define NR_PPOLL 414 /* Exercise the earlier ARM time64 backport as well. */
#define NR_SETUID 213
#define NR_PRLIMIT 369
#define SIGINFO_PAD
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c;
 register long r3 __asm__("r3")=d,r4 __asm__("r4")=e,r5 __asm__("r5")=f,r7 __asm__("r7")=n;
 __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(r7) : "memory","cc");return r0;
}
#endif
#define C0(n) call(n,0,0,0,0,0,0)
#define C1(n,a) call(n,(long)(a),0,0,0,0,0)
#define C2(n,a,b) call(n,(long)(a),(long)(b),0,0,0,0)
#define C3(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define C4(n,a,b,c,d) call(n,(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define C5(n,a,b,c,d,e) call(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)
#define NR_PIDFD_OPEN 434
#define NR_PIDFD_SIGNAL 424
#define PIDFD 0x1000
#define SIGCHLD 17
#define INTMAX 2147483647
#define WEXITED 4
#define WSTOPPED 2
#define WCONTINUED 8
#define WNOHANG 1
#define WNOWAIT 0x01000000
struct siginfo { int signo, error, code; SIGINFO_PAD int pid; unsigned uid; int status; unsigned char tail[104]; };
struct ts { s64 sec,nsec; };
struct pollfd { int fd; short events,revents; };
struct limit { u64 current,maximum; };
static unsigned failures,checks;
static char line[512];static usize used;
void *memset(void *p,int v,usize n) { unsigned char *b=p;for(usize i=0;i<n;i++)b[i]=(unsigned char)v;return p; }
void *memcpy(void *d,const void *s,usize n) {unsigned char *a=d;const unsigned char *b=s;for(usize i=0;i<n;i++)a[i]=b[i];return d;}
static void text(const char *s) {while(*s&&used<sizeof(line)-1)line[used++]=*s++;}
static void number(long n) {char b[32];unsigned i=0;unsigned long x;if(n<0){text("-");x=0-(unsigned long)n;}else x=n;do{b[i++]=(char)('0'+x%10);x/=10;}while(x);while(i)line[used++]=b[--i];}
static void emit(void) {text("\n");C3(NR_WRITE,1,line,used);used=0;}
static __attribute__((noreturn)) void quit(int code) {C1(NR_EXIT,code);for(;;);}
static void check(const char *name,long actual,long expected) {checks++;text("PIDFD_CHECK abi=");text(ABI);text(" name=");text(name);text(" actual=");number(actual);text(" expected=");number(expected);text(" result=");text(actual==expected?"pass":"FAIL");emit();if(actual!=expected)failures++;}
static void need(const char *name,long actual,long expected) {check(name,actual,expected);if(actual!=expected)quit(1);}
static int validfd(const char *name,long fd) {need(name,fd>=0,1);return (int)fd;}
static long waitfd(int fd,struct siginfo *si,int opts) {memset(si,0,sizeof(*si));return C5(NR_WAITID,3,fd,si,opts,0);}
static long signal_fd(int fd,int sig,void *info,unsigned flags) {return C4(NR_PIDFD_SIGNAL,fd,sig,info,flags);}
static long pollfd(int fd,int ms) {struct pollfd p={fd,1,0};struct ts t={ms/1000,(ms%1000)*1000000};long r=C5(NR_PPOLL,&p,1,&t,0,0);if(r==1&&!(p.revents&1))return -1000;return r;}
static int countfds(void) {int n=0;for(int fd=0;fd<256;fd++)if(C3(NR_FCNTL,fd,1,0)>=0)n++;return n;}
static long info_pid(int fd) {char p[64]="/proc/self/fdinfo/",b[512];unsigned n=18;char digits[16];unsigned k=0;unsigned x=fd;do{digits[k++]=(char)('0'+x%10);x/=10;}while(x);while(k)p[n++]=digits[--k];p[n]=0;long f=C4(NR_OPENAT,-100,p,0,0);if(f<0)return f;long r=C3(NR_READ,f,b,sizeof(b)-1);C1(NR_CLOSE,f);if(r<0)return r;b[r]=0;for(long i=0;i+5<r;i++)if(b[i]=='P'&&b[i+1]=='i'&&b[i+2]=='d'&&b[i+3]==':'){i+=4;while(b[i]=='\t'||b[i]==' ')i++;int neg=b[i]=='-';if(neg)i++;long v=0;while(b[i]>='0'&&b[i]<='9')v=v*10+b[i++]-'0';return neg?-v:v;}return -1001;}
static void errors_and_self(void) {
 struct siginfo si;long me=C0(NR_GETPID);int before=countfds();
 check("open_pid_zero",C2(NR_PIDFD_OPEN,0,0),-22);
 check("open_missing_pid",C2(NR_PIDFD_OPEN,INTMAX,0),-3);
 check("open_invalid_flags",C2(NR_PIDFD_OPEN,me,~0u),-22);
 int fd=validfd("open_self",C2(NR_PIDFD_OPEN,me,0));
 check("cloexec",C3(NR_FCNTL,fd,1,0)&1,1);
 check("self_fdinfo",info_pid(fd),me);
 check("self_not_child",waitfd(fd,&si,WEXITED|WNOHANG),-10);
 check("self_not_exited",pollfd(fd,0),0);
 check("signal_zero_self",signal_fd(fd,0,0,0),0);
 check("signal_bad_flags",signal_fd(fd,0,0,1),-22);
 check("signal_bad_info",signal_fd(fd,0,(void *)1,0),-14);
 int nullfd=validfd("null_fd",C4(NR_OPENAT,-100,"/dev/null",0,0));
 check("wait_non_pidfd",waitfd(nullfd,&si,WEXITED|WNOHANG),-9);
 check("signal_non_pidfd",signal_fd(nullfd,0,0,0),-9);
 C1(NR_CLOSE,nullfd);C1(NR_CLOSE,fd);
 check("signal_closed",signal_fd(fd,0,0,0),-9);
 check("self_fd_count",countfds(),before);
}
static void clone_lifecycle(void) {
 int pipe[2],fd=-1;struct siginfo si;long child;char ch=0;
 int before=countfds();need("pipe",C2(NR_PIPE2,pipe,0),0);
 int expected=validfd("fd_slot",C4(NR_OPENAT,-100,"/dev/null",0,0));C1(NR_CLOSE,expected);
 child=C5(NR_CLONE,PIDFD|SIGCHLD,0,&fd,0,0);
 if(child==0){
  C1(NR_CLOSE,pipe[0]);ch=(C3(NR_FCNTL,expected,1,0)==-9)?'Y':'N';
  C3(NR_WRITE,pipe[1],&ch,1);
  /* No normal return: parent stops, continues and terminates this child. */
  for(;;){struct ts t={1,0};C5(NR_PPOLL,0,0,&t,0,0);}
 }
 need("clone_pid",child>0,1);validfd("clone_pidfd",fd);C1(NR_CLOSE,pipe[1]);
 need("child_ready",C3(NR_READ,pipe[0],&ch,1),1);C1(NR_CLOSE,pipe[0]);
 check("pidfd_not_inherited",ch,'Y');
 check("clone_cloexec",C3(NR_FCNTL,fd,1,0)&1,1);
 check("clone_fdinfo",info_pid(fd),child);
 check("poll_alive",pollfd(fd,0),0);
 check("nohang_alive",waitfd(fd,&si,WEXITED|WNOHANG),0);
 check("nohang_zero_pid",si.pid,0);
 memset(&si,0,sizeof(si));si.signo=10;si.code=0;
 check("signal_reject_spoof",signal_fd(fd,10,&si,0),-1);
 check("signal_reject_mismatch",signal_fd(fd,12,&si,0),-22);
 need("stop_child",signal_fd(fd,19,0,0),0);
 need("wait_stopped",waitfd(fd,&si,WSTOPPED),0);check("stopped_pid",si.pid,child);check("stopped_code",si.code,5);
 check("poll_stopped_not_exit",pollfd(fd,0),0);
 need("continue_child",signal_fd(fd,18,0,0),0);
 need("wait_continued",waitfd(fd,&si,WCONTINUED),0);check("continued_code",si.code,6);
 need("terminate_child",signal_fd(fd,15,0,0),0);
 need("poll_exit_notification",pollfd(fd,2000),1);
 need("wait_nowait",waitfd(fd,&si,WEXITED|WNOWAIT),0);check("exit_pid",si.pid,child);check("exit_signal",si.status,15);check("exit_code",si.code,2);
 int dup=validfd("duplicate_pidfd",C3(NR_FCNTL,fd,0,0));C1(NR_CLOSE,fd);
 need("wait_nowait_duplicate",waitfd(dup,&si,WEXITED|WNOWAIT),0);check("duplicate_exit_pid",si.pid,child);
 need("reap_pidfd",waitfd(dup,&si,WEXITED),0);
 check("second_reap_echild",waitfd(dup,&si,WEXITED|WNOHANG),-10);
 check("signal_reaped_esrch",signal_fd(dup,0,0,0),-3);
 check("fdinfo_reaped",info_pid(dup),-1);
 check("poll_after_reap",pollfd(dup,0),1);C1(NR_CLOSE,dup);
 check("lifecycle_fd_count",countfds(),before);
}
static void clone_failures(void) {
 int before=countfds(),fd=-1;long r;
 for(int i=0;i<32;i++){
  r=C5(NR_CLONE,PIDFD|SIGCHLD,0,(void *)1,0,0);if(r==0)quit(111);
  if(r!=-14){check("bad_pointer_eFAULT",r,-14);break;}
 }
 check("bad_pointer_fd_cleanup",countfds(),before);
 r=C5(NR_CLONE,PIDFD|SIGCHLD|0x00100000,0,&fd,0,0);if(r==0)quit(112);check("parent_settid_conflict",r,-22);
 r=C5(NR_CLONE,PIDFD|SIGCHLD|0x00400000,0,&fd,0,0);if(r==0)quit(113);check("detached_conflict",r,-22);
 r=C5(NR_CLONE,PIDFD|SIGCHLD|0x00010900,0,&fd,0,0);if(r==0)quit(114);check("thread_conflict",r,-22);
 struct limit saved,small={0,0};need("get_fd_limit",C4(NR_PRLIMIT,0,7,0,&saved),0);small.maximum=saved.maximum;
 need("reduce_private_fd_limit",C4(NR_PRLIMIT,0,7,&small,0),0);
 r=C5(NR_CLONE,PIDFD|SIGCHLD,0,&fd,0,0);if(r==0)quit(115);
 need("restore_private_fd_limit",C4(NR_PRLIMIT,0,7,&saved,0),0);check("clone_emfile",r,-24);
 check("failure_fd_count",countfds(),before);
}
static void permission_test(void) {
 int fd=validfd("permission_parent_pidfd",C2(NR_PIDFD_OPEN,C0(NR_GETPID),0));
 long c=C5(NR_CLONE,SIGCHLD,0,0,0,0);
 if(c==0){if(C1(NR_SETUID,65534)!=0)quit(120);quit(signal_fd(fd,0,0,0)==-1?0:121);}
 need("permission_fork",c>0,1);int childfd=validfd("permission_child_pidfd",C2(NR_PIDFD_OPEN,c,0));struct siginfo si;
 need("permission_wait",waitfd(childfd,&si,WEXITED),0);check("permission_enforced",si.status,0);C1(NR_CLOSE,childfd);C1(NR_CLOSE,fd);
}
static void queued_signal(void) {
 int fd=-1;long c=C5(NR_CLONE,PIDFD|SIGCHLD,0,&fd,0,0);if(c==0)for(;;){struct ts t={1,0};C5(NR_PPOLL,0,0,&t,0,0);}
 need("queued_clone",c>0,1);struct siginfo si;memset(&si,0,sizeof(si));si.signo=10;si.code=-1;si.pid=(int)C0(NR_GETPID);
 need("queued_user_siginfo",signal_fd(fd,10,&si,0),0);need("queued_reap",waitfd(fd,&si,WEXITED),0);check("queued_delivered",si.status,10);C1(NR_CLOSE,fd);
}
void _start(void) {
 long marker=C4(NR_OPENAT,-100,"/QEMU_LAB_GUEST",0,0);if(marker<0)quit(125);C1(NR_CLOSE,marker);
 long gate=C5(NR_WAITID,3,INTMAX,0,WEXITED|WNOHANG,0);
 text("PIDFD_CAPABILITY abi=");text(ABI);text(" errno=");number(gate);emit();if(gate==-22||gate==-38){text("PIDFD_UNSUPPORTED abi=");text(ABI);emit();quit(77);}need("invalid_fd_gate",gate,-9);
 errors_and_self();clone_lifecycle();clone_failures();permission_test();queued_signal();
 text("PIDFD_SUMMARY abi=");text(ABI);text(" checks=");number(checks);text(" failures=");number(failures);emit();quit(failures?1:0);
}
