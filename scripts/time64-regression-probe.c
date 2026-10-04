/* Direct Linux syscall ABI probe. No libc, vDSO, dynamic loader or time_t.
 * Disposable guest clock is moved to 2100 and restored at the final stage.
 * Waits have ready objects, zero/past timeouts or mismatched futex values.
 * Other mutations use private IPC, local sockets and an unlinked /tmp file.
 * QEMU only. Requires guest marker and exact explicitly selected kernel build.
 */
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned long usize;
#define PTR(p) ((long)(p))
#define FUTURE 4102444800LL /* 2100-01-01 UTC: deliberately exceeds INT32_MAX. */
#define CANARY 0xa1753e29d6b4c80fULL
struct ts64 { i64 sec, nsec; };
struct guard_ts { u64 pre; struct ts64 t; u64 post; };
struct its64 { struct ts64 interval, value; };
struct guard_its { u64 pre; struct its64 t; u64 post; };
_Static_assert(sizeof(struct ts64) == 16, "kernel timespec64 layout");
_Static_assert(sizeof(struct its64) == 32, "kernel itimerspec64 layout");

#ifdef __aarch64__
#define ABI "aarch64-native64"
#define NR_WRITE 64
#define NR_CLOSE 57
#define NR_EXIT 94
#define NR_UNAME 160
#define NR_GETPID 172
#define NR_OPENAT 56
#define NR_UNLINKAT 35
#define NR_STATX 291
#define NR_TIMERFD_CREATE 85
#define N_GETTIME 113
#define N_GETRES 114
#define N_SLEEP 115
#define N_TIMERGET 108
#define N_TIMERSET 110
#define N_FDGET 87
#define N_FDSET 86
#define N_UTIME 88
#define N_SELECT 72
#define N_POLL 73
#define N_IOGET 292
#define N_RECV 243
#define N_MQSEND 182
#define N_MQRECV 183
#define N_SEM 192
#define N_SIGWAIT 137
#define N_FUTEX 98
#define N_SCHED 127
static long call(long nr, long a, long b, long c, long d, long e, long f)
{
    register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
    register long x8 __asm__("x8")=nr;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory","cc");
    return x0;
}
#else
#ifdef __ARM_PCS_VFP
#define ABI "arm32-hardfloat-direct-time64"
#else
#define ABI "arm32-softfloat-direct-time64"
#endif
#define NR_WRITE 4
#define NR_CLOSE 6
#define NR_EXIT 248
#define NR_UNAME 122
#define NR_GETPID 20
#define NR_OPENAT 322
#define NR_UNLINKAT 328
#define NR_STATX 397
#define NR_TIMERFD_CREATE 350
/* Verified against Linux UAPI asm-generic/unistd.h: 415 is unused. */
#define N_GETTIME 403
#define N_GETRES 406
#define N_SLEEP 407
#define N_TIMERGET 408
#define N_TIMERSET 409
#define N_FDGET 410
#define N_FDSET 411
#define N_UTIME 412
#define N_SELECT 413
#define N_POLL 414
#define N_IOGET 416
#define N_RECV 417
#define N_MQSEND 418
#define N_MQRECV 419
#define N_SEM 420
#define N_SIGWAIT 421
#define N_FUTEX 422
#define N_SCHED 423
static long call(long nr, long a, long b, long c, long d, long e, long f)
{
    register long r0 __asm__("r0")=a, r1 __asm__("r1")=b, r2 __asm__("r2")=c;
    register long r3 __asm__("r3")=d, r4 __asm__("r4")=e, r5 __asm__("r5")=f;
    register long r7 __asm__("r7")=nr;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(r7) : "memory","cc");
    return r0;
}
#endif
#define C0(n) call(n,0,0,0,0,0,0)
#define C1(n,a) call(n,(long)(a),0,0,0,0,0)
#define C2(n,a,b) call(n,(long)(a),(long)(b),0,0,0,0)
#define C3(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define C4(n,a,b,c,d) call(n,(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define C5(n,a,b,c,d,e) call(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)

void *memset(void *dest, int value, usize n) { unsigned char *p=dest; for(usize i=0;i<n;i++)p[i]=(unsigned char)value;return dest; }
void *memcpy(void *dest,const void *src,usize n) { unsigned char *d=dest;const unsigned char *s=src;for(usize i=0;i<n;i++)d[i]=s[i];return dest; }
#ifndef EXPECTED_KERNEL_BUILD
#error Explicit EXPECTED_KERNEL_BUILD is required
#endif
#define STR_INNER(x) #x
#define STR(x) STR_INNER(x)
static int equal(const char *a,const char *b) { while(*a&&*a==*b){a++;b++;}return *a==*b; }
static char line[1024]; static usize used; static unsigned missing, failures, available, behavior_pass;
static void text(const char *s) { while(*s&&used<sizeof(line)-1)line[used++]=*s++; }
static void number(long value) { char b[32];unsigned long n;unsigned i=0;if(value<0){text("-");n=0-(unsigned long)value;}else n=value;do{b[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)line[used++]=b[--i]; }
static void hex64(u64 value) { const char *digits="0123456789abcdef";text("0x");for(int i=15;i>=0;i--)line[used++]=digits[(value>>(i*4))&15]; }
static void emit(void) { text("\n");usize off=0;while(off<used){long n=C3(NR_WRITE,1,line+off,used-off);if(n<=0)break;off+=(usize)n;}used=0; }
static void result(const char *name,long nr,long ret,int correct,int behavioral)
{
    text("TIME64_RESULT abi=");text(ABI);text(" api=");text(name);text(" nr=");number(nr);text(" ret=");number(ret);
    if(ret==-38){missing++;text(" availability=ENOSYS behavior=not_tested");}
    else {available++;text(" availability=present behavior=");if(!behavioral)text("inventory_only");else if(correct){behavior_pass++;text("pass");}else{failures++;text("FAIL");}}
    emit();
}
static void detail(const char *name,int okay) { text("TIME64_CHECK name=");text(name);text(" result=");text(okay?"pass":"FAIL");emit();if(!okay)failures++; }
static int intact(struct guard_ts *g) { return g->pre==CANARY&&g->post==CANARY; }
static int valid_ts(struct guard_ts *g) { return intact(g)&&g->t.sec>=0&&g->t.nsec>=0&&g->t.nsec<1000000000LL; }
static void init_ts(struct guard_ts *g) { g->pre=CANARY;g->post=CANARY;g->t.sec=-1;g->t.nsec=-1; }
static void init_its(struct guard_its *g) { memset(g,0,sizeof(*g));g->pre=CANARY;g->post=CANARY; }
static int valid_its(struct guard_its *g) { return g->pre==CANARY&&g->post==CANARY&&g->t.value.sec>=0&&g->t.value.nsec>=0&&g->t.value.nsec<1000000000LL&&g->t.interval.sec==0&&g->t.interval.nsec==0; }
static void clocks(void)
{
    struct guard_ts g; long ret;
#ifndef __aarch64__
    struct {u64 pre;int sec,nsec;u64 post;} old;
    old.pre=old.post=CANARY;old.sec=old.nsec=-1;
    ret=C2(263,0,&old.sec);
    detail("legacy_clock_gettime32_control",ret==0&&old.pre==CANARY&&old.post==CANARY&&old.sec>0&&old.nsec>=0&&old.nsec<1000000000);
    text("TIME64_LEGACY sec=");number(old.sec);text(" nsec=");number(old.nsec);emit();
#endif
    init_ts(&g);ret=C2(N_GETTIME,0,&g.t);
    result("clock_gettime",N_GETTIME,ret,ret==0&&valid_ts(&g)&&g.t.sec>0,1);
    if(ret==0){text("TIME64_VALUE clock_realtime_sec=");hex64((u64)g.t.sec);text(" nsec=");hex64((u64)g.t.nsec);emit();}
    init_ts(&g);ret=C2(N_GETRES,1,&g.t);
    result("clock_getres",N_GETRES,ret,ret==0&&valid_ts(&g),1);
    g.t.sec=0;g.t.nsec=0;
    ret=C4(N_SLEEP,1,1,&g.t,0); /* Absolute monotonic epoch: already in the past. */
    result("clock_nanosleep_past",N_SLEEP,ret,ret==0&&intact(&g),1);
    init_ts(&g);ret=C2(N_SCHED,0,&g.t);
    result("sched_rr_get_interval",N_SCHED,ret,ret==0&&valid_ts(&g),1);
}
static void no_waits(void)
{
    struct guard_ts zero={CANARY,{0,0},CANARY},future={CANARY,{FUTURE,123456789},CANARY};
    u64 empty_mask=0;u32 futex=0;long ret;
    ret=call(N_SELECT,0,0,0,0,PTR(&zero.t),0);
    result("pselect6_zero",N_SELECT,ret,ret==0&&intact(&zero),1);
    zero.t.sec=zero.t.nsec=0;
    ret=C5(N_POLL,0,0,&zero.t,0,8);
    result("ppoll_zero",N_POLL,ret,ret==0&&intact(&zero),1);
    ret=C4(N_SIGWAIT,&empty_mask,0,&zero.t,8);
    result("rt_sigtimedwait_zero",N_SIGWAIT,ret,ret==-11&&intact(&zero),1);
    ret=call(N_FUTEX,PTR(&futex),9|128|256,1,PTR(&future.t),0,0xffffffffUL);
    result("futex_future_value_mismatch",N_FUTEX,ret,ret==-11&&intact(&future)&&futex==0,1);
}
static void timerfd(void)
{
    struct guard_its set,get;
    struct guard_ts now;
    long fd=C2(NR_TIMERFD_CREATE,0,2048|524288),ret;
    if(fd<0){detail("timerfd_create_prerequisite",0);return;}
    init_its(&set);init_its(&get);set.t.value.sec=FUTURE;set.t.value.nsec=123456789;
    ret=C4(N_FDSET,fd,1,&set.t,0);
    int armed=ret==0;
    result("timerfd_settime_future2100",N_FDSET,ret,armed&&valid_its(&set),1);
    ret=C2(N_FDGET,fd,&get.t);
    result("timerfd_gettime",N_FDGET,ret,ret==0&&valid_its(&get),1);
    /* Close immediately; this cannot leave a timer installed on the machine. */
    detail("private_timerfd_closed",C1(NR_CLOSE,fd)==0);
    if(armed&&ret==0){
        init_ts(&now);long got=C2(N_GETTIME,0,&now.t);
        if(got==0&&valid_ts(&now)){
            i64 restored=get.t.value.sec+now.t.sec;
            detail("timerfd_future2100_roundtrip",restored>=FUTURE-2&&restored<=FUTURE+2);
            text("TIME64_VALUE timer_remaining_sec=");hex64((u64)get.t.value.sec);text(" reconstructed_absolute_sec=");hex64((u64)restored);emit();
        }else detail("timerfd_roundtrip_clock_available",0);
    }
}
static void filetime(void)
{
    char path[96];const char prefix[]="/tmp/qemu-time64-";usize n=0;
    for(usize i=0;i<sizeof(prefix)-1;i++)path[n++]=prefix[i];
    unsigned long pid=(unsigned long)C0(NR_GETPID);char digits[24];unsigned j=0;
    do{digits[j++]=(char)('0'+pid%10);pid/=10;}while(pid);
    while(j)path[n++]=digits[--j];path[n]=0;
    long fd=C4(NR_OPENAT,-100,path,2|64|128|524288,0600);
    if(fd<0){detail("temporary_file_exclusive_create",0);return;}
    long removed=C3(NR_UNLINKAT,-100,path,0);
    if(removed){C1(NR_CLOSE,fd);detail("temporary_file_immediate_unlink",0);return;}
    struct {u64 pre;struct ts64 t[2];u64 post;} values={CANARY,{{FUTURE,123456789},{FUTURE+1,987654321}},CANARY};
    long ret=C4(N_UTIME,fd,0,values.t,0);
    result("utimensat_future2100",N_UTIME,ret,ret==0&&values.pre==CANARY&&values.post==CANARY,1);
    if(ret==0){
        struct {u64 pre;unsigned char bytes[256];u64 post;} sx;
        sx.pre=sx.post=CANARY;memset(sx.bytes,0,sizeof(sx.bytes));
        long statret=C5(NR_STATX,fd,"",0x1000,0x60,sx.bytes);
        i64 atime=0,mtime=0;u32 mask=0,ansec=0,mnsec=0;
        memcpy(&mask,sx.bytes,4);memcpy(&atime,sx.bytes+64,8);memcpy(&ansec,sx.bytes+72,4);
        memcpy(&mtime,sx.bytes+112,8);memcpy(&mnsec,sx.bytes+120,4);
        detail("statx_future2100_exact_roundtrip",statret==0&&sx.pre==CANARY&&sx.post==CANARY&&
               (mask&0x60)==0x60&&atime==FUTURE&&mtime==FUTURE+1&&ansec==123456789&&mnsec==987654321);
        text("TIME64_VALUE file_atime_sec=");hex64((u64)atime);text(" file_mtime_sec=");hex64((u64)mtime);emit();
    }
    detail("unlinked_file_closed",C1(NR_CLOSE,fd)==0);
}
static void inventory(void)
{
    struct ts64 zero={0,0};struct its64 timer={{0,0},{0,0}};
    /* Invalid IDs only: these establish dispatch, never semantic correctness. */
    result("timer_gettime_invalid_id",N_TIMERGET,C2(N_TIMERGET,-1,&timer),0,0);
    result("timer_settime_invalid_id",N_TIMERSET,C4(N_TIMERSET,-1,0,&timer,0),0,0);
    detail("AIO_disabled_expected_ENOSYS", call(N_IOGET,0,0,0,0,PTR(&zero),0)==-38);
    result("recvmmsg_invalid_fd",N_RECV,C5(N_RECV,-1,0,1,0x40,&zero),0,0);
    result("mq_timedsend_invalid_fd",N_MQSEND,C5(N_MQSEND,-1,0,0,0,&zero),0,0);
    result("mq_timedreceive_invalid_fd",N_MQRECV,C5(N_MQRECV,-1,0,0,0,&zero),0,0);
    result("semtimedop_invalid_id",N_SEM,C4(N_SEM,-1,0,0,&zero),0,0);
    text("TIME64_SCOPE clock_settime_and_adjtime=guarded_guest_stage reserved_arm32_415=not_called");emit();
}
#ifdef __aarch64__
#define NR_MAP 222
#define NR_MPROTECT 226
#define NR_MUNMAP 215
#define NR_PIPE2 59
#define NR_READ 63
#define NR_SOCKETPAIR 199
#define NR_SENDMSG 211
#define NR_SIGMASK 135
#define NR_KILL 129
#define NR_TIMERCREATE 107
#define NR_TIMERDELETE 111
#define NR_MQOPEN 180
#define NR_MQUNLINK 181
#define NR_SEMGET 190
#define NR_SEMCTL 191
#define N_SETTIME 112
#define N_ADJTIME 266
#else
#define NR_MAP 192
#define NR_MPROTECT 125
#define NR_MUNMAP 91
#define NR_PIPE2 359
#define NR_READ 3
#define NR_SOCKETPAIR 288
#define NR_SENDMSG 296
#define NR_SIGMASK 175
#define NR_KILL 37
#define NR_TIMERCREATE 257
#define NR_TIMERDELETE 261
#define NR_MQOPEN 274
#define NR_MQUNLINK 275
#define NR_SEMGET 299
#define NR_SEMCTL 300
#define N_SETTIME 404
#define N_ADJTIME 405
#endif
struct pollfd { int fd; short events,revents; };
static void ready_and_masks(void)
{
    int fds[2]={-1,-1};
    if(C2(NR_PIPE2,fds,2048|524288)){detail("pipe2_prerequisite",0);return;}
    detail("pipe_write",C3(NR_WRITE,fds[1],"x",1)==1);
    struct {void *mask;usize size;} args;
    u64 mask=(1ULL<<9)|(1ULL<<62), before=0,after=0;
    args.mask=&mask;args.size=8;
    u64 original_mask=0,high_mask=1ULL<<62;
    long blocked=C4(NR_SIGMASK,0,&high_mask,&original_mask,8);
    long sent=blocked==0?C2(NR_KILL,C0(NR_GETPID),63):-1;
    detail("pending_high_RT63_prepared",blocked==0&&sent==0);
    detail("get_signal_mask_before",C4(NR_SIGMASK,2,0,&before,8)==0);
    usize bits[8]={0};bits[(unsigned)fds[0]/(sizeof(usize)*8)]|=(usize)1<<((unsigned)fds[0]%(sizeof(usize)*8));
    struct guard_ts t={CANARY,{FUTURE,123456789},CANARY};
    long ret=call(N_SELECT,fds[0]+1,PTR(bits),0,0,PTR(&t.t),PTR(&args));
    detail("pselect_ready_fd_future64_with_sigmask",ret==1&&intact(&t)&&bits[(unsigned)fds[0]/(sizeof(usize)*8)]!=0);
    detail("get_signal_mask_after",C4(NR_SIGMASK,2,0,&after,8)==0&&before==after);
    long mapping=call(NR_MAP,0,8192,3,0x22,-1,0);
    if(mapping<0&&mapping>=-4095){detail("guard_mmap",0);}else{
        unsigned char *page=(void *)mapping;
        if(C3(NR_MPROTECT,page+4096,4096,0)){detail("guard_mprotect",0);}else{
            void *boundary_args=page+4096-sizeof(args);memcpy(boundary_args,&args,sizeof(args));
            t.t.sec=t.t.nsec=0;
            detail("pselect_sigarg_exact_size_guardpage",call(N_SELECT,0,0,0,0,PTR(&t.t),PTR(boundary_args))==0);
            usize *boundary_fdset=(void *)(page+4096-sizeof(usize));*boundary_fdset=(usize)1<<(unsigned)fds[0];
            t.t.sec=FUTURE;t.t.nsec=0;
            detail("pselect_fdset_word_size_guardpage",call(N_SELECT,fds[0]+1,PTR(boundary_fdset),0,0,PTR(&t.t),PTR(&args))==1&&*boundary_fdset==((usize)1<<(unsigned)fds[0]));
        }
        detail("guard_munmap",C2(NR_MUNMAP,page,8192)==0);
    }
    args.size=4;t.t.sec=t.t.nsec=0;
    detail("pselect_wrong_sigset_size_EINVAL",call(N_SELECT,0,0,0,0,PTR(&t.t),PTR(&args))==-22);
    args.size=8;args.mask=(void *)1;
    detail("pselect_bad_sigset_pointer_EFAULT",call(N_SELECT,0,0,0,0,PTR(&t.t),PTR(&args))==-14);
    struct pollfd f={fds[0],1,0};t.t.sec=FUTURE;t.t.nsec=123456789;
    detail("ppoll_ready_future64_with_sigmask",C5(N_POLL,&f,1,&t.t,&mask,8)==1&&f.revents==1&&intact(&t));
    detail("ppoll_wrong_sigset_size_EINVAL",C5(N_POLL,&f,1,&t.t,&mask,4)==-22);
    detail("ppoll_bad_sigset_pointer_EFAULT",C5(N_POLL,&f,1,&t.t,1,8)==-14);
    struct ts64 no_wait={0,0};
    long consumed=C4(N_SIGWAIT,&high_mask,0,&no_wait,8);
    detail("pselect_ppoll_preserved_pending_high_mask",consumed==63);
    if(consumed==63)detail("high_signal_mask_restored",C4(NR_SIGMASK,2,&original_mask,0,8)==0);
    detail("pipe_close",C1(NR_CLOSE,fds[0])==0&&C1(NR_CLOSE,fds[1])==0);
}
static void siginfo_case(void)
{
    u64 mask=1ULL<<9,old=0;
    if(C4(NR_SIGMASK,0,&mask,&old,8)){detail("block_signal",0);return;}
    long pid=C0(NR_GETPID);long sent=C2(NR_KILL,pid,10);
    struct {u64 pre;unsigned char data[128];u64 post;} si;
    si.pre=si.post=CANARY;memset(si.data,0,sizeof(si.data));
    struct ts64 t={FUTURE,123456789};
    long got=sent==0?C4(N_SIGWAIT,&mask,si.data,&t,8):-1;
    int signo=0,code=0,sender=0;memcpy(&signo,si.data,4);memcpy(&code,si.data+8,4);
#ifdef __aarch64__
    memcpy(&sender,si.data+16,4);
#else
    memcpy(&sender,si.data+12,4);
#endif
    detail("sigtimedwait_pending_future_siginfo_layout",got==10&&signo==10&&code==0&&sender==pid&&si.pre==CANARY&&si.post==CANARY);
    /* Restore only after consumption; a failed implementation exits with the
     * signal still blocked, avoiding delivery of an unexpected default signal. */
    if(got==10)detail("signal_mask_restored",C4(NR_SIGMASK,2,&old,0,8)==0);
}
struct iovec {void *base;usize length;};
struct msghdr {void *name;u32 namelen;struct iovec *iov;usize iovlen;void *control;usize controllen;u32 flags;};
struct mmsghdr {struct msghdr h;u32 length;};
struct cmsghdr {usize length;int level,type;};
#define ALIGN_WORD(n) (((n)+sizeof(usize)-1)&~(sizeof(usize)-1))
static void recvmmsg_case(void)
{
    int fds[2]={-1,-1};
    if(C4(NR_SOCKETPAIR,1,2|2048|524288,0,fds)){detail("socketpair_prerequisite",0);return;}
    char first='A',tail[2]={'B','C'};
    struct iovec sendiov[2]={{&first,1},{tail,2}};
    union {usize align;unsigned char bytes[64];} control;
    memset(&control,0,sizeof(control));
    struct cmsghdr *cm=(void *)control.bytes;
    cm->length=ALIGN_WORD(sizeof(*cm))+sizeof(int);cm->level=1;cm->type=1;
    memcpy(control.bytes+ALIGN_WORD(sizeof(*cm)),&fds[0],sizeof(int));
    struct msghdr send={0};send.iov=sendiov;send.iovlen=2;send.control=control.bytes;send.controllen=ALIGN_WORD(cm->length);
    detail("sendmsg_rights_gather_iov",C3(NR_SENDMSG,fds[0],&send,0)==3);
    detail("send_second_datagram",C3(NR_WRITE,fds[0],"WXYZ",4)==4);
    struct {u64 pre;char bytes[8];u64 post;} payload[2];
    struct {u64 pre;unsigned char bytes[64];u64 post;} received_control;
    struct {u64 pre;struct mmsghdr messages[2];u64 post;} rx;
    memset(&rx,0,sizeof(rx));memset(payload,0,sizeof(payload));memset(&received_control,0,sizeof(received_control));
    rx.pre=rx.post=received_control.pre=received_control.post=CANARY;
    payload[0].pre=payload[0].post=payload[1].pre=payload[1].post=CANARY;
    struct iovec rxiov[3]={{payload[0].bytes,1},{payload[0].bytes+1,2},{payload[1].bytes,8}};
    rx.messages[0].h.iov=rxiov;rx.messages[0].h.iovlen=2;
    rx.messages[0].h.control=received_control.bytes;rx.messages[0].h.controllen=sizeof(received_control.bytes);
    rx.messages[1].h.iov=rxiov+2;rx.messages[1].h.iovlen=1;
    struct guard_ts t={CANARY,{FUTURE,123456789},CANARY};
    long ret=C5(N_RECV,fds[1],rx.messages,2,0x40,&t.t);
    int passed=ret==2&&rx.pre==CANARY&&rx.post==CANARY&&intact(&t)&&
      rx.messages[0].length==3&&rx.messages[1].length==4&&
      payload[0].bytes[0]=='A'&&payload[0].bytes[1]=='B'&&payload[0].bytes[2]=='C'&&
      payload[1].bytes[0]=='W'&&payload[1].bytes[3]=='Z'&&
      payload[0].pre==CANARY&&payload[0].post==CANARY&&payload[1].pre==CANARY&&payload[1].post==CANARY;
    detail("recvmmsg_two_messages_nested_iov_layout",passed);
    struct cmsghdr recvcm;memcpy(&recvcm,received_control.bytes,sizeof(recvcm));int received_fd=-1;
    if(ret>=1&&rx.messages[0].h.controllen>=ALIGN_WORD(sizeof(recvcm))+sizeof(int))memcpy(&received_fd,received_control.bytes+ALIGN_WORD(sizeof(recvcm)),sizeof(int));
    detail("recvmmsg_SCM_RIGHTS_control_layout",passed&&received_control.pre==CANARY&&received_control.post==CANARY&&
        recvcm.length==ALIGN_WORD(sizeof(recvcm))+sizeof(int)&&recvcm.level==1&&recvcm.type==1&&
        !(rx.messages[0].h.flags&8)&&received_fd>=0);
    if(received_fd>=0)detail("received_rights_fd_close",C1(NR_CLOSE,received_fd)==0);
    detail("socketpair_close",C1(NR_CLOSE,fds[0])==0&&C1(NR_CLOSE,fds[1])==0);
}
static void posix_timer_case(void)
{
    union {usize align;unsigned char bytes[64];} ev;memset(&ev,0,sizeof(ev));
    int none=1;memcpy(ev.bytes+sizeof(usize)+4,&none,4);
    int id=-1;long ret=C3(NR_TIMERCREATE,1,ev.bytes,&id);
    if(ret){detail("POSIX_timer_create_SIGEV_NONE",0);return;}
    struct guard_its set,get;init_its(&set);init_its(&get);set.t.value.sec=FUTURE;
    ret=C4(N_TIMERSET,id,0,&set.t,0);
    detail("POSIX_timer_settime_future2100",ret==0&&valid_its(&set));
    ret=C2(N_TIMERGET,id,&get.t);
    detail("POSIX_timer_gettime_future_roundtrip",ret==0&&valid_its(&get)&&get.t.value.sec>=FUTURE-2&&get.t.value.sec<=FUTURE);
    detail("POSIX_timer_delete",C1(NR_TIMERDELETE,id)==0);
}
static void ipc_case(void)
{
    /* Each probe is a separate process and guest; unlink queues immediately. */
    const char *name="qemu-time64-private";
    long attr[8]={0,2,16,0,0,0,0,0};
    long mq=C4(NR_MQOPEN,name,2|64|128|524288,0600,attr);
    if(mq<0){detail("mq_open_private",0);}else{
        detail("mq_unlink_immediate",C1(NR_MQUNLINK,name)==0);
        struct ts64 future={FUTURE,123456789};char data[16]={0};u32 priority=0;
        detail("mq_timedsend_future",C5(N_MQSEND,mq,"hello",5,7,&future)==0);
        detail("mq_timedreceive_future",C5(N_MQRECV,mq,data,sizeof(data),&priority,&future)==5&&priority==7&&data[0]=='h'&&data[4]=='o');
        detail("mq_close",C1(NR_CLOSE,mq)==0);
    }
    long sem=C3(NR_SEMGET,0,1,01000|0600);
    if(sem<0){detail("semget_private",0);return;}
    struct {unsigned short number;short op,flags;} op={0,0,0};struct ts64 future={FUTURE,0};
    detail("semtimedop_zero_value_future",C4(N_SEM,sem,&op,1,&future)==0);
    detail("sem_remove",C4(NR_SEMCTL,sem,0,0,0)==0);
}
static void malformed_and_legacy(void)
{
    struct guard_ts t={CANARY,{0,1000000000},CANARY};
    detail("clock_nanosleep_bad_nanoseconds_EINVAL",C4(N_SLEEP,1,0,&t.t,0)==-22&&intact(&t));
    detail("clock_gettime_bad_pointer_EFAULT",C2(N_GETTIME,0,1)==-14);
    detail("clock_getres_bad_clock_EINVAL",C2(N_GETRES,16,&t.t)==-22);
    t.t.sec=FUTURE;t.t.nsec=0;
    detail("clock_settime_invalid_clock_no_mutation",C2(N_SETTIME,16,&t.t)==-22);
    detail("clock_adjtime_invalid_clock_no_mutation",C2(N_ADJTIME,16,0)==-22);
    t.t.sec=0;t.t.nsec=(i64)0xdeadbeef00000000ULL;
    long ret=C4(N_SLEEP,1,1,&t.t,0);
#ifdef __aarch64__
    detail("native64_rejects_dirty_nsec_high_bits",ret==-22&&intact(&t));
#else
    detail("compat64_ignores_dirty_nsec_high_bits",ret==0&&intact(&t));
    struct {u64 pre;int sec,nsec;u64 post;} old={CANARY,0,0,CANARY};
    detail("legacy_clock_getres_8byte_control",C2(264,1,&old.sec)==0&&old.pre==CANARY&&old.post==CANARY&&old.nsec>=0&&old.nsec<1000000000);
    struct {u64 pre;int interval_sec,interval_nsec,value_sec,value_nsec;u64 post;} set={CANARY,0,0,60,123456789,CANARY},get={CANARY,0,0,0,0,CANARY};
    long fd=C2(NR_TIMERFD_CREATE,1,2048|524288);
    if(fd<0){detail("legacy_timerfd_create",0);return;}
    detail("legacy_timerfd_settime_16byte_control",C4(353,fd,0,&set.interval_sec,0)==0&&set.pre==CANARY&&set.post==CANARY);
    detail("legacy_timerfd_gettime_16byte_control",C2(354,fd,&get.interval_sec)==0&&get.pre==CANARY&&get.post==CANARY&&get.value_sec>=58&&get.value_sec<=60);
    detail("legacy_timerfd_close",C1(NR_CLOSE,fd)==0);
#endif
}
static void guest_clock2100(void)
{
    struct guard_ts original,got;init_ts(&original);init_ts(&got);
    if(C2(N_GETTIME,0,&original.t)||!valid_ts(&original)){detail("save_VM_clock",0);return;}
    struct ts64 future={FUTURE,123456789};long set=C2(N_SETTIME,0,&future);
    detail("VM_only_clock_settime_2100",set==0);
    if(set)return;
    long ret=C2(N_GETTIME,0,&got.t);
    detail("VM_clock_gettime_2100_roundtrip",ret==0&&valid_ts(&got)&&got.t.sec>=FUTURE&&got.t.sec<=FUTURE+2);
    struct {u64 pre;unsigned char data[208];u64 post;} tx;
    memset(&tx,0,sizeof(tx));tx.pre=tx.post=CANARY;
    ret=C2(N_ADJTIME,0,tx.data);i64 sec=0,fraction=0;int status=0;
    memcpy(&sec,tx.data+72,8);memcpy(&fraction,tx.data+80,8);memcpy(&status,tx.data+40,4);
    i64 fraction_limit=(status&0x2000)?1000000000LL:1000000LL;
    detail("VM_clock_adjtime_modes0_208byte_2100",ret>=0&&ret<=5&&tx.pre==CANARY&&tx.post==CANARY&&sec>=FUTURE&&sec<=FUTURE+2&&fraction>=0&&fraction<fraction_limit);
    detail("VM_clock_restored",C2(N_SETTIME,0,&original.t)==0);
}
__attribute__((noreturn)) void _start(void)
{
    char uts[6][65];memset(uts,0,sizeof(uts));long ret=C1(NR_UNAME,uts);
    const char expected[]="#" STR(EXPECTED_KERNEL_BUILD) " ";int match=1;
    for(usize i=0;i<sizeof(expected)-1;i++)if(uts[3][i]!=expected[i])match=0;
    long marker=C4(NR_OPENAT,-100,"/QEMU_LAB_GUEST",0,0);
    if(marker>=0)C1(NR_CLOSE,marker);
    if(ret||!equal(uts[2],"4.19.294")||!match||marker<0){
        text("TIME64_REFUSED requires_QEMU_guest_and_kernel_build=");text(STR(EXPECTED_KERNEL_BUILD));emit();
        C1(NR_EXIT,90);for(;;){}
    }
    text("TIME64_BEGIN abi=");text(ABI);text(" build=");text(STR(EXPECTED_KERNEL_BUILD));emit();
    clocks();no_waits();timerfd();filetime();inventory();ready_and_masks();
    siginfo_case();recvmmsg_case();posix_timer_case();ipc_case();malformed_and_legacy();guest_clock2100();
    detail("all_enabled_time64_entries_present",missing==0);
    text("TIME64_SUMMARY abi=");text(ABI);text(" available=");number(available);text(" ENOSYS=");number(missing);
    text(" behavior_pass=");number(behavior_pass);text(" failures=");number(failures);text(" clock_writes=guest_only_restored");emit();
    if(!failures){text("LAB_TIME64_ABI_PASS abi=");text(ABI);emit();}
    C1(NR_EXIT,failures?1:0);for(;;){}
}
