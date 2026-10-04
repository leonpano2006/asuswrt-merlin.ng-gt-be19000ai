/* Direct Linux syscall ABI probe. No libc, vDSO, dynamic loader or time_t.
 * No clock setting or adjustment. Every wait is zero/past or value-mismatched.
 * Only a private timerfd and an immediately unlinked /tmp file are modified.
 * Caller: verify GT-BE19000AI and use a bounded outer timeout.
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
    char path[96];const char prefix[]="/tmp/kernel8-time64-";usize n=0;
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
    result("io_pgetevents_invalid_context",N_IOGET,call(N_IOGET,0,0,0,0,PTR(&zero),0),0,0);
    result("recvmmsg_invalid_fd",N_RECV,C5(N_RECV,-1,0,1,0x40,&zero),0,0);
    result("mq_timedsend_invalid_fd",N_MQSEND,C5(N_MQSEND,-1,0,0,0,&zero),0,0);
    result("mq_timedreceive_invalid_fd",N_MQRECV,C5(N_MQRECV,-1,0,0,0,&zero),0,0);
    result("semtimedop_invalid_id",N_SEM,C4(N_SEM,-1,0,0,&zero),0,0);
    text("TIME64_SKIPPED clock_settime=not_called clock_adjtime=not_called reserved_arm32_415=not_called");emit();
}
__attribute__((noreturn)) void _start(void)
{
    char uts[6][65];memset(uts,0,sizeof(uts));
    long ret=C1(NR_UNAME,uts);
    if(ret||!equal(uts[2],"4.19.294")||uts[3][0]!='#'||uts[3][1]!='8'||uts[3][2]!=' '){
        text("TIME64_REFUSED expected_kernel=4.19.294_#8 actual_release=");text(uts[2]);text(" version=");text(uts[3]);emit();
        C1(NR_EXIT,90);for(;;){}
    }
    text("TIME64_BEGIN abi=");text(ABI);text(" libc=none vdso=none timeval_time_t=not_used release=");text(uts[2]);text(" machine=");text(uts[4]);emit();
    clocks();no_waits();timerfd();filetime();inventory();
    text("TIME64_SUMMARY abi=");text(ABI);text(" available=");number(available);text(" ENOSYS=");number(missing);
    text(" behavior_pass=");number(behavior_pass);text(" failures=");number(failures);text(" global_clock_writes=0");emit();
    C1(NR_EXIT,failures?1:0);for(;;){}
}
