/* Explicit-loader time64 probe. The normal mode changes no global clock.
 * Optional --qemu-regression requires the guest marker and selected kernel build, adds bounded
 * interrupt tests, and moves only the disposable VM clock to 2100 then restores
 * it. No host/router clock changes or external networking. */
#define _GNU_SOURCE 1
#define _TIME_BITS 64
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#ifndef EXPECTED_KERNEL_BUILD
#define EXPECTED_KERNEL_BUILD 9
#endif

_Static_assert(sizeof(time_t) == 8, "probe must use 64-bit time_t");

static volatile sig_atomic_t signals_seen;
static void interrupted(int number) { (void)number; signals_seen++; }
static int local_alarm(void)
{
    struct itimerval it = {0};
    it.it_value.tv_usec = 20000;
    return setitimer(ITIMER_REAL, &it, NULL);
}
static void cancel_alarm(void)
{
    struct itimerval it = {0};
    (void)setitimer(ITIMER_REAL, &it, NULL);
}
static int interrupted_tests(void)
{
    struct utsname u;
    char expected[32];
    snprintf(expected, sizeof(expected), "#%d ", EXPECTED_KERNEL_BUILD);
    if (access("/QEMU_LAB_GUEST", R_OK) || uname(&u) ||
        strncmp(u.version, expected, strlen(expected)) != 0 || strcmp(u.release,"4.19.294") != 0) {
        fprintf(stderr,"FAIL interrupt tests require QEMU kernel%d\n",EXPECTED_KERNEL_BUILD);return 1;
    }
    struct sigaction sa = {0};sa.sa_handler=interrupted;sigemptyset(&sa.sa_mask);
    if(sigaction(SIGALRM,&sa,NULL))return 1;
    struct timespec future={INT64_C(0x80000010),123456789},remaining={0};
    if(local_alarm())return 1;
    int result=clock_nanosleep(CLOCK_MONOTONIC,0,&future,&remaining);cancel_alarm();
    if(result!=EINTR||signals_seen!=1||remaining.tv_sec<INT32_MAX||remaining.tv_sec>future.tv_sec||remaining.tv_nsec<0||remaining.tv_nsec>=1000000000L){
        fprintf(stderr,"FAIL nanosleep EINTR result=%d signals=%d rem=%" PRId64 "\n",result,signals_seen,(int64_t)remaining.tv_sec);return 1;
    }
    puts("GLIBC_TIME64_NANOSLEEP_EINTR_PASS");
#ifdef __arm__
    const long nr_select=413,nr_poll=414;
#else
    const long nr_select=72,nr_poll=73;
#endif
    unsigned long long before=0,after=0,mask=UINT64_C(1)<<62;
    if(syscall(SYS_rt_sigprocmask,2,NULL,&before,8))return 1;
    struct {void *mask;size_t size;} sigarg={&mask,8};
    struct {uint64_t before;struct timespec timeout;uint64_t after;} t;
    for(int api=0;api<2;api++){
        t.before=t.after=UINT64_C(0x5e67aa809ac42b31);t.timeout=future;
        if(local_alarm())return 1;
        errno=0;
        long ret=api==0?syscall(nr_select,0,NULL,NULL,NULL,&t.timeout,&sigarg):
                         syscall(nr_poll,NULL,0,&t.timeout,&mask,8);
        int saved=errno;cancel_alarm();
        if(syscall(SYS_rt_sigprocmask,2,NULL,&after,8))return 1;
        if(ret!=-1||saved!=EINTR||before!=after||t.before!=UINT64_C(0x5e67aa809ac42b31)||t.after!=UINT64_C(0x5e67aa809ac42b31)||
           t.timeout.tv_sec<INT32_MAX||t.timeout.tv_sec>future.tv_sec||t.timeout.tv_nsec<0||t.timeout.tv_nsec>=1000000000L){
            fprintf(stderr,"FAIL raw %s EINTR result=%ld errno=%d rem=%" PRId64 "\n",api?"ppoll":"pselect",ret,saved,(int64_t)t.timeout.tv_sec);return 1;
        }
        printf("GLIBC_RAW_%s_TIME64_EINTR_COPYBACK_PASS\n",api?"PPOLL":"PSELECT");
    }
    /* Stop/continue without a user handler exercises restart_syscall with the
     * stored futex timeout; a handler would legitimately produce EINTR. */
#ifdef __arm__
    const long nr_futex=422;
#else
    const long nr_futex=98;
#endif
    int *word=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(word==MAP_FAILED)return 1;
    *word=0;pid_t parent=getpid(),child=fork();
    if(child<0){munmap(word,4096);return 1;}
    if(child==0){
        usleep(20000);
        if(kill(parent,SIGSTOP))_exit(2);
        usleep(20000);
        if(kill(parent,SIGCONT))_exit(3);
        usleep(20000);
        long woke=syscall(nr_futex,word,1,1,NULL,NULL,0);
        _exit(woke==1?0:4);
    }
    struct timespec futex_time=future;
    errno=0;long waited=syscall(nr_futex,word,0,0,&futex_time,NULL,0);int saved=errno;
    int status=0;pid_t joined=waitpid(child,&status,0);munmap(word,4096);
    if(waited!=0||joined!=child||!WIFEXITED(status)||WEXITSTATUS(status)!=0){
        fprintf(stderr,"FAIL futex restart result=%ld errno=%d child=%d\n",waited,saved,status);return 1;
    }
    puts("GLIBC_RAW_FUTEX_TIME64_STOP_CONT_RESTART_PASS");
    struct timespec original,probe_future={INT64_C(4102444800),123456789},observed;
    if(clock_gettime(CLOCK_REALTIME,&original)||clock_settime(CLOCK_REALTIME,&probe_future))return 1;
    int got=clock_gettime(CLOCK_REALTIME,&observed);
    int restored=clock_settime(CLOCK_REALTIME,&original);
    if(got||restored||observed.tv_sec<probe_future.tv_sec||observed.tv_sec>probe_future.tv_sec+2){
        fputs("FAIL glibc guest 2100 clock roundtrip\n",stderr);return 1;
    }
    puts("GLIBC_TIME64_VM_CLOCK_2100_RESTORED_PASS");
    return 0;
}

int main(int argc, char **argv)
{
    int expect_overflow;
    int regression = argc == 3 && strcmp(argv[2], "--qemu-regression") == 0;
    if ((argc != 2 && !regression) || (strcmp(argv[1], "--expect-eoverflow") != 0 &&
                      strcmp(argv[1], "--expect-supported") != 0)) {
        fprintf(stderr, "usage: %s --expect-eoverflow|--expect-supported [--qemu-regression]\n", argv[0]);
        return 125;
    }
    expect_overflow = strcmp(argv[1], "--expect-eoverflow") == 0;
    printf("ABI long=%zu time_t=%zu timespec=%zu __TIMESIZE=%d\n",
           sizeof(long), sizeof(time_t), sizeof(struct timespec), __TIMESIZE);
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec <= 0 ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) {
        fprintf(stderr, "FAIL current clock errno=%d\n", errno);
        return 1;
    }
    printf("CURRENT_CLOCK_PASS seconds=%" PRId64 " nanoseconds=%ld\n",
           (int64_t) now.tv_sec, now.tv_nsec);
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "FAIL timerfd_create errno=%d\n", errno);
        return 1;
    }
    struct itimerspec timer = {0};
    timer.it_value.tv_sec = (time_t) INT64_C(0x80000010);
    errno = 0;
    int result = timerfd_settime(fd, 0, &timer, NULL);
    int saved_errno = errno;
    int close_result = close(fd); /* Cancel an accepted distant timer immediately. */
    printf("TIME64_TIMER seconds=%" PRId64 " result=%d errno=%d closed=%d\n",
           (int64_t) timer.it_value.tv_sec, result, saved_errno, close_result);
    if (close_result != 0 || (expect_overflow ?
        (result != -1 || saved_errno != EOVERFLOW) : result != 0)) {
        fprintf(stderr, "FAIL expected=%s\n", expect_overflow ? "EOVERFLOW" : "accepted");
        return 1;
    }
    if (regression && (expect_overflow || interrupted_tests())) return 1;
    puts(expect_overflow ? "GLIBC_TIME64_FALLBACK_LIMIT_CONFIRMED" :
                           "GLIBC_TIME64_TIMER_SUPPORTED");
    return 0;
}
