#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CG "/sys/fs/cgroup/unified/psi-io"
#define BLK "/sys/fs/cgroup/blkio/psi-io"
#define DEVICE "/dev/loop2"
#define IMAGE "/ram/psi-io.img"
#define CHUNK 65536
#define OPERATIONS 32
#define RATE 262144
static pid_t worker_pid;
static int cpu_ids[2];
struct pressure { unsigned long long some, full; };
struct progress {
    atomic_uint inflight, completed;
    int before_cpu[OPERATIONS], after_cpu[OPERATIONS];
    double operation_seconds[OPERATIONS], elapsed;
};
static void cleanup(void)
{
    if (worker_pid > 0) {
        kill(worker_pid, SIGKILL);
        while (waitpid(worker_pid, NULL, 0) < 0 && errno == EINTR) {}
        worker_pid = 0;
    }
}
static void ck(int yes, const char *what)
{
    if (!yes) {
        fprintf(stderr, "LAB_PSI_IO_FAILED %s errno=%d (%s)\n", what, errno, strerror(errno));
        cleanup(); exit(1);
    }
}
static void watchdog(int sig)
{
    (void)sig; if (worker_pid > 0) kill(worker_pid, SIGKILL);
    static const char msg[] = "LAB_PSI_IO_FAILED watchdog\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg)-1); _exit(124);
}
static double now(void)
{
    struct timespec t; ck(!clock_gettime(CLOCK_MONOTONIC, &t), "clock");
    return t.tv_sec + t.tv_nsec/1e9;
}
static void put(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC); ck(fd >= 0, path);
    ssize_t n = write(fd, value, strlen(value)); int error = errno;
    close(fd); errno = error; ck(n == (ssize_t)strlen(value), path);
}
static void move_to(pid_t pid, const char *group)
{
    char path[256], value[32]; snprintf(path, sizeof(path), "%s/cgroup.procs", group);
    snprintf(value, sizeof(value), "%d", pid); put(path, value);
}
static void set_cpu(pid_t pid, int cpu)
{
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    ck(!sched_setaffinity(pid, sizeof(set), &set), "set worker CPU");
}
static struct pressure read_pressure(const char *path)
{
    FILE *f = fopen(path, "r"); ck(f != NULL, path);
    char line[256], kind[8]; double a, b, c; unsigned long long total;
    struct pressure p = {0}; unsigned mask = 0;
    while (fgets(line, sizeof(line), f)) {
        ck(sscanf(line, "%7s avg10=%lf avg60=%lf avg300=%lf total=%llu", kind, &a, &b, &c, &total) == 5,
           "IO pressure format");
        if (!strcmp(kind, "some")) { ck(!(mask & 1), "duplicate some"); p.some = total; mask |= 1; }
        else if (!strcmp(kind, "full")) { ck(!(mask & 2), "duplicate full"); p.full = total; mask |= 2; }
        else ck(0, "unexpected IO pressure kind");
    }
    fclose(f); ck(mask == 3, "IO some and full present"); return p;
}
static int trigger(const char *path, const char *value)
{
    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC); ck(fd >= 0, path);
    ck(write(fd, value, strlen(value)+1) == (ssize_t)strlen(value)+1, "register IO trigger");
    return fd;
}
static int epoll_for(int fd)
{
    int ep = epoll_create1(EPOLL_CLOEXEC); ck(ep >= 0, "epoll create");
    struct epoll_event event = {.events=EPOLLPRI, .data.fd=fd};
    ck(!epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event), "epoll register IO"); return ep;
}
static void wait_poll(int fd, const char *name)
{
    struct pollfd p = {.fd=fd, .events=POLLPRI}; int n = poll(&p, 1, 4000);
    ck(n == 1 && (p.revents & POLLPRI) && !(p.revents & (POLLERR|POLLHUP|POLLNVAL)), name);
    printf("LAB_PSI_IO_EVENT kind=poll name=%s flags=0x%x\n", name, p.revents);
}
static void wait_epoll(int ep, const char *name)
{
    struct epoll_event event; int n = epoll_wait(ep, &event, 1, 4000);
    ck(n == 1 && (event.events & EPOLLPRI) && !(event.events & (EPOLLERR|EPOLLHUP)), name);
    printf("LAB_PSI_IO_EVENT kind=epoll name=%s flags=0x%x\n", name, event.events);
}
static void read_again(int fd)
{
    char buf[1024]; ck(lseek(fd, 0, SEEK_SET) == 0, "rewind IO pressure");
    ck(read(fd, buf, sizeof(buf)) > 0, "read IO pressure between notifications");
}
static char task_state(pid_t pid)
{
    char path[64], buf[1024]; snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC); ck(fd >= 0, "worker stat");
    ssize_t n = read(fd, buf, sizeof(buf)-1); close(fd); ck(n > 0, "read worker stat"); buf[n]=0;
    char *end = strrchr(buf, ')'); ck(end && end[1]==' ' && end[2], "worker stat state"); return end[2];
}
static void wchan(pid_t pid, char *buf, size_t size)
{
    char path[64]; snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC); ck(fd >= 0, "worker wchan");
    ssize_t n = read(fd, buf, size-1); close(fd); ck(n >= 0, "read worker wchan"); buf[n]=0;
}
static void guard_loop(void)
{
    struct statfs fs; ck(!statfs(IMAGE, &fs) && fs.f_type == 0x01021994, "tmpfs-only loop image");
    struct stat image, device; ck(!stat(IMAGE, &image) && image.st_size == 8388608, "8MiB image guard");
    ck(!stat(DEVICE, &device) && S_ISBLK(device.st_mode) && major(device.st_rdev)==7, "loop device guard");
    int fd = open(DEVICE, O_RDONLY | O_CLOEXEC); ck(fd >= 0, "open loop guard");
    struct loop_info64 info; ck(!ioctl(fd, LOOP_GET_STATUS64, &info), "loop association"); close(fd);
    ck(info.lo_inode == image.st_ino && info.lo_offset == 0 && info.lo_sizelimit == 0,
       "loop belongs to guest RAM image");
}
static void io_worker(struct progress *progress, int gate)
{
    signal(SIGALRM, SIG_DFL); alarm(35);
    ck(!prctl(PR_SET_PDEATHSIG, SIGKILL), "worker parent death signal");
    set_cpu(0, cpu_ids[0]);
    char byte; ck(read(gate, &byte, 1) == 1, "worker start gate"); close(gate);
    void *buffer = NULL; ck(!posix_memalign(&buffer, 4096, CHUNK), "aligned IO buffer");
    int fd = open(DEVICE, O_RDONLY | O_DIRECT | O_CLOEXEC); ck(fd >= 0, "read-only RAM loop");
    double start = now();
    for (unsigned i = 0; i < OPERATIONS; i++) {
        memset(buffer, 0xa5, CHUNK);
        progress->before_cpu[i] = sched_getcpu();
        atomic_store_explicit(&progress->inflight, i+1, memory_order_release);
        double began = now();
        ck(pread(fd, buffer, CHUNK, (off_t)i*CHUNK) == CHUNK, "throttled direct IO read");
        progress->operation_seconds[i] = now()-began;
        progress->after_cpu[i] = sched_getcpu();
        for (unsigned j=0; j<CHUNK; j++) ck(((unsigned char *)buffer)[j] == 0, "RAM loop data round trip");
        atomic_store_explicit(&progress->completed, i+1, memory_order_release);
    }
    progress->elapsed = now()-start;
    close(fd); free(buffer); _exit(0);
}
static unsigned stalled_migrations(struct progress *progress)
{
    unsigned qualified=0, attempts=0, last_operation=0;
    double deadline=now()+4.0;
    while (attempts<8 && now()<deadline) {
        unsigned seq=atomic_load_explicit(&progress->inflight, memory_order_acquire);
        unsigned done=atomic_load_explicit(&progress->completed, memory_order_acquire);
        if (!seq || seq<=last_operation || done>=seq || task_state(worker_pid)!='D') { usleep(2000); continue; }
        last_operation=seq; attempts++;
        int from=progress->before_cpu[seq-1], target=from==cpu_ids[0]?cpu_ids[1]:cpu_ids[0];
        char symbol[160]; wchan(worker_pid,symbol,sizeof(symbol));
        set_cpu(worker_pid,target);
        const char *destination=(attempts&1)?CG "/b":CG "/a";
        move_to(worker_pid,destination);
        int still_stalled=atomic_load_explicit(&progress->completed,memory_order_acquire)<seq && task_state(worker_pid)=='D';
        double wake_deadline=now()+1.5;
        while (atomic_load_explicit(&progress->completed,memory_order_acquire)<seq && now()<wake_deadline) usleep(1000);
        ck(atomic_load_explicit(&progress->completed,memory_order_acquire)>=seq, "IO worker resumes after migration");
        int resumed=progress->after_cpu[seq-1];
        if (still_stalled) {
            ck(resumed==target && resumed!=from, "stalled IO resumes on requested different CPU"); qualified++;
        }
        printf("LAB_PSI_IO_MIGRATION operation=%u observed_state=D remained_D=%d before_cpu=%d target_cpu=%d resumed_cpu=%d cgroup=%s wchan=%s\n",
               seq,still_stalled,from,target,resumed,destination,symbol);
    }
    if (qualified)
        printf("LAB_PSI_IO_PASS cross_cpu_stalled_wakeup_and_cgroup_migration qualified=%u attempts=%u\n",qualified,attempts);
    else
        printf("LAB_PSI_IO_LIMIT no_qualified_cross_cpu_stalled_wakeup attempts=%u\n",attempts);
    return qualified;
}
int main(void)
{
    if (!getenv("PSI_IO_QEMU_PROBE") || access("/QEMU_LAB_GUEST", F_OK)) return 125;
    setbuf(stdout,NULL); signal(SIGALRM,watchdog); alarm(45);
    struct utsname u; ck(!uname(&u),"uname"); printf("LAB_KERNEL %s %s\n",u.release,u.version);
    guard_loop(); cpu_set_t set; ck(!sched_getaffinity(0,sizeof(set),&set),"available CPUs");
    int n=0; for(int i=0;i<CPU_SETSIZE && n<2;i++) if(CPU_ISSET(i,&set)) cpu_ids[n++]=i;
    ck(n==2,"two-vCPU guard");
    ck(!mkdir(CG,0700) && !mkdir(CG "/a",0700) && !mkdir(CG "/b",0700) && !mkdir(BLK,0700),"test cgroups");
    struct stat device; ck(!stat(DEVICE,&device),"device number"); char limit[64];
    snprintf(limit,sizeof(limit),"%u:%u %d",major(device.st_rdev),minor(device.st_rdev),RATE);
    put(BLK "/blkio.throttle.read_bps_device",limit);
    struct pressure before_global=read_pressure("/proc/pressure/io"),before_a=read_pressure(CG "/a/io.pressure"),before_b=read_pressure(CG "/b/io.pressure");
    int global=trigger("/proc/pressure/io","some 20000 500000");
    int a_some=trigger(CG "/a/io.pressure","some 20000 500000");
    int a_full=trigger(CG "/a/io.pressure","full 20000 500000"),a_ep=epoll_for(a_full);
    int b_some=trigger(CG "/b/io.pressure","some 20000 500000");
    int b_full=trigger(CG "/b/io.pressure","full 20000 500000"),b_ep=epoll_for(b_full);
    struct progress *progress=mmap(NULL,sizeof(*progress),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    ck(progress!=MAP_FAILED,"shared worker observations"); memset(progress,0,sizeof(*progress));
    int gate[2]; ck(!pipe2(gate,O_CLOEXEC),"start gate");
    worker_pid=fork(); ck(worker_pid>=0,"fork IO worker");
    if(!worker_pid) { close(gate[1]); io_worker(progress,gate[0]); }
    close(gate[0]); move_to(worker_pid,BLK); move_to(worker_pid,CG "/a");
    ck(write(gate[1],"x",1)==1,"release IO worker"); close(gate[1]);
    wait_poll(a_some,"cgroup_a_io_some"); wait_epoll(a_ep,"cgroup_a_io_full"); wait_poll(global,"global_io_some");
    read_again(a_some); wait_poll(a_some,"cgroup_a_io_some_rearm");
    read_again(a_full); wait_epoll(a_ep,"cgroup_a_io_full_rearm");
    unsigned migrated=stalled_migrations(progress);
    wait_poll(b_some,"cgroup_b_io_some_after_migration"); wait_epoll(b_ep,"cgroup_b_io_full_after_migration");
    int status; ck(waitpid(worker_pid,&status,0)==worker_pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"IO worker successful exit"); worker_pid=0;
    ck(atomic_load_explicit(&progress->completed,memory_order_acquire)==OPERATIONS,"all bounded reads completed");
    ck(progress->elapsed>=6.0 && progress->elapsed<25.0,"256KiB/s throttle actually delayed 2MiB reads");
    struct pressure after_global=read_pressure("/proc/pressure/io"),after_a=read_pressure(CG "/a/io.pressure"),after_b=read_pressure(CG "/b/io.pressure");
    ck(after_a.some>before_a.some && after_a.full>before_a.full,"cgroup A IO some/full increased");
    ck(after_b.some>before_b.some && after_b.full>before_b.full,"cgroup B IO some/full increased after migration");
    ck(after_global.some>before_global.some && after_global.full>=before_global.full,"global IO total increased and monotonic");
    printf("LAB_PSI_IO_PASS actual_some_full_notifications_rearm a_some_delta=%llu a_full_delta=%llu b_some_delta=%llu b_full_delta=%llu global_some_delta=%llu global_full_delta=%llu bytes=%d throttle_seconds=%.3f qualified_cross_cpu_migrations=%u\n",
           after_a.some-before_a.some,after_a.full-before_a.full,after_b.some-before_b.some,after_b.full-before_b.full,
           after_global.some-before_global.some,after_global.full-before_global.full,CHUNK*OPERATIONS,progress->elapsed,migrated);
    close(a_ep);close(b_ep);close(global);close(a_some);close(a_full);close(b_some);close(b_full);munmap(progress,sizeof(*progress));
    ck(!rmdir(CG "/a") && !rmdir(CG "/b") && !rmdir(CG) && !rmdir(BLK),"remove IO test cgroups");
    alarm(0);puts("PSI_IO_PROBE_COMPLETE");return 0;
}
