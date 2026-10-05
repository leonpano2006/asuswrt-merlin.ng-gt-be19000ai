#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _TIME_BITS 64
#include <dlfcn.h>
#include <errno.h>
#include <gnu/libc-version.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
_Static_assert(sizeof(time_t) == 8, "time64 required");
_Static_assert(sizeof(off_t) == 8, "large file offsets required");

static void require(int ok, const char *operation)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s errno=%d (%s)\n", operation, errno, strerror(errno));
        exit(1);
    }
}

static void pthread_ok(int rc, const char *operation)
{
    if (rc) {
        errno = rc;
        require(0, operation);
    }
}

struct thread_state {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int ready;
};

static void *worker(void *opaque)
{
    struct thread_state *state = opaque;
    pthread_ok(pthread_mutex_lock(&state->lock), "worker mutex lock");
    state->ready = 1;
    pthread_ok(pthread_cond_signal(&state->cond), "worker cond signal");
    pthread_ok(pthread_mutex_unlock(&state->lock), "worker mutex unlock");
    return state;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *version = gnu_get_libc_version();
    printf("runtime_glibc=%s time_t=%zu off_t=%zu\n", version,
           sizeof(time_t), sizeof(off_t));
    require(strcmp(version, "2.44") == 0, "exact glibc 2.44 runtime");

    struct thread_state state = {.lock = PTHREAD_MUTEX_INITIALIZER};
    pthread_condattr_t attr;
    pthread_ok(pthread_condattr_init(&attr), "condattr init");
    pthread_ok(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), "condattr monotonic");
    pthread_ok(pthread_cond_init(&state.cond, &attr), "cond init");
    pthread_ok(pthread_condattr_destroy(&attr), "condattr destroy");
    pthread_t thread;
    pthread_ok(pthread_mutex_lock(&state.lock), "main mutex lock");
    pthread_ok(pthread_create(&thread, NULL, worker, &state), "pthread create");
    while (!state.ready)
        pthread_ok(pthread_cond_wait(&state.cond, &state.lock), "cond wait");
    struct timespec deadline;
    require(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0, "monotonic clock");
    deadline.tv_nsec += 20000000;
    if (deadline.tv_nsec >= 1000000000) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000;
    }
    int rc;
    do {
        rc = pthread_cond_timedwait(&state.cond, &state.lock, &deadline);
    } while (rc == 0);
    require(rc == ETIMEDOUT, "timed condition variable timeout");
    pthread_ok(pthread_mutex_unlock(&state.lock), "main mutex unlock");
    void *thread_result = NULL;
    pthread_ok(pthread_join(thread, &thread_result), "pthread join");
    require(thread_result == &state, "pthread result");
    pthread_ok(pthread_cond_destroy(&state.cond), "cond destroy");
    pthread_ok(pthread_mutex_destroy(&state.lock), "mutex destroy");
    puts("pthread_condvar_futex=PASS");

    pid_t child;
    char *const args[] = {"sh", "-c", "exit 17", NULL};
    rc = posix_spawn(&child, "/bin/sh", NULL, NULL, args, environ);
    if (rc) { errno = rc; require(0, "posix_spawn"); }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "spawn waitpid");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 17, "spawn exit status");
    puts("posix_spawn_wait=PASS");

    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    rc = getaddrinfo("localhost", NULL, &hints, &addresses);
    if (rc) {
        fprintf(stderr, "FAIL getaddrinfo localhost: %s\n", gai_strerror(rc));
        return 1;
    }
    require(addresses != NULL, "NSS localhost result");
    freeaddrinfo(addresses);
    struct passwd *pw = getpwuid(getuid());
    require(pw != NULL && pw->pw_uid == getuid(), "NSS getpwuid");
    puts("nss_hosts_passwd=PASS");

    void *handle = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    require(handle != NULL, "dlopen libm");
    dlerror();
    double (*cosine)(double) = (double (*)(double)) dlsym(handle, "cos");
    require(dlerror() == NULL && cosine != NULL, "dlsym cos");
    double value = cosine(0.5);
    require(value > 0.8775825618 && value < 0.8775825620, "dynamic libm result");
    require(dlclose(handle) == 0, "dlclose libm");
    puts("dlopen_dlsym=PASS");

    const time_t future = 4102444800LL; /* 2100-01-01 UTC; no clock changes. */
    int timer = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    require(timer >= 0, "timerfd create");
    struct itimerspec alarm = {.it_value = {.tv_sec = future, .tv_nsec = 123456789}};
    require(timerfd_settime(timer, TFD_TIMER_ABSTIME, &alarm, NULL) == 0,
            "timerfd absolute 2100");
    struct itimerspec remaining;
    require(timerfd_gettime(timer, &remaining) == 0 && remaining.it_value.tv_sec > 0,
            "timerfd future remaining time");
    alarm = (struct itimerspec){0};
    require(timerfd_settime(timer, 0, &alarm, NULL) == 0, "timerfd cancel");
    require(close(timer) == 0, "timerfd close");
    puts("timerfd_post2038=PASS");

    char name[] = "/tmp/glibc244-native-XXXXXX";
    int fd = mkstemp(name);
    require(fd >= 0, "private timestamp file");
    require(unlink(name) == 0, "unlink private timestamp file");
    struct timespec timestamps[2] = {{future, 123456789}, {future, 987654321}};
    require(futimens(fd, timestamps) == 0, "futimens 2100");
    struct stat st;
    require(fstat(fd, &st) == 0, "fstat 2100");
    require(st.st_atim.tv_sec == future && st.st_atim.tv_nsec == 123456789 &&
            st.st_mtim.tv_sec == future && st.st_mtim.tv_nsec == 987654321,
            "2100 timestamp roundtrip");
    require(close(fd) == 0, "timestamp file close");
    puts("futimens_post2038=PASS");
    puts("GLIBC244_NATIVE_WRAPPER_PASS");
    return 0;
}
