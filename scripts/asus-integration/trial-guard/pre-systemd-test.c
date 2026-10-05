/* SPDX-License-Identifier: GPL-2.0-or-later
 * QEMU-only PID1 handoff fixture. The collector explicitly fakes ASUS/SSH
 * health after the native systemd smoke service; not a real service proof.
 */
#define main process_handoff_test_unused
#include "handoff-test.c"
#undef main
#include <sys/prctl.h>
#include <sys/stat.h>

static void put_file(const char *path,const char *text) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd>=0);
    size_t n=strlen(text);assert(write(fd,text,n)==(ssize_t)n);assert(!close(fd));
}
static void observer(struct test t) {
    assert(!prctl(PR_SET_NAME,"trial-mock-health"));close(t.control);t.control=-1;
    struct trial_message m=receive(t.health,5000);assert(m.kind==TRIAL_MONITORING);
    uint64_t deadline=ms()+295000;unsigned seq=0;bool emitted=false,cgroup_recorded=false;
    while(ms()<deadline) {
        if(!access("/run/leon-trial-systemd-up",F_OK)) {
            /* Before systemd mounts cgroup2, /proc/PID/cgroup may be empty.
             * Inspect the actual adopted cgroup only after native boot. */
            if(!cgroup_recorded) {
                char path[80],line[1024];snprintf(path,sizeof(path),"/proc/%ld/cgroup",(long)t.pid);
                int cg=open(path,O_RDONLY|O_CLOEXEC);assert(cg>=0);ssize_t got=read(cg,line,sizeof(line)-1);assert(got>0);close(cg);line[got]=0;
                printf("LAB_TRIAL_GUARD_CGROUP %s",line);fflush(stdout);cgroup_recorded=true;
            }
            char exe[256];ssize_t n=readlink("/proc/1/exe",exe,sizeof(exe)-1);assert(n>0);exe[n]=0;
            assert(!strcmp(exe,"/usr/lib/systemd/systemd"));
            assert(kill(t.pid,0)==0);
            sendm(t.health,TRIAL_FIXTURE_LOCAL,TRIAL_ALL_LOCAL,++seq,t.nonce);
            sendm(t.health,TRIAL_FIXTURE_LAN,0,seq,t.nonce);
            struct pollfd p={.fd=t.health,.events=POLLIN};
            while(poll(&p,1,0)==1) {
                struct trial_message event=receive(t.health,1000);
                assert(event.kind==TRIAL_FIXTURE_HEALTHY);
                if(!emitted) {
                    put_file("/run/leon-trial-preexec-healthy","mock healthy after actual systemd exec\n");
                    emitted=true;printf("LAB_TRIAL_PREEXEC_SYSTEMD_CHILD_SURVIVES_PASS\n");fflush(stdout);
                }
            }
        }
        nap(1000);
    }
    _exit(0); /* Fixture overall QEMU deadline is shorter than this branch. */
}
int main(int argc,char **argv) {
    assert(argc==1&&getpid()==1);(void)argv;
    guardian="/usr/libexec/leon-lab/trial/guardian-fixture-slow";
    struct test t=launch(false);
    pid_t collector=fork();assert(collector>=0);
    if(!collector)observer(t);
    close(t.health);
    printf("LAB_TRIAL_PREEXEC_ARMED_PID_%ld_BEFORE_SYSTEMD\n",(long)t.pid);fflush(stdout);
    execl("/usr/lib/systemd/systemd","/usr/lib/systemd/systemd","--system",
        "--unit=leon-full-boot.target","--log-target=console","--log-level=info",NULL);
    /* Actual exec failure still owns control socket; confirmed abort is needed
     * before a vendor fallback may be considered. No vendor code in fixture. */
    sendm(t.control,TRIAL_ABORT_PREEXEC,0,0,t.nonce);
    assert(receive(t.control,3000).kind==TRIAL_ABORTED);
    for(;;)pause();
}
