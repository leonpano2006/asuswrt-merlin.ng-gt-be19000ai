/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "diagnostic-writer.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef AG_DIAG_FIXTURE
#error Tests must use the fixture build, never the production device adapter.
#endif
static uint64_t clock_ms(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;}
static struct ag_diag_event event(unsigned id){
    struct ag_diag_event e={.stage=AG_DIAG_GUARD_ACCEPTED,.reason=AG_CORE_FAILURE,.contract=AG_THIS_BOOT_COMMITTED2,
      .monotonic_ms=12345,.core_sequence=91,.missing_core=AG_ROOT_RW_IDENTITY,.missing_services=AG_SSH};
    snprintf(e.boot_id,sizeof(e.boot_id),"%08x-1111-4111-8111-111111111111",id);memset(e.generation_sha256,0xab,32);return e;
}
static enum ag_diag_result wait_bounded(struct ag_diag_writer *w){
    uint64_t until=clock_ms()+4200;
    for(;;){enum ag_diag_result r=ag_diag_poll(w,clock_ms());if(r!=AG_DIAG_PENDING)return r;
       assert(clock_ms()<until);usleep(1000);}
}
static enum ag_diag_result once(const char *root,unsigned id,unsigned fault,enum ag_diag_target target){
    struct ag_diag_policy p={.target=target,.fixture_root=root,.fault=fault};
    struct ag_diag_event e=event(id);struct ag_diag_writer w={0};
    uint64_t before=clock_ms();assert(!ag_diag_start(&w,&p,&e,-1,before));
    assert(clock_ms()-before<200);assert(w.pid>1);
    assert(ag_diag_start(&w,&p,&e,-1,clock_ms())==-1);
    return wait_bounded(&w);
}
static void path(char *out,size_t cap,const char *root,unsigned id){snprintf(out,cap,"%s/leon-boot/diagnostics/%08x-1111-4111-8111-111111111111.failure.json",root,id);}
static int exists(const char *p){struct stat s;return lstat(p,&s)==0;}
int main(int argc,char **argv){
    assert(argc==2);const char *root=argv[1];assert(mkdir(root,0700)==0);char f[4096],other[4096];struct stat st;
    assert(once(root,1,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_SAVED);path(f,sizeof(f),root,1);
    assert(!lstat(f,&st)&&S_ISREG(st.st_mode)&&st.st_size<=AG_DIAG_MAX_BYTES&&(st.st_mode&0777)==0600&&st.st_nlink==1);
    char old[2048],fresh[2048];int fd=open(f,O_RDONLY);assert(fd>=0);ssize_t size=read(fd,old,sizeof(old));close(fd);assert(size>0);
    assert(once(root,1,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_EXISTS);fd=open(f,O_RDONLY);assert(fd>=0);assert(read(fd,fresh,sizeof(fresh))==size&&!memcmp(old,fresh,(size_t)size));close(fd);
    puts("PASS atomic_0600_bounded_and_no_overwrite");
    path(f,sizeof(f),root,2);assert(!symlink("/dev/null",f));assert(once(root,2,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_REFUSED);
    path(f,sizeof(f),root,3);assert(!mkfifo(f,0600));assert(once(root,3,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_REFUSED);
    path(f,sizeof(f),root,4);path(other,sizeof(other),root,1);assert(!link(other,f));assert(once(root,4,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_REFUSED);assert(!unlink(f));
    puts("PASS symlink_fifo_hardlink_final_refused");
    snprintf(f,sizeof(f),"%s/leon-boot",root);assert(!chmod(f,0777));assert(once(root,5,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_REFUSED);assert(!chmod(f,0700));
    snprintf(f,sizeof(f),"%s/root-link",root);assert(!symlink(root,f));assert(once(f,5,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_REFUSED);
    puts("PASS writable_parent_and_root_symlink_refused");
    assert(once(root,6,AG_DIAG_PARTIAL_WRITE,AG_DIAG_JFFS)==AG_DIAG_IO_ERROR);path(f,sizeof(f),root,6);assert(!exists(f));
    assert(once(root,7,AG_DIAG_FULL,AG_DIAG_JFFS)==AG_DIAG_IO_ERROR);path(f,sizeof(f),root,7);assert(!exists(f));
    assert(once(root,8,AG_DIAG_READONLY,AG_DIAG_JFFS)==AG_DIAG_IO_ERROR);path(f,sizeof(f),root,8);assert(!exists(f));
    puts("PASS partial_write_and_injected_full_readonly_do_not_publish");
    assert(once(root,9,AG_DIAG_AFTER_RENAME,AG_DIAG_JFFS)==AG_DIAG_PUBLISHED_UNCERTAIN);path(f,sizeof(f),root,9);assert(exists(f));
    assert(once(root,9,AG_DIAG_NO_FAULT,AG_DIAG_JFFS)==AG_DIAG_EXISTS);
    puts("PASS post_publish_uncertainty_preserves_record");
    struct ag_diag_policy p={.target=AG_DIAG_JFFS,.fixture_root=root,.fault=AG_DIAG_HANG};
    struct ag_diag_event e=event(10);struct ag_diag_writer w={0};int pipefd[2];assert(!pipe2(pipefd,O_NONBLOCK|O_CLOEXEC));
    uint64_t started=clock_ms();assert(!ag_diag_start(&w,&p,&e,pipefd[1],started));assert(fcntl(pipefd[1],F_GETFD)>=0);close(pipefd[1]);
    char byte;uint64_t end=clock_ms()+1000;for(;;){ssize_t n=read(pipefd[0],&byte,1);if(n==0)break;assert(n==-1&&errno==EAGAIN&&clock_ms()<end);usleep(1000);}close(pipefd[0]);
    assert(wait_bounded(&w)==AG_DIAG_TIMED_OUT&&w.pid==0&&w.kill_sent);assert(clock_ms()-started>=AG_DIAG_DEADLINE_MS);
    puts("PASS inherited_watchdog_fd_closed_parent_unchanged_real_3s_timeout_reaped");
    p.fault=AG_DIAG_UNREAPED;e=event(11);w=(struct ag_diag_writer){0};started=clock_ms();assert(!ag_diag_start(&w,&p,&e,-1,started));pid_t child=w.pid;
    for(unsigned i=0;i<10000;++i)assert(ag_diag_poll(&w,started+3000+i)==AG_DIAG_PENDING);
    assert(w.pid==child&&w.timed_out&&w.kill_sent&&clock_ms()-started<1000);
    /* Fixture bypasses waitpid only to model a D-state survivor; actual child
     * was SIGKILLed. Test harness explicitly reaps this synthetic case. */
    int status;for(unsigned i=0;;++i){pid_t reaped=waitpid(child,&status,WNOHANG);if(reaped==child)break;assert(i<1000);usleep(1000);}
    puts("PASS synthetic_unreapable_retains_pid_no_block_no_second_child");
    snprintf(f,sizeof(f),"%s/var",root);assert(!mkdir(f,0755));snprintf(f,sizeof(f),"%s/var/lib",root);assert(!mkdir(f,0755));
    assert(once(root,12,AG_DIAG_NO_FAULT,AG_DIAG_P11)==AG_DIAG_SAVED);
    puts("PASS p11_bootstrap_directory_contract");
    p.fault=0;e=event(13);e.boot_id[0]='"';w=(struct ag_diag_writer){0};assert(ag_diag_start(&w,&p,&e,-1,clock_ms())<0&&w.pid==0);
    e=event(13);e.reason=999;assert(ag_diag_start(&w,&p,&e,-1,clock_ms())<0&&w.pid==0);
    puts("PASS arbitrary_text_and_unknown_enum_refused_before_fork");
    p.fault=AG_DIAG_HANG;e=event(14);w=(struct ag_diag_writer){0};
    assert(!ag_diag_start(&w,&p,&e,-1,clock_ms()));child=w.pid;assert(!kill(child,SIGKILL));
    for(unsigned i=0;;++i){pid_t reaped=waitpid(child,&status,WNOHANG);if(reaped==child)break;assert(i<1000);usleep(1000);}
    assert(ag_diag_poll(&w,clock_ms())==AG_DIAG_CHILD_OWNERSHIP_LOST&&w.pid==0&&w.lost_pid==child);
    assert(ag_diag_poll(&w,UINT64_MAX)==AG_DIAG_CHILD_OWNERSHIP_LOST&&!w.kill_sent);
    puts("PASS external_reap_clears_owned_pid_never_signals_reused_pid");
    assert(!prctl(PR_SET_CHILD_SUBREAPER,1));int announce[2];assert(!pipe2(announce,O_CLOEXEC));
    pid_t middle=fork();assert(middle>=0);
    if(!middle){close(announce[0]);struct ag_diag_writer orphan={0};struct ag_diag_event x=event(15);
        if(ag_diag_start(&orphan,&p,&x,-1,clock_ms()))_exit(1);
        if(write(announce[1],&orphan.pid,sizeof(orphan.pid))!=sizeof(orphan.pid))_exit(2);
        usleep(100000);_exit(0);
    }
    close(announce[1]);struct pollfd ready={.fd=announce[0],.events=POLLIN};assert(poll(&ready,1,1000)==1);
    pid_t orphan_pid;assert(read(announce[0],&orphan_pid,sizeof(orphan_pid))==sizeof(orphan_pid));close(announce[0]);
    for(unsigned i=0;;++i){pid_t reaped=waitpid(middle,&status,WNOHANG);if(reaped==middle)break;assert(i<2000);usleep(1000);}assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    for(unsigned i=0;;++i){pid_t reaped=waitpid(orphan_pid,&status,WNOHANG);if(reaped==orphan_pid)break;assert(i<2000);usleep(1000);}
    assert((WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL)||(WIFEXITED(status)&&WEXITSTATUS(status)==125));
    path(f,sizeof(f),root,15);assert(!exists(f));
    puts("PASS parent_death_terminates_logger_or_refuses_start_race");
    return 0;
}
