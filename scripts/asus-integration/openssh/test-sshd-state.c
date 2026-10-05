/* Pure parser fixture: no sshd/service/account or hardware operation. */
#include "sshd-state.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    static const char argv[]="/usr/sbin/sshd\0-D\0-f\0/run/leon-asus-ssh/sshd_config\0";
    static const char title[]="sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10-100 startups";
    assert(leon_sshd_command_matches(argv,sizeof(argv)-1));
    assert(leon_sshd_command_matches(title,sizeof(title)));
    char padded[256]={0};memcpy(padded,title,sizeof(title));
    assert(leon_sshd_command_matches(padded,sizeof(padded)));
    padded[sizeof(title)+3]='x';assert(!leon_sshd_command_matches(padded,sizeof(padded)));
    for(size_t n=0;n<sizeof(argv)-1;++n)assert(!leon_sshd_command_matches(argv,n));
    for(size_t n=0;n<sizeof(title);++n)assert(!leon_sshd_command_matches(title,n));
    static const char appended[]="/usr/sbin/sshd\0-D\0-f\0/run/leon-asus-ssh/sshd_config\0-oPermitRootLogin=yes\0";
    assert(!leon_sshd_command_matches(appended,sizeof(appended)-1));
    static const char *const bad[]={
        "sshd: /usr/sbin/sshd -D -f /etc/ssh/sshd_config [listener] 0 of 10-100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config.extra [listener] 0 of 10-100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] -1 of 10-100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 10000000000 of 10-100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10-100 startup",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10-100 startups extra",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10-100 startups\n",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener]  of 10-100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of -100 startups",
        "sshd: /usr/sbin/sshd -D -f /run/leon-asus-ssh/sshd_config [listener] 0 of 10- startups",
        "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
    };
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i)assert(!leon_sshd_command_matches(bad[i],strlen(bad[i])+1));
    puts("LAB_SSHD_CANONICAL_ARGV_TITLE_BOUNDARIES_PASS");
    printf("positive=3 malformed=13 truncated=%zu\n",sizeof(argv)-1+sizeof(title));
    return 0;
}
