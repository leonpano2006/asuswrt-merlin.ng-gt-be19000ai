#!/bin/bash
set -eu
export PATH=/usr/sbin:/usr/bin
printf 'FRESH_SSH_SESSION\n'
printenv | LC_ALL=C grep -E '^(LANG|LANGUAGE|LC_[A-Z_]+|TERM)=' || :
test "$(locale charmap)" = UTF-8
printf 'TTY='; tty
dialog --print-version
dialog --print-maxsize
DEBIAN_FRONTEND=dialog perl -MDebconf::FrontEnd::Dialog -e 'my $f=Debconf::FrontEnd::Dialog->new; print "DIALOG_FRONTEND_PASS\n";'
printf 'HOSTNAME='; hostname
printf 'HOST_LOOKUP\n'; getent hosts "$(hostname)" || :
printf 'HOSTS_LOCAL_ENTRIES\n'
grep -E '^127\.' /etc/hosts
printf 'LOCALE_DIALOG_READONLY_END\n'
