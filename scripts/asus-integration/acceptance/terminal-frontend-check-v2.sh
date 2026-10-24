#!/bin/bash
set -eu
export PATH=/usr/sbin:/usr/bin
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008 ]
DEBIAN_FRONTEND=dialog perl -MDebconf::Config -MDebconf::FrontEnd::Dialog -e 'my $f=Debconf::FrontEnd::Dialog->new; print "DIALOG_FRONTEND_PASS\n";'
printf 'LOCALE_DIALOG_READONLY_END\n'
