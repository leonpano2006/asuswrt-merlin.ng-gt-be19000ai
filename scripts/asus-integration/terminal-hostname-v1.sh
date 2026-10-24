#!/bin/bash
set -eu
export PATH=/usr/sbin:/usr/bin LC_ALL=C.UTF-8
[ "$EUID" = 0 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-4000-8000-000000000008 ]
[ "$(hostname)" = GT-BE19000AI-6B50 ]
[ -f /etc/hosts ] && [ ! -L /etc/hosts ]
[ "$(grep -c '^127\.0\.1\.1 be19000ai-bcm$' /etc/hosts)" = 1 ]
[ ! -e /etc/hosts.before-terminal-support-v1 ]
cp -p /etc/hosts /etc/hosts.before-terminal-support-v1
sed -i 's/^127\.0\.1\.1 be19000ai-bcm$/127.0.1.1 GT-BE19000AI-6B50 be19000ai-bcm/' /etc/hosts
getent hosts GT-BE19000AI-6B50
sudo -n true 2>/var/tmp/leon-terminal-sudo-validation.err
[ ! -s /var/tmp/leon-terminal-sudo-validation.err ]
printf 'TERMINAL_HOST_ALIAS_FIXED no_service_actions=true\n'
