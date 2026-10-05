#!/bin/bash
# Reuse the already enrolled key on .51; never export its private key.
set -euo pipefail
case "${1:-}" in
  "")
    exec /usr/bin/ssh -tt -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -t -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes MastermixStudios@192.168.100.15'
    ;;
  --check)
    exec /usr/bin/ssh -T -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -T -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes MastermixStudios@192.168.100.15 "set -e; uname -r; cat /proc/1/comm; cat /proc/sys/kernel/random/boot_id"'
    ;;
  --ubuntu-recovery)
    # Available only after the separately validated recovery package/key is
    # provisioned on Ubuntu. Its host key has a distinct pinned alias on .51.
    exec /usr/bin/ssh -tt -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -t -K 5 -I 180 -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ProxyCommand=nc 192.168.100.15 2222" -p 2222 MastermixStudios@leon-ubuntu26-be19000ai'
    ;;
  --ubuntu-primary-check)
    exec /usr/bin/ssh -T -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -T -K 5 -I 30 -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ProxyCommand=nc 192.168.100.15 22" MastermixStudios@leon-ubuntu26-be19000ai "set -e; uname -r; uname -v; cat /proc/1/comm; cat /proc/sys/kernel/random/boot_id; findmnt -n -o SOURCE,FSTYPE,OPTIONS /; id -u"'
    ;;
  --ubuntu-recovery-check)
    exec /usr/bin/ssh -T -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -T -K 5 -I 30 -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ProxyCommand=nc 192.168.100.15 2222" -p 2222 MastermixStudios@leon-ubuntu26-be19000ai "set -e; uname -r; uname -v; cat /proc/1/comm; cat /proc/sys/kernel/random/boot_id; findmnt -n -o SOURCE,FSTYPE,OPTIONS /; id -u"'
    ;;
  *) printf 'Usage: %s [--check|--ubuntu-recovery|--ubuntu-primary-check|--ubuntu-recovery-check]\n' "$0" >&2; exit 2 ;;
esac
