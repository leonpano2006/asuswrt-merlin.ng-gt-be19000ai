#!/bin/bash
# Candidate only: requires the separately reviewed fixed link-local setup.
# .51 keeps its existing private key. This command never provisions a network
# address, changes known_hosts, acknowledges the guardian or accepts a boot.
set -euo pipefail
case "${1:---check}" in
  --check)
    exec /usr/bin/ssh -T -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -T -K 5 -I 30 -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ProxyCommand=nc 169.254.190.15 2223" -p 2223 MastermixStudios@leon-ubuntu26-be19000ai "set -e; uname -r; uname -v; cat /proc/1/comm; cat /proc/sys/kernel/random/boot_id; findmnt -n -o SOURCE,FSTYPE,OPTIONS /; id -u"'
    ;;
  --interactive)
    exec /usr/bin/ssh -tt -b 192.168.100.35 \
      -o BatchMode=yes -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes \
      -o ConnectTimeout=6 -o ServerAliveInterval=5 root@192.168.100.51 \
      'exec dbclient -t -K 5 -I 180 -i /root/.ssh/netpanel -o BatchMode=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=yes -o "ProxyCommand=nc 169.254.190.15 2223" -p 2223 MastermixStudios@leon-ubuntu26-be19000ai'
    ;;
  *) printf 'Usage: %s [--check|--interactive]\n' "$0" >&2; exit 2 ;;
esac
