#!/bin/sh
# Run on the existing .51 netpanel host to undo only this CCR extension.
set -eu
backup=/root/netpanel-before-ccr-card-20261004
test -f "$backup/netpanel-collector"
cp "$backup/netpanel-collector" /usr/bin/netpanel-collector
chmod 755 /usr/bin/netpanel-collector
/etc/init.d/netpanel restart
# Retain the added files for inspection, but stop serving the endpoint.
if [ -f /www/cgi-bin/ccr-status.cgi ]; then
 mv /www/cgi-bin/ccr-status.cgi "$backup/ccr-status.cgi.disabled"
fi
