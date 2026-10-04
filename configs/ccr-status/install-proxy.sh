set -eu
stage=/tmp/ccr-proxy-stage
backup=/root/netpanel-before-ccr-card-20261004
test ! -e "$backup"
test ! -e /www/cgi-bin/ccr-status.cgi
sh -n "$stage/netpanel-collector"
sh -n "$stage/netpanel-source.sh"
mkdir -p "$backup" /usr/libexec/netpanel/ccr-status
cp /usr/bin/netpanel-collector "$backup/"
cp "$stage/netpanel-source.sh" "$stage/normalize.jq" /usr/libexec/netpanel/ccr-status/
chmod 700 /usr/libexec/netpanel/ccr-status/netpanel-source.sh
/usr/libexec/netpanel/ccr-status/netpanel-source.sh
jq -e '.status=="ok" and .model=="CCR2216-1G-12XS-2XQ"' /tmp/netpanel-ccr.json >/dev/null
cp "$stage/ccr-status.cgi" /www/cgi-bin/ccr-status.cgi
chmod 755 /www/cgi-bin/ccr-status.cgi
cp "$stage/netpanel-collector" /usr/bin/netpanel-collector
chmod 755 /usr/bin/netpanel-collector
/etc/init.d/netpanel restart
jq '{status,model,cpu,ports:(.ports|length),errors}' /tmp/netpanel-ccr.json
