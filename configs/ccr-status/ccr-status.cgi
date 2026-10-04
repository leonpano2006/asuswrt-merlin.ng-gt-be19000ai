#!/bin/sh
# A read-only view of the existing LAN netpanel cache; no CORS, no API credentials.
if [ -s /tmp/netpanel-ccr.json ]; then
 printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
 cat /tmp/netpanel-ccr.json
else
 printf 'Status: 503 Service Unavailable\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n{"error":"not_ready"}\n'
fi
