#!/bin/sh
# Fixed private official OpenWrt GNU timeout and musl closure. No global replacement.
exec /bin/busybox env -i LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin /tmp/leon-uplink-rescue-tools/lib/libc.so --library-path /tmp/leon-uplink-rescue-tools/lib /tmp/leon-uplink-rescue-tools/bin/timeout "$@"
