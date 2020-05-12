#!/bin/sh
echo 5 > /proc/sys/net/ipv4/neigh/default/gc_thresh1
for f in /proc/sys/net/ipv4/neigh/*/base_reachable_time ; do echo 30 > "$f" ; done
for f in /proc/sys/net/ipv4/neigh/*/gc_stale_time ; do echo 40 > "$f" ; done
echo 15 > /proc/sys/net/ipv4/neigh/default/gc_interval
