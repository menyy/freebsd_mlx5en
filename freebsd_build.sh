#!/bin/sh
#Uncomment this line to enable TurboLRO
#LRO="HAVE_TURBO_LRO=YES"
SRC="$1"
[ -z "$SRC" ] && (
SRC="/usr/src"
)
echo "The FreeBSD source tree is at $SRC ..."
bmake -m $SRC/share/mk SYSDIR=$SRC/sys -C freebsd/modules $LRO generate
bmake -m $SRC/share/mk SYSDIR=$SRC/sys -C freebsd/modules $LRO clean cleandepend
bmake -m $SRC/share/mk SYSDIR=$SRC/sys -C freebsd/modules $LRO depend
bmake -m $SRC/share/mk SYSDIR=$SRC/sys -C freebsd/modules $LRO all -j12
bmake -m $SRC/share/mk SYSDIR=$SRC/sys -C freebsd/modules $LRO install

