#!/bin/sh
# The idiot's guide to test gnu auto* crap.
rm -f lt*
touch PORTING
libtoolize -f -c
aclocal
autoheader -f
automake -a -f -c
autoconf -f
./configure
make distcheck
