#!/bin/sh
#
# Test #include facility
#

USER=`\ls -l $TESTDIR/test2.inc | awk '{print $3}'`
UID=`id -u $USER`
exec 2>&1
./testsudoers -U $UID root id <<EOF
#include $TESTDIR/test2.inc
EOF
