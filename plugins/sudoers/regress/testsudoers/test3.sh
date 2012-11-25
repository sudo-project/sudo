#!/bin/sh
#
# Test #include facility
#

USER=`\ls -l $TESTDIR/test2.inc | awk '{print $3}'`
MYUID=`id -u $USER`
exec 2>&1
./testsudoers -U $MYUID root id <<EOF
#includedir $TESTDIR/test3.d
EOF
