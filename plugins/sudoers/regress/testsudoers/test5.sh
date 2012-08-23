#!/bin/sh
#
# Test sudoers file mode check
#

# Create test file
TESTFILE=`pwd`/regress/testsudoers/test5.inc
cat >$TESTFILE <<EOF
root ALL = ALL
EOF

USER=`\ls -l $TESTFILE | awk '{print $3}'`
UID=`id -u $USER`
exec 2>&1

# Test world writable
chmod 666 $TESTFILE
./testsudoers -U $UID root id <<EOF
#include $TESTFILE
EOF

# Test group writable
chmod 664 $TESTFILE
./testsudoers -U $UID -G 1 root id <<EOF
#include $TESTFILE
EOF

rm -f $TESTFILE
