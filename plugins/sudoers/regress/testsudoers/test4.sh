#!/bin/sh
#
# Test sudoers owner check
#

exec 2>&1
./testsudoers -U 1 root id <<EOF
#include $TESTDIR/test2.inc
EOF

exit 0
