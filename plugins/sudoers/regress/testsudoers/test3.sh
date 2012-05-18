#!/bin/sh
#
# Test #include facility
#

./testsudoers -U `id -u` root id <<EOF
#includedir $TESTDIR/test3.d
EOF
