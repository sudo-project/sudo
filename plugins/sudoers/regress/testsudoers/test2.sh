#!/bin/sh
#
# Test #include facility
#

./testsudoers root id <<EOF
#include $TESTDIR/test2.inc
EOF
