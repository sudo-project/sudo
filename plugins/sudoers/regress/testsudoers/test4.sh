#!/bin/sh
#
# Test sudoers owner check
#

: ${TESTSUDOERS=testsudoers}

# Avoid warnings about memory leaks when there is a syntax error
ASAN_OPTIONS=detect_leaks=0; export ASAN_OPTIONS

exec 2>&1
$TESTSUDOERS -U 1 root id <<EOF
@include $TESTDIR/test2.inc
EOF

exit 0
