#!/bin/sh
#
# Test @include with garbage after the path name
#

# Avoid warnings about memory leaks when there is a syntax error
ASAN_OPTIONS=detect_leaks=0; export ASAN_OPTIONS

MYUID=`\ls -ln $TESTDIR/test2.inc | awk '{print $3}'`
MYGID=`\ls -ln $TESTDIR/test2.inc | awk '{print $4}'`
exec 2>&1

echo "Testing @include with garbage after the path name"
echo ""
./testsudoers -U $MYUID -G $MYGID root id <<EOF
@include $TESTDIR/test2.inc womp womp
EOF

echo ""
echo "Testing #include with garbage after the path name"
echo ""
./testsudoers -U $MYUID -G $MYGID root id <<EOF
#include $TESTDIR/test2.inc womp womp
EOF

exit 0
