#!/bin/sh
#
# Test for NULL dereference with "sudo -g group" when the sudoers rule
# has no runas user or group listed.
# This is RedHat bug Bug 667103.
#

WANT=${SRCDIR-.}/regress/testsudoers/test1.ok
GOT=ts_test1.out
./testsudoers -g wheel root id > $GOT <<EOF
root ALL = ALL
EOF

# Check results
if cmp $WANT $GOT >/dev/null; then
    echo "testsudoers 1: OK"
else
    echo "testsudoers 1: FAILED"
    diff $WANT $GOT
fi
