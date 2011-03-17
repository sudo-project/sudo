#!/bin/sh
#
# Test whitespace in User_List as part of a per-user Defaults entry
#

WANT=${SRCDIR-.}/regress/testsudoers/test3.ok
GOT=ts_test3.out
./testsudoers -d > $GOT <<EOF
User_Alias FOO = foo, bar
Defaults:FOO env_reset
Defaults:foo,bar env_reset
Defaults:foo,\ bar env_reset
Defaults:foo, bar env_reset
EOF

# Check results
if cmp $WANT $GOT >/dev/null; then
    echo "testsudoers 3: OK"
else
    echo "testsudoers 3: FAILED"
    diff $WANT $GOT
fi
