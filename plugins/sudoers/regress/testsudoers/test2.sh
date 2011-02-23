#!/bin/sh
#
# Test quoted group names in sudoers.
# Note that a backslash is treated literally unless
# it is escaping a double quote.
#

WANT=${SRCDIR-.}/regress/testsudoers/test2.out
GOT=ts_test2.out
./testsudoers -d > $GOT <<EOF
"%:C/non UNIX 0 c" ALL=(ALL) ALL
"%:C/non\'UNIX\'1 c" ALL=(ALL) ALL
"%:C/non\"UNIX\"0 c" ALL=(ALL) ALL
"%:C/non_UNIX_0 c" ALL=(ALL) ALL
"%:C/non\'UNIX_3 c" ALL=(ALL) ALL
EOF

# Check results
if cmp $WANT $GOT >/dev/null; then
    echo "testsudoers 2: OK"
else
    echo "testsudoers 2: FAILED"
    diff $WANT $GOT
fi
