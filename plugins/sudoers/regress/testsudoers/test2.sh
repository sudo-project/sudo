#!/bin/sh
#
# Verify that all command tags are parsed OK.
# See http://www.sudo.ws/bugs/show_bug.cgi?id=437
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
