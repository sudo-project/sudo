#!/bin/sh
#
# Verify that all command tags are parsed OK.
# See http://www.sudo.ws/bugs/show_bug.cgi?id=437
#

WANT=${SRCDIR-.}/regress/visudo/test1.ok
GOT=vs_test1.out
./visudo -c -f- > $GOT <<EOF
"%:C/non UNIX 0 c" ALL=(ALL) ALL
"%:C/non\'UNIX\'1 c" ALL=(ALL) ALL
"%:C/non\"UNIX\"0 c" ALL=(ALL) ALL
"%:C/non_UNIX_0 c" ALL=(ALL) ALL
"%:C/non\'UNIX_3 c" ALL=(ALL) ALL
EOF

# Check results
if cmp $WANT $GOT >/dev/null; then
    echo "visudo 2: OK"
else
    echo "visudo 2: FAILED"
    diff $WANT $GOT
fi
