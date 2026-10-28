#!/bin/sh
#
# Verify that a Defaults>runas entry is applied based on the runas
# user even when a runas group the runas user is not a member of
# is specified with -g.
#

: ${TESTSUDOERS=testsudoers}

exec 2>&1

echo "Testing with runas user root:"
echo ""
$TESTSUDOERS -u root -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
Defaults:admin !authenticate
Defaults>root authenticate
admin ALL = (ALL:ALL) ALL
EOF

echo ""
echo "Testing with runas user root and runas group users:"
echo ""
$TESTSUDOERS -u root -g users -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
Defaults:admin !authenticate
Defaults>root authenticate
admin ALL = (ALL:ALL) ALL
EOF

exit 0
