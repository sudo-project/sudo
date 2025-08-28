#!/bin/sh
#
# Verify that a user is allowed to run commands with only the group changed.
#

: ${TESTSUDOERS=testsudoers}

exec 2>&1

$TESTSUDOERS -u admin -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (admin:staff) /bin/ls
EOF

$TESTSUDOERS -u admin -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (:staff) /bin/ls
EOF

$TESTSUDOERS -u admin -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (root:staff) /bin/ls
EOF

$TESTSUDOERS -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (admin:staff) /bin/ls
EOF

$TESTSUDOERS -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (:staff) /bin/ls
EOF

$TESTSUDOERS -g staff -p ${TESTDIR}/passwd -P ${TESTDIR}/group \
    admin /bin/ls <<'EOF'
admin ALL = (root:staff) /bin/ls
EOF

exit 0
