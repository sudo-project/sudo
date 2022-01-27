#!/bin/sh
#
# Test cvtsudoers merge
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -f sudoers -l /dev/null xerxes:${TESTDIR}/sudoers1 ${TESTDIR}/sudoers2 xyzzy:${TESTDIR}/sudoers3
