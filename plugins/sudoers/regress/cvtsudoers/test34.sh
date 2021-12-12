#!/bin/sh
#
# Test cvtsudoers merge
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -f sudoers xerxes:${TESTDIR}/sudoers1 ${TESTDIR}/sudoers2 xyzzy:${TESTDIR}/sudoers3 2>/dev/null
