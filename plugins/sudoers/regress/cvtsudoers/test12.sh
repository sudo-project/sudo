#!/bin/sh
#
# Test that Aliases are removed when filtering by defaults type
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -c "" -f sudoers -d user $TESTDIR/sudoers.defs
