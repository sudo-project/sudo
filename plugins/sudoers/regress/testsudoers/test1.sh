#!/bin/sh
#
# Test for NULL dereference with "sudo -g group" when the sudoers rule
# has no runas user or group listed.
# This is RedHat bug Bug 667103.
#

./testsudoers -g wheel root id <<EOF
root ALL = ALL
EOF
