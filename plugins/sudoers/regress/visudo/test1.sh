#!/bin/sh
#
# Verify that all command tags are parsed OK.
# See http://www.sudo.ws/bugs/show_bug.cgi?id=437
#

WANT=${SRCDIR-.}/regress/visudo/test1.ok
GOT=vs_test1.out
./visudo -c -f- > $GOT <<EOF
user1 ALL = LOG_INPUT: LOG_OUTPUT: /usr/bin/su -:\
      ALL = NOLOG_INPUT: NOLOG_OUTPUT: /usr/bin/id
user2 ALL = NOPASSWD: NOEXEC: SETENV: /usr/bin/vi:\
      ALL = PASSWD: EXEC: NOSETENV: /usr/bin/echo
EOF

# Check results
if cmp $WANT $GOT >/dev/null; then
    echo "visudo 1: OK"
else
    echo "visudo 1: FAILED"
    diff $WANT $GOT
fi
