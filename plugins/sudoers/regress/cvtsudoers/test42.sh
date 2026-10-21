#!/bin/sh
#
# Test an LDIF attribute folded over more than two lines.
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -c "" -i ldif -b "ou=SUDOers,dc=sudo,dc=ws" -f sudoers <<EOF
dn: cn=millert,ou=SUDOers,dc=sudo,dc=ws
objectClass: top
objectClass: sudoRole
cn: millert
sudoUser: millert
sudoHost: ALL
sudoCommand: /usr/bin/sys
 temctl rest
 art httpd
sudoCommand: /usr/bin/ls

EOF
