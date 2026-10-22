#!/bin/sh
#
# Test that sudoUser lists differing only in case are not merged
# but sudoHost lists differing only in case are.
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -c "" -i ldif -b "ou=SUDOers,dc=sudo,dc=ws" -f sudoers <<EOF
dn: cn=role1,ou=SUDOers,dc=sudo,dc=ws
objectClass: sudoRole
cn: role1
sudoUser: Alice
sudoHost: WebServer
sudoCommand: /usr/bin/id

dn: cn=role2,ou=SUDOers,dc=sudo,dc=ws
objectClass: sudoRole
cn: role2
sudoUser: alice
sudoHost: webserver
sudoCommand: /bin/sh

EOF
