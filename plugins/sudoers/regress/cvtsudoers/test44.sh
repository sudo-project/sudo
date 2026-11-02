#!/bin/sh
#
# Test CSV output of log tags, boolean options and aliases
# when there are no Defaults settings.
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -c "" -f csv <<EOF
User_Alias ADMINS = alice
ADMINS ALL = (root) NOLOG_INPUT: /bin/ls
bob ALL = (root) NOLOG_OUTPUT: /bin/cat
carol ALL = (root) LOG_INPUT: /bin/date
EOF

$CVTSUDOERS -c "" -i ldif -b "ou=SUDOers,dc=sudo,dc=ws" -f csv <<EOF
dn: cn=role1,ou=SUDOers,dc=sudo,dc=ws
objectClass: sudoRole
cn: role1
sudoUser: alice
sudoHost: ALL
sudoCommand: /bin/ls
sudoOption: env_reset
sudoOption: !requiretty

EOF
