#!/bin/sh
#
# Verify that an LDAP sudoNotBefore or sudoNotAfter value that cannot
# be parsed does not remove the time restriction.
#

: ${TESTSUDOERS=testsudoers}

exec 2>&1

for attr in "sudoNotAfter: 20200101000000.00Z" "sudoNotAfter: bogus" \
    "sudoNotBefore: bogus"; do
    $TESTSUDOERS -i ldif root /bin/sh <<-EOF
	dn: cn=root,ou=SUDOers,dc=sudo,dc=ws
	objectClass: top
	objectClass: sudoRole
	cn: root
	sudoUser: root
	sudoRunAs: ALL
	sudoHost: ALL
	sudoCommand: /bin/sh
	$attr
	EOF
    echo ""
done

exit 0
