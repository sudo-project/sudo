#!/bin/sh
#
# Verify that a last match wins in a Runas_List.
# A negated user or group at the end takes precedence.
#

: ${VISUDO=visudo}

# Expect failure
$VISUDO -cf - <<-EOF || exit 0
	user1	ALL = sudoedit /etc/motd
	user1	ALL = sudoedit shadow
	user1	ALL = sudoedit /etc/motd shadow
	user1	ALL = sudoedit ^shadow$
	EOF

exit 1
