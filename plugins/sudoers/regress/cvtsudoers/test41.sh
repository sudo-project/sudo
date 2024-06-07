#!/bin/sh
#
# Test behavior of undefined aliases using --expand-aliases in JSON output.
# https://github.com/sudo-project/sudo/issues/381
#

: ${CVTSUDOERS=cvtsudoers}

$CVTSUDOERS -c "" -f json -e <<EOF
User_Alias		CLI_USER = cli
Defaults:CLI_USR	!lecture

Host_Alias		SUN_HOST = sparc5
Defaults@SUN_HST	log_year

Cmnd_Alias		REBOOT = /sbin/halt, /sbin/reboot, /sbin/poweroff
Defaults!REBOT		!use_pty
EOF
