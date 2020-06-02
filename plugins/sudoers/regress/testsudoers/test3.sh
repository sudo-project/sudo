#!/bin/sh
#
# Test @includedir facility
#

parentdir="`echo $0 | sed 's:/[^/]*$::'`"
if [ -d "$parentdir" ]; then
	# make sure include file is owned by current user
	rm -rf "${parentdir}/test3.d"
	mkdir "${parentdir}/test3.d"
	cat >"${parentdir}/test3.d/root" <<-EOF
		root ALL = ALL
	EOF

	MYUID=`\ls -lnd $TESTDIR/test3.d | awk '{print $3}'`
	MYGID=`\ls -lnd $TESTDIR/test3.d | awk '{print $4}'`
	exec 2>&1

	echo "Testing @includedir of an unquoted path"
	echo ""
	./testsudoers -U $MYUID -G $MYGID root id <<-EOF
		@includedir $TESTDIR/test3.d
	EOF

	echo ""
	echo "Testing @includedir of a double-quoted path"
	echo ""
	./testsudoers -U $MYUID -G $MYGID root id <<-EOF
		@includedir "$TESTDIR/test3.d"
	EOF

	echo ""
	echo "Testing #includedir of an unquoted path"
	echo ""
	./testsudoers -U $MYUID -G $MYGID root id <<-EOF
		#includedir $TESTDIR/test3.d
	EOF

	echo ""
	echo "Testing #includedir of a double-quoted path"
	echo ""
	./testsudoers -U $MYUID -G $MYGID root id <<-EOF
		#includedir "$TESTDIR/test3.d"
	EOF

	rm -rf "${parentdir}/test3.d"
	exit 0
fi

echo "$0: unable to determine parent dir" 1>&2
exit 1
