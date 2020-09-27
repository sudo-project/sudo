#!/bin/sh
#
# Test entries with no trailing newline.
#

exec 2>&1

echo ""
echo "Testing user privilege without a newline"
echo ""
printf "millert ALL = ALL" | ./testsudoers -d

echo ""
echo "Testing alias without a newline"
echo ""
printf "Cmnd_Alias FOO=/bin/bar" | ./testsudoers -d

echo ""
echo "Testing Defaults without a newline"
echo ""
printf "Defaults log_output" | ./testsudoers -d

exit 0
