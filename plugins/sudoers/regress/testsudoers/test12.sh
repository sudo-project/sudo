#!/bin/sh
#
# Test sudoers file with multiple syntax errors
# The standard error output is dup'd to the standard output.
#

# Avoid warnings about memory leaks when there is a syntax error
ASAN_OPTIONS=detect_leaks=0; export ASAN_OPTIONS

echo "Testing sudoers with multiple syntax errors"
echo ""
./testsudoers -d <<EOF 2>&1 | sed 's/\(syntax error\), .*/\1/' 
User_Alias A1 = u1 u2 : A2 = u3, u4

millert ALL = /fail : foo

root ALL = ALL bar
EOF
