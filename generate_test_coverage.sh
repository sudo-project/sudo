#! /bin/bash

# This script is meant as an example on how to generate test coverage information
# It is meant to be executed from an empty build directory like:
# Usage: <path to the script>/generate_test_coverage.sh [some extra configure options]

# Example:
# mkdir -p build
# cd build
# ../generate_test_coverage.sh --enable-python

script_dir=$(dirname "$0")
CONFIGURE=${CONFIGURE:-${script_dir}/configure}
LCOV=${LCOV:-lcov}
GENHTML=${GENHTML:-genhtml}

echo "Using configure: $CONFIGURE (Override with CONFIGURE environment variable)"
echo "Extra configure options: $@ (Override with script arguments)"
echo "Using lcov: $LCOV (Override with LCOV environment variable)"
echo "Using genhtml: $GENHTML (Override with GENHTML environment variable)"
echo

"$CONFIGURE" "$@" CFLAGS="--coverage -fprofile-arcs -ftest-coverage -O0" LDFLAGS="-lgcov"
make
make check
"${LCOV}" -c --directory . --output-file coverage.info --rc "geninfo_adjust_src_path = $PWD => $script_dir"
"${GENHTML}" coverage.info --output-directory test_coverage
echo "Test coverage can be found at: test_coverage/index.html"
