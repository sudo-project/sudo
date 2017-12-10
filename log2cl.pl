#!/usr/bin/env perl
#
# Copyright (c) 2017 Todd C. Miller <Todd.Miller@sudo.ws>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Simple script to massage "git log" output into a GNU style ChangeLog.
# The goal is to emulate "hg log --style=changelog" via perl format.

use warnings;

my $format="%ad  %aN  <%aE>%n%h%n%B%nFILES:";
my @cmd = ("git", "log", "--log-size", "--name-only", "--date=short", "--format=$format", @ARGV);
open(LOG, '-|', @cmd) || die "$0: unable to run git log: $!";

my $hash;
my $body;
my @files;
my $key_date = "";
my $log_size = 0;
my $state = 0;

while (<LOG>) {
    chomp;
    if (/^log size (\d+)$/) {
	# XXX - should use log_size to make sure we get the entire entry
	$log_size = $1;

	# Print previous entry if there is one
	print_entry($hash, $body, @files) if defined($hash);

	# Init new entry
	$state = 1;
	undef $hash;
	undef $body;
	undef @files;

	# Check for continued entry
	$_ = <LOG>;
	last unless defined($_);
	chomp;
	if ($_ ne $key_date) {
	    # New entry
	    print "$_\n\n";
	    $key_date = $_;
	}
    } elsif (/^FILES:$/) {
	$state = 3;
    } else {
	if ($state == 1) {
	    # hash
	    $hash = $_;
	    $state++;
	} elsif ($state == 2) {
	    # multi-line message body
	    if (defined($body)) {
		$_ = "\r" if $_ eq "";
		$body .= " $_";
	    } else {
		$body = $_;
	    }
	} elsif ($state == 3) {
	    # file list
	    push(@files, $_) unless $_ eq "";
	} else {
	    warn "unexpected state $state for $_\n";
	}
    }
}

# Print the last entry
print_entry($hash, $body, @files) if defined($hash);

exit(0);

sub print_entry
{
    my $hash = '[' . shift . ']';
    my $body = shift;
    my $files = "* " . join(", ", @_) . ":";

    local $= = 9999;	# to silence warning (hack)

    format =
	^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ~~
	$files
	^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ~~
	$body
	@*
	$hash

.
    write;
}
