#!/usr/bin/env perl
#
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2017, 2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
# The goal is to emulate "hg log --template=changelog" via perl format.

use Getopt::Std;
use Text::Wrap;
use strict;
use warnings;

# Git log format: author date, author name, author email
#                 abbreviated commit hash
#		  raw commit body
my $format="%ad  %aN  <%aE>%n%h%n%B%n";

# Parse options and build up "git log" command
my @cmd = ( "git" );
my %opts;
getopts('mR:', \%opts);
push(@cmd, "--git-dir", $opts{"R"}) if exists $opts{"R"};
push(@cmd, "log", "--log-size", "--name-only", "--date=short", "--format=$format", @ARGV);

open(LOG, '-|', @cmd) || die "$0: unable to run git log: $!";

my $hash;
my $body;
my @files;
my $key_date = "";
my $log_size = 0;
my @lines;
my $hash_link = "https://git.sudo.ws/sudo/commit/?id=";

# Wrap like "hg log --template=changelog"
$Text::Wrap::columns = 77;
# Don't preserve tabs
$Text::Wrap::unexpand = 0;

while (<LOG>) {
    chomp;
    if (/^log size (\d+)$/) {
	$log_size = $1;

	# Print previous entry if there is one
	print_entry($hash, $body, @files) if defined($hash);

	# Init new entry
	undef $hash;
	undef $body;
	undef @files;
	undef @lines;

	# Read entry and split on newlines
	read(LOG, my $buf, $log_size) ||
	    die "$0: unable to read $log_size bytes: $!\n";
	@lines = split(/\r?\n/, $buf);

	# Check for continued entry (duplicate Date + Author)
	$_ = shift(@lines);
	# Strip author email address for markdown
	s/\s*<[^>]+>$// if exists $opts{'m'};

	if ($_ ne $key_date) {
	    # New entry
	    print "$_\n\n";
	    $key_date = $_;
	}

	# Hash comes first
	$hash = shift(@lines);

	# Commit message body (multi-line)
	my $sep = "";
	foreach (@lines) {
	    last if $_ eq "--HG--";
	    if ($_ eq "") {
		$sep = "\n\n";
		next;
	    }
	    s/^\s+//;
	    s/\s+$//;
	    $body .= ${sep} . $_;
	    $sep = " ";
	}
    } else {
	# Not a log entry, must be the file list
	push(@files, $_) unless $_ eq "";
    }
}

# Print the last entry
print_entry($hash, $body, @files) if defined($hash);

exit(0);

sub print_entry
{
    if (exists $opts{'m'}) {
	print_entry_markdown(@_);
    } else {
	print_entry_plain(@_);
    }
}

sub print_entry_plain
{
    my $hash = shift;
    my $body = shift;
    my $files = "* " . join(", ", @_) . ":";

    print wrap("\t", "\t", $files) . "\n";
    print fill("\t", "\t", $body) . "\n";
    print "\t[$hash]\n\n";
}

sub print_entry_markdown
{
    my $hash = shift;
    my $body = shift;
    my $files = ": * " . join(", ", @_) . ":  ";

    # Obfuscate email addresses in body
    $body =~ s/([^@ ]+@)[\w\.-]+\.(com|org|edu|ws|io)/$1.../g;

    # Escape email chars in body
    $body =~ s/([@<>])/\\$1/g;

    # Expand GitHub issue and bugzilla links
    $body =~ s@(GitHub issue #)(\d+)@[$1$2](https://github.com/sudo-project/sudo/issues/$2)@;
    $body =~ s@(Bug #)(\d+)@[$1$2](https://bugzilla.sudo.ws/show_bug.cgi?id=$2)@;

    print wrap("", "    ", $files) . "\n";
    print fill("    ", "    ", $body) . "\n";
    print "    [[${hash}]](${hash_link}${hash})\n\n";
}
