#!/usr/bin/perl -p

BEGIN {
    $t = undef;
}

if (/^\./) {
    if (/^\.I[PX].*use_loginclass/) {
	$t = '@LCMAN@';
    } elsif (/^\.I[PX].*(role|type)/) {
	$t = '@SEMAN@';
    } else {
	$t = undef;
    }
}

# Fix up broken pod2man formatting of F<@foo@/bar>
s/\\fI\\f(\(C)?I\@([^\@]*)\\fI\@/\\fI\@$2\@/g;

# Comment out Compile-time-specific lines in DESCRIPTION
if ($t) {
    $_ = $t . $_;
}
