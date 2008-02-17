#!/usr/bin/perl -p

BEGIN {
    $prepend = 0;
}
if (/-r.*role.*-t.*type/) {
    # comment out SELinux-specific line in SYNOPSIS
    s/^/\@SEMAN\@/;
} elsif (/^\.IP(.*-[rt])?/) {
    $prepend = defined($1);
}

# comment out SELinux-specific lines in DESCRIPTION
if ($prepend) {
    s/^/\@SEMAN\@/;
}
