#!/usr/bin/perl -p

BEGIN {
    %tags = ( 'a', 'BA', 'c', 'LC', 'r', 'SL', 't', 'SL');
    $cond = -1;
}

# Initialize the numeric register we use for conditionals
if ($cond == -1) {
    $_ = ".nr SL \@SEMAN\@\n.nr BA \@BAMAN\@\n.nr LC \@LCMAN\@\n.nr PT \@password_timeout\@\n.\\\"\n$_";
    $cond = 0;
}

# Add conditionals
if (/^\.IP.*-([acrt])/) {
    $_ = ".if \\n($tags{$1} \\{\\\n$_";
    $cond = 1;
} elsif ($cond && /^\.(Sh|SS|IP|PP)/) {
    $_ = "\\}\n$_";
    $cond = 0;
}

if (/-a.*auth_type/) {
    $_ = ".if \\n($tags{'a'} $_";
} elsif (/(-c.*class.*\||login_cap)/) {
    $_ = ".if \\n($tags{'c'} $_";
} elsif (/-r.*role.*-t.*type/) {
    $_ = ".if \\n($tags{'r'} $_";
}

# Fix up broken pod2man formatting of F<@foo@/bar>
s/\\fI\\f(\(C)?I\@([^\@]*)\\fI\@/\\fI\@$2\@/g;

# Try to deal sensibly with password_timeout being set to 0 by default
s/([^ ]*\@password_timeout\@[^ ]* minutes.$)/\n.ie \\n(PT $1\n.el unlimited./;
