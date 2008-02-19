#!/usr/bin/perl -p

BEGIN {
    %tags = ( 'a', '@BAMAN@', 'c', '@LCMAN@', 'r', '@SEMAN@', 't', '@SEMAN@');
    $t = undef;
}
if (/^\.IP(.*-([acrt]))?/) {
    $t = $1 ? $tags{$2} : undef;
} elsif (/-a.*auth_type/) {
    $_ = $tags{'a'} . $_;
} elsif (/(-c.*class.*\||login_cap)/) {
    $_ = $tags{'c'} . $_;
} elsif (/-r.*role.*-t.*type/) {
    $_ = $tags{'r'} . $_;
}

# Fix up broken pod2man formatting of F<@foo@/bar>
s/\\fI\\f(\(C)?I\@([^\@]*)\\fI\@/\\fI\@$2\@/g;

# comment out Compile-time-specific lines in DESCRIPTION
if ($t) {
    $_ = $t . $_;
}
