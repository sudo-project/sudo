#!/usr/bin/perl -p

BEGIN {
    $cond = -1;
}

# Initialize the numeric register we use for conditionals
if ($cond == -1) {
    $_ = ".nr SL \@SEMAN\@\n.nr BA \@BAMAN\@\n.nr LC \@LCMAN\@\n.\\\"\n$_";
    $cond = 0;
}

# Make SELinux_Spec conditional
if (/(.*)SELinux_Spec\? (.*)$/) {
    $_ = ".ie \\n(SL $_.el $1$2\n";
} elsif (/^(.*SELinux_Spec ::=)/) {
    $_ = ".if \\n(SL \\{\\\n$_";
} elsif (/^(.*Tag_Spec ::=)/) {
    $_ = "\\}\n$_";
}

if (/^\.S[Sh] "SELinux_Spec"/) {
    $_ = ".if \\n(SL \\{\\\n$_";
    $cond = 1;
} elsif (/^\.IP "(role|type)"/) {
    $_ = ".if \\n(SL \\{\\\n$_";
    $cond = 1;
} elsif (/^\.IP "use_loginclass"/) {
    $_ = ".if \\n(LC \\{\\\n$_";
    $cond = 1;
} elsif ($cond && /^\.(Sh|SS|IP|PP)/) {
    $_ = "\\}\n$_";
    $cond = 0;
}

# Fix up broken pod2man formatting of F<@foo@/bar>
s/\\fI\\f(\(C)?I\@([^\@]*)\\fI\@/\\fI\@$2\@/g;
s/\\f\(\CW\@([^\@]*)\\fR\@/\@$1\@/g;
#\f(CW@secure_path\fR@
