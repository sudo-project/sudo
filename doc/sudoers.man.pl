#!/usr/bin/perl -p

BEGIN {
    $cond = -1;
}

# Initialize the numeric registers we use for conditionals
if ($cond == -1) {
    $prefix = "";
    $prefix = "$prefix.nr BA \@BAMAN\@\n";
    $prefix = "$prefix.nr LC \@LCMAN\@\n";
    $prefix = "$prefix.nr PS \@PSMAN\@\n";
    $prefix = "$prefix.nr SL \@SEMAN\@\n";
    $_ = "$prefix.\\\"\n$_";
    $cond = 0;
}

# Make SELinux_Spec and Solaris_Priv_Spec conditional
if (/(.*) SELinux_Spec\? Solaris_Priv_Spec(.*)$/) {
    $_ = "$1\\*(S+$2\n";
    $prefix = "";
    $prefix = "$prefix.ds S+\n";
    $prefix = "$prefix.if \\n(SL .as S+ \" SELinux_Spec?\n";
    $prefix = "$prefix.if \\n(PS .as S+ \" Solaris_Priv_Spec?\n";
    $_ = "$prefix$_";
} elsif (/^(.*SELinux_Spec ::=)/) {
    $_ = ".if \\n(SL \\{\\\n$_";
} elsif (/^(.*Solaris_Priv_Spec ::=)/) {
    $_ = "\\}\n.if \\n(PS \\{\\\n$_";
} elsif (/^(.*Tag_Spec ::=)/) {
    $_ = "\\}\n$_";
}

if (/^\.(Sh|SS|IP|PP)/) {
    $prefix = $cond ? "\\}\n" : "";
    $cond = 0;
}
if (/^\.S[Sh] "SELinux_Spec"/) {
    $_ = "$prefix.if \\n(SL \\{\\\n$_";
    $cond = 1;
} elsif (/^\.IP "(role|type)"/) {
    $_ = "$prefix.if \\n(SL \\{\\\n$_";
    $cond = 1;
} elsif (/^\.S[Sh] "Solaris_Priv_Spec"/) {
    $_ = "$prefix.if \\n(PS \\{\\\n$_";
    $cond = 1;
} elsif (/^\.IP "(privs|limitprivs)"/) {
    $_ = "$prefix.if \\n(PS \\{\\\n$_";
    $cond = 1;
} elsif (/^\.IP "use_loginclass"/) {
    $_ = "$prefix.if \\n(LC \\{\\\n$_";
    $cond = 1;
} elsif (/^\.(Sh|SS|IP|PP)/) {
    $_ = "$prefix$_";
}

# Fix up broken pod2man formatting of F<@foo@/bar>
s/\\fI\\f(\(C)?I\@([^\@]*)\\fI\@/\\fI\@$2\@/g;
s/\\f\(\CW\@([^\@]*)\\fR\@/\@$1\@/g;
#\f(CW@secure_path\fR@
