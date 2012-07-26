#!/bin/sh

: ${SED='sed'}

# Subsections to remove (SELinux and Solaris are adjacent)
RM_SS=
if [ X"$PSMAN" != X"1" ]; then
    if [ X"$SEMAN" != X"1" ]; then
	RM_SS='/^\.SS "SELinux_Spec"/,/^\.SS "[^S]/{;/^\.SS "[^S][^o][^l]/!d;};'
    else
	RM_SS='/^\.SS "Solaris_Priv_Spec"/,/^\.SS/{;/^\.SS "[^S][^o][^l]/!d;};'
    fi
elif [ X"$SEMAN" != X"1" ]; then
	RM_SS='/^\.SS "SELinux_Spec"/,/^\.SS/{;/^\.SS "[^S][^E][^L]/!d;};'
fi

# BSD login class
LC_SED=
if [ X"$LCMAN" != X"1" ]; then
    LC_SED='/^On BSD systems/,/\.$/{;d;};/^use_loginclass$/,/^\.TP 18n$/{;/^\.PD$/!d;};'
fi

# Solaris PrivSpec
PS_SED=
if [ X"$PSMAN" != X"1" ]; then
    PS_SED='s/Solaris_Priv_Spec? //;/^Solaris_Priv_Spec ::=/{;N;d;};/^l*i*m*i*t*privs$/,/^\.TP 18n$/{;/^\.PD$/!d;};'
fi

# SELinux
SE_SED=
if [ X"$SEMAN" != X"1" ]; then
    SE_SED='s/SELinux_Spec? //;/^SELinux_Spec ::=/{;N;d;};/^[rt][oy][lp]e$/,/^\.TP 18n$/{;/^\.PD$/!d;};'
fi

$SED -e "$SE_SED$PS_SED$LC_SED$RM_SS"
