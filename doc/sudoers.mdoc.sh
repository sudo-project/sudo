#!/bin/sh

: ${SED='sed'}

# Subsections to remove (SELinux and Solaris are adjacent)
RM_SS=
if [ X"$PSMAN" != X"1" ]; then
    if [ X"$SEMAN" != X"1" ]; then
	RM_SS='/^\.Ss SELinux_Spec/,/^\.Ss [^S]/{;/^\.Ss [^S][^o][^l]/!d;};'
    else
	RM_SS='/^\.Ss Solaris_Priv_Spec/,/^\.Ss/{;/^\.Ss [^S][^o][^l]/!d;};'
    fi
elif [ X"$SEMAN" != X"1" ]; then
	RM_SS='/^\.Ss SELinux_Spec/,/^\.Ss/{;/^\.Ss [^S][^E][^L]/!d;};'
fi

# BSD login class
LC_SED=
if [ X"$LCMAN" != X"1" ]; then
    LC_SED='/^On BSD systems/,/\.$/{;d;};/^\.It use_loginclass$/,/^\.It/{;/^\.It [^u][^s][^e][^_][^l]/!d;};'
fi

# Solaris PrivSpec
PS_SED=
if [ X"$PSMAN" != X"1" ]; then
    PS_SED='s/Solaris_Priv_Spec? //;/^Solaris_Priv_Spec ::=/{;N;d;};/^\.It limitprivs$/,/^\.It/{;/^\.It [^l][^i][^m][^i][^t]/!d;};/^\.It privs$/,/^\.It/{;/^\.It [^p][^r][^i][^v][^s]$/!d;};'
fi

# SELinux
SE_SED=
if [ X"$SEMAN" != X"1" ]; then
    SE_SED='s/SELinux_Spec? //;/^SELinux_Spec ::=/{;N;d;};/^\.It [rt][oy][lp]e$/,/^\.It/{;/^\.It [^rt][^oy][^lp][^e]$/!d;};'
fi

$SED -e "$SE_SED$PS_SED$LC_SED$RM_SS"
