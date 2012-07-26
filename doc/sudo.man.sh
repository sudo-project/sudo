#!/bin/sh

: ${SED='sed'}

# BSD auth
BA_FLAG=""
BA_ITEM=""
if [ X"$BAMAN" != X"1" ]; then
    BA_FLAG=';/^\[\\fB\\-a\\fR\\ \\fIauth_type\\fR/d'
    BA_ITEM=';/^\\fB\\-a\\fR \\fItype\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# BSD login class
LC_FLAG=""
LC_ITEM=""
if [ X"$LCMAN" != X"1" ]; then
    LC_FLAG=';/^\[\\fB\\-c\\fR\\ \\fIclass\\fR/d'
    LC_ITEM=';/^\\fB\\-c\\fR \\fIclass\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# SELinux
SE_FLAG=""
SE_ITEM=""
if [ X"$SEMAN" != X"1" ]; then
    SE_FLAG=';/^\[\\fB\\-[rt]\\fR\\ \\fI[rt][oy][lp]e\\fR/d'
    SE_ITEM=';/^\\fB\\-[rt]\\fR \\fI[rt][oy][lp]e\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# Now put it all together and replace "0 minutes" with "unlimited"
$SED -e '/^\\fR0\\fR$/{;N;s/^\\fR0\\fR\nminutes\.$/unlimited./;}'"$BA_FLAG$LC_FLAG$SE_FLAG$BA_ITEM$LC_ITEM$SE_ITEM"
#!/bin/sh

: ${SED='sed'}

# BSD auth
BA_FLAG=""
BA_ITEM=""
if [ X"$BAMAN" != X"1" ]; then
    BA_FLAG=';/^\[\\fB\\-a\\fR\\ \\fIauth_type\\fR/d'
    BA_ITEM=';/^\\fB\\-a\\fR \\fItype\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# BSD login class
LC_FLAG=""
LC_ITEM=""
if [ X"$LCMAN" != X"1" ]; then
    LC_FLAG=';/^\[\\fB\\-c\\fR\\ \\fIclass\\fR/d'
    LC_ITEM=';/^\\fB\\-c\\fR \\fIclass\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# SELinux
SE_FLAG=""
SE_ITEM=""
if [ X"$SEMAN" != X"1" ]; then
    SE_FLAG=';/^\[\\fB\\-[rt]\\fR\\ \\fI[rt][oy][lp]e\\fR/d'
    SE_ITEM=';/^\\fB\\-[rt]\\fR \\fI[rt][oy][lp]e\\fR$/,/^\.TP 12n$/{;/^\.PD$/!d;}'
fi

# Now put it all together and replace "0 minutes" with "unlimited"
$SED -e '/^\\fR0\\fR$/{;N;s/^\\fR0\\fR\nminutes\.$/unlimited./;}'"$BA_FLAG$LC_FLAG$SE_FLAG$BA_ITEM$LC_ITEM$SE_ITEM"
