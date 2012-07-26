#!/bin/sh

: ${SED='sed'}

# BSD auth
BA_FLAG=""
BA_ITEM=""
if [ X"$BAMAN" != X"1" ]; then
    BA_FLAG='/^.*\n\.Op Fl a Ar auth_type/{;N;/^.*\n\.Ek$/d;};'
    BA_ITEM=';/^\.It Fl a Ar type/,/BSD authentication\.$/{;d;}'
fi

# BSD login class
LC_FLAG=""
LC_ITEM=""
if [ X"$LCMAN" != X"1" ]; then
    LC_FLAG='/^.*\n\.Op Fl c Ar class/{;N;/^.*\n\.Ek$/d;};'
    LC_ITEM=';/^\.It Fl c Ar class/,/BSD login classes\.$/{;d;};/^\.Xr login_cap 3 ,$/d'
fi

# SELinux
SE_FLAG=""
SE_ITEM=""
if [ X"$SEMAN" != X"1" ]; then
    SE_FLAG='/^.*\n\.Op Fl r Ar role/{;N;/^.*\n\.Ek$/d;};/^.*\n\.Op Fl t Ar type/{;N;/^.*\n\.Ek$/d;};'
    SE_ITEM=';/^\.It Fl r Ar role/,/newline character\.$/{;d;};/^\.It Fl t Ar type/,/specified role\.$/{;d;}'
fi

# Unsupported flags must be removed together
RM_FLAGS=""
if [ -n "$BA_FLAG$LC_FLAG$SE_FLAG" ]; then
    RM_FLAGS=";/^\.Bk -words\$/{;N;$BA_FLAG$LC_FLAG$SE_FLAG}"
fi

# Now put it all together and replace "0 minutes" with "unlimited"
$SED -e '/^\.Li 0$/{;N;s/^\.Li 0\nminutes\.$/unlimited./;}'"$RM_FLAGS$BA_ITEM$LC_ITEM$SE_ITEM"
#!/bin/sh

: ${SED='sed'}

# BSD auth
BA_FLAG=""
BA_ITEM=""
if [ X"$BAMAN" != X"1" ]; then
    BA_FLAG='/^.*\n\.Op Fl a Ar auth_type/{;N;/^.*\n\.Ek$/d;};'
    BA_ITEM=';/^\.It Fl a Ar type/,/BSD authentication\.$/{;d;}'
fi

# BSD login class
LC_FLAG=""
LC_ITEM=""
if [ X"$LCMAN" != X"1" ]; then
    LC_FLAG='/^.*\n\.Op Fl c Ar class/{;N;/^.*\n\.Ek$/d;};'
    LC_ITEM=';/^\.It Fl c Ar class/,/BSD login classes\.$/{;d;};/^\.Xr login_cap 3 ,$/d'
fi

# SELinux
SE_FLAG=""
SE_ITEM=""
if [ X"$SEMAN" != X"1" ]; then
    SE_FLAG='/^.*\n\.Op Fl r Ar role/{;N;/^.*\n\.Ek$/d;};/^.*\n\.Op Fl t Ar type/{;N;/^.*\n\.Ek$/d;};'
    SE_ITEM=';/^\.It Fl r Ar role/,/newline character\.$/{;d;};/^\.It Fl t Ar type/,/specified role\.$/{;d;}'
fi

# Unsupported flags must be removed together
RM_FLAGS=""
if [ -n "$BA_FLAG$LC_FLAG$SE_FLAG" ]; then
    RM_FLAGS=";/^\.Bk -words\$/{;N;$BA_FLAG$LC_FLAG$SE_FLAG}"
fi

# Now put it all together and replace "0 minutes" with "unlimited"
$SED -e '/^\.Li 0$/{;N;s/^\.Li 0\nminutes\.$/unlimited./;}'"$RM_FLAGS$BA_ITEM$LC_ITEM$SE_ITEM"
