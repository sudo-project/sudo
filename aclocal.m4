dnl Local m4 macors for autoconf (used by sudo)
dnl
dnl checks for programs
dnl
define(SUDO_PROG_INSTALL,
[# Make sure to not get the incompatible SysV /etc/install, /sbin/install
# and /usr/sbin/install, which might be in PATH before a BSD-like install,
# or the SunOS /usr/etc/install directory, or the AIX /bin/install,
# or the AFS install, which mishandles nonexistent args, or
# /usr/ucb/install on SVR4, which tries to use the nonexistent group
# `staff'.  On most BSDish systems install is in /usr/bin, not /usr/ucb
# anyway.  Sigh.  We can always use the installbsd in $srcdir.
if test "z${INSTALL}" = "z" ; then
  echo checking for BSD compatible install...
  savepath="$PATH"
  PATH="${PATH}:${srcdir}"
  IFS="${IFS= 	}"; saveifs="$IFS"; IFS="${IFS}:"
  for dir in $PATH; do
    test -z "$dir" && dir=.
    case $dir in
    /sbin|/etc|/usr/sbin|/usr/etc|/usr/afsws/bin|/usr/ucb) ;;
    *)
      if test -f $dir/installbsd; then
	INSTALL="$dir/installbsd -c" # OSF1
	INSTALL_PROGRAM='$(INSTALL)'
	INSTALL_DATA='$(INSTALL) -m 644'
	break
      fi
      if test -f $dir/install; then
	if grep dspmsg $dir/install >/dev/null 2>&1; then
	  : # AIX
	else
	  INSTALL="$dir/install -c"
	  INSTALL_PROGRAM='$(INSTALL)'
	  INSTALL_DATA='$(INSTALL) -m 644'
	  break
	fi
      fi
      ;;
    esac
  done
  IFS="$saveifs"
  PATH="$savepath"
fi
INSTALL=${INSTALL-cp}
AC_SUBST(INSTALL)dnl
test -n "$verbose" && echo "	setting INSTALL to $INSTALL"
INSTALL_PROGRAM=${INSTALL_PROGRAM-'$(INSTALL)'}
AC_SUBST(INSTALL_PROGRAM)dnl
test -n "$verbose" && echo "	setting INSTALL_PROGRAM to $INSTALL_PROGRAM"
INSTALL_DATA=${INSTALL_DATA-'$(INSTALL)'}
AC_SUBST(INSTALL_DATA)dnl
test -n "$verbose" && echo "	setting INSTALL_DATA to $INSTALL_DATA"
])dnl
dnl
dnl check for sendmail
dnl
define(SUDO_PROG_SENDMAIL,
[if test -f "/usr/sbin/sendmail"; then
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/sbin/sendmail")
elif test -f "/usr/lib/sendmail"; then
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/lib/sendmail")
elif test -f "/usr/etc/sendmail"; then
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/etc/sendmail")
elif test -f "/usr/local/lib/sendmail"; then
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/local/lib/sendmail")
elif test -f "/usr/local/bin/sendmail"; then
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/local/bin/sendmail")
fi
])dnl
dnl
dnl check for vi
dnl
define(SUDO_PROG_VI,
[if test -f "/usr/bin/vi"; then
    AC_DEFINE(_SUDO_PATH_VI, "/usr/bin/vi")
elif test -f "/usr/ucb/vi"; then
    AC_DEFINE(_SUDO_PATH_VI, "/usr/ucb/vi")
elif test -f "/usr/local/bin/vi"; then
    AC_DEFINE(_SUDO_PATH_VI, "/usr/local/bin/vi")
fi
])dnl
dnl
dnl check for pwd
dnl
define(SUDO_PROG_PWD,
[if test -f "/usr/bin/pwd"; then
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/bin/pwd")
elif test -f "/bin/pwd"; then
    AC_DEFINE(_SUDO_PATH_PWD, "/bin/pwd")
elif test -f "/usr/ucb/pwd"; then
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/ucb/pwd")
elif test -f "/usr/sbin/pwd"; then
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/sbin/pwd")
fi
])dnl
dnl
dnl check for mv
dnl
define(SUDO_PROG_MV,
[if test -f "/usr/bin/mv"; then
    AC_DEFINE(_SUDO_PATH_MV, "/usr/bin/mv")
elif test -f "/bin/mv"; then
    AC_DEFINE(_SUDO_PATH_MV, "/bin/mv")
elif test -f "/usr/ucb/mv"; then
    AC_DEFINE(_SUDO_PATH_MV, "/usr/ucb/mv")
elif test -f "/usr/sbin/mv"; then
    AC_DEFINE(_SUDO_PATH_MV, "/usr/sbin/mv")
fi
])dnl
dnl
dnl Check for ssize_t declation
dnl
define(SUDO_SSIZE_T,
[AC_CHECKING(for ssize_t in sys/types.h)
AC_HEADER_EGREP(ssize_t, sys/types.h, , AC_DEFINE(ssize_t, int))])dnl
dnl
dnl check for known UNIX variants
dnl XXX - check to see that uname was checked first
dnl
define(SUDO_OSTYPE,
AC_BEFORE([$0], [AC_PROGRAM_CHECK])
[echo trying to figure out what OS you are running...
OS="unknown"
OSREV=0
if test -n "$UNAMEPROG"; then
    echo "checking OS based on uname(1)"
    OS=`$UNAMEPROG -s`
    # this is yucky but we want to make sure $OSREV is an int...
    OSREV=`$UNAMEPROG -r | $SEDPROG -e 's/^[[ \.0A-z]]*//' -e 's/\..*//'`

    if test "$OS" = "SunOS" -a "$OSREV" -ge 5 ; then
	OS="solaris"
    fi
else
    if test -z "$OS"; then
	SUDO_CONVEX(OS="convex")
    fi
    if test -z "$OS"; then
	SUDO_MTXINU(OS="mtxinu")
    fi
    if test -z "$OS"; then
	SUDO_NEXT(OS="NeXT")
    fi
    if test -z "$OS"; then
	SUDO_BSD(OS="bsd")
    fi
    if test -z "$OS"; then
	OS="unknown"
    fi
fi
])dnl
dnl
dnl checks for UNIX variants that lack uname
dnl
dnl SUDO_CONVEX
dnl
define(SUDO_CONVEX,
[echo checking for ConvexOS 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#if defined(__convex__) || defined(convex)
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_MTXINU
dnl
define(SUDO_MTXINU,
[echo checking for MORE/BSD
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#include <sys/param.h>
#ifdef MORE_BSD
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_NEXT
dnl
define(SUDO_NEXT,
[echo checking for NeXTstep 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef NeXT
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_BSD
dnl
define(SUDO_BSD,
[echo checking for BSD 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#include <sys/param.h>
#ifdef BSD
  yes
#endif
], [$1], [$2])
])dnl
