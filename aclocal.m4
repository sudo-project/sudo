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
  echo checking for BSD compatible install
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
    AC_DEFINE(_PATH_SENDMAIL, "/usr/sbin/sendmail")
elif test -f "/usr/lib/sendmail"; then
    AC_DEFINE(_PATH_SENDMAIL, "/usr/lib/sendmail")
elif test -f "/usr/etc/sendmail"; then
    AC_DEFINE(_PATH_SENDMAIL, "/usr/etc/sendmail")
elif test -f "/usr/local/lib/sendmail"; then
    AC_DEFINE(_PATH_SENDMAIL, "/usr/local/lib/sendmail")
elif test -f "/usr/local/bin/sendmail"; then
    AC_DEFINE(_PATH_SENDMAIL, "/usr/local/bin/sendmail")
fi
])dnl
dnl
dnl check for vi
dnl
define(SUDO_PROG_VI,
[if test -f "/usr/bin/vi"; then
    AC_DEFINE(_PATH_VI, "/usr/bin/vi")
elif test -f "/usr/ucb/vi"; then
    AC_DEFINE(_PATH_VI, "/usr/ucb/vi")
elif test -f "/usr/local/bin/vi"; then
    AC_DEFINE(_PATH_VI, "/usr/local/bin/vi")
fi
])dnl
dnl
dnl checks for UNIX variants
dnl
dnl SUDO_AIX
dnl
define(SUDO_AIX,
[echo checking for AIX 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef _AIX
  yes
#endif
], AC_DEFINE(_ALL_SOURCE) [$1], [$2])
])dnl
dnl
dnl SUDO_HPUX
dnl
define(SUDO_HPUX,
[echo checking for HP-UX 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#if defined(hpux) || defined(__hpux)
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_DEC_OSF1
dnl
define(SUDO_DEC_OSF1,
[echo checking for DEC OSF/1 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef __alpha
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_LINUX
dnl
define(SUDO_LINUX,
[echo checking for linux
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#if defined(linux) || defined(__linux)
  yes
#endif
], [$1], [$2])
])dnl
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
], AC_DEFINE(_CONVEX_SOURCE) [$1], [$2])
])dnl
dnl
dnl SUDO_KSR
dnl
define(SUDO_KSR,
[echo checking for KSROS 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef __ksr__
  yes
#endif
], INSTALL=/usr/sbin/install [$1], [$2])
])dnl
dnl
dnl SUDO_SUNOS
dnl
define(SUDO_SUNOS,
[echo checking for SunOS 4.x
AC_BEFORE([$0], [AC_PROGRAM_CHECK])
if test -n "$UNAMEPROG"; then
    if test "`$UNAMEPROG -s`" = "SunOS"; then
	SUNOS="`uname -r | cut -c1`"
	if test "$SUNOS" -le 4; then
	    :
	    [$1]
	else
	    :
	    [$2]
	fi
    else
	:
	[$2]
    fi
fi
])dnl
dnl
dnl SUDO_SOLARIS
dnl
define(SUDO_SOLARIS,
[echo checking for Solaris
AC_BEFORE([$0], [AC_PROGRAM_CHECK])
if test -n "$UNAMEPROG"; then
    if test "`$UNAMEPROG -s`" = "SunOS"; then
	SUNOS="`uname -r | cut -c1`"
	if test "$SUNOS" -ge 5; then
	    AC_DEFINE(SVR4)
	    [$1]
	else
	    :
	    [$2]
	fi
    else
	:
	[$2]
    fi
fi
])dnl
dnl
dnl SUDO_IRIX
dnl
define(SUDO_IRIX,
[echo checking for Irix
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[
#ifdef sgi
  yes
#endif
], AC_DEFINE(_BSD_COMPAT) AC_DEFINE(RETSIGTYPE, int) AC_DEFINE(STDC_HEADERS) [$1], [$2])
])dnl
