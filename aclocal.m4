dnl Local m4 macors for autoconf (used by sudo)
dnl
dnl checks for programs
dnl
define(SUDO_PROG_INSTALL,
[# Make sure to not get the incompatible SysV /etc/install and
# /usr/sbin/install, which might be in PATH before a BSD-like install,
# or the SunOS /usr/etc/install directory, or the AIX /bin/install,
# or the AFS install, which mishandles nonexistent args, or
# /usr/ucb/install on SVR4, which tries to use the nonexistent group
# `staff'.  On most BSDish systems install is in /usr/bin, not /usr/ucb
# anyway.  Sigh.  We can always use the installbsd in $srcdir.
if test "z${INSTALL}" = "z" ; then
  echo checking for install
  savepath="$PATH"
  PATH="${PATH}:${srcdir}"
  IFS="${IFS= 	}"; saveifs="$IFS"; IFS="${IFS}:"
  for dir in $PATH; do
    test -z "$dir" && dir=.
    case $dir in
    /etc|/usr/sbin|/usr/etc|/usr/afsws/bin|/usr/ucb) ;;
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
    SENDMAIL="/usr/sbin/sendmail"
elif test -f "/usr/lib/sendmail"; then
    SENDMAIL="/usr/lib/sendmail"
elif test -f "/usr/etc/sendmail"; then
    SENDMAIL="/usr/etc/sendmail"
elif test -f "/usr/local/lib/sendmail"; then
    SENDMAIL="/usr/local/lib/sendmail"
elif test -f "/usr/local/bin/sendmail"; then
    SENDMAIL="/usr/local/bin/sendmail"
else
    SENDMAIL=""
fi
])dnl
dnl
dnl checks for UNIX variants
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
define(SUDO_CONVEX,
[echo checking for ConvexOS 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef convex
  yes
#endif
], AC_DEFINE(_CONVEX_SOURCE) [$1], [$2])
])dnl
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
define(SUDO_SUNOS,
[echo checking for SunOS
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_HEADER_EGREP])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[
#include <sys/param.h>
#if defined(sun) && !defined(BSD)
  yes
#endif
], [$1], [$2])
])dnl
dnl
