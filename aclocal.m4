dnl Local m4 macors for autoconf (used by sudo)
dnl
dnl checks for programs
dnl
dnl
dnl check for sendmail
dnl
AC_DEFUN(SUDO_PROG_SENDMAIL, [AC_MSG_CHECKING(checking for sendmail)
if test -f "/usr/sbin/sendmail"; then
    AC_MSG_RESULT(/usr/sbin/sendmail)
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/sbin/sendmail")
elif test -f "/usr/lib/sendmail"; then
    AC_MSG_RESULT(/usr/lib/sendmail)
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/lib/sendmail")
elif test -f "/usr/etc/sendmail"; then
    AC_MSG_RESULT(/usr/etc/sendmail)
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/etc/sendmail")
elif test -f "/usr/local/lib/sendmail"; then
    AC_MSG_RESULT(/usr/local/lib/sendmail)
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/local/lib/sendmail")
elif test -f "/usr/local/bin/sendmail"; then
    AC_MSG_RESULT(/usr/local/bin/sendmail)
    AC_DEFINE(_SUDO_PATH_SENDMAIL, "/usr/local/bin/sendmail")
else
    AC_MSG_RESULT(not found)
fi
])dnl
dnl
dnl check for vi
dnl
AC_DEFUN(SUDO_PROG_VI, [AC_MSG_CHECKING(checking for vi)
if test -f "/usr/bin/vi"; then
    AC_MSG_RESULT(/usr/bin/vi)
    AC_DEFINE(_SUDO_PATH_VI, "/usr/bin/vi")
elif test -f "/usr/ucb/vi"; then
    AC_MSG_RESULT(/usr/ucb/vi)
    AC_DEFINE(_SUDO_PATH_VI, "/usr/ucb/vi")
elif test -f "/usr/bsd/vi"; then
    AC_MSG_RESULT(/usr/bsd/vi)
    AC_DEFINE(_SUDO_PATH_VI, "/usr/bsd/vi")
elif test -f "/usr/local/bin/vi"; then
    AC_MSG_RESULT(/usr/local/bin/vi)
    AC_DEFINE(_SUDO_PATH_VI, "/usr/local/bin/vi")
else
    AC_MSG_RESULT(not found)
fi
])dnl
dnl
dnl check for pwd
dnl
AC_DEFUN(SUDO_PROG_PWD, [AC_MSG_CHECKING(checking for pwd)
if test -f "/usr/bin/pwd"; then
    AC_MSG_RESULT(/usr/bin/pwd)
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/bin/pwd")
elif test -f "/bin/pwd"; then
    AC_MSG_RESULT(/bin/pwd)
    AC_DEFINE(_SUDO_PATH_PWD, "/bin/pwd")
elif test -f "/usr/ucb/pwd"; then
    AC_MSG_RESULT(/usr/ucb/pwd)
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/ucb/pwd")
elif test -f "/usr/sbin/pwd"; then
    AC_MSG_RESULT(/usr/sbin/pwd)
    AC_DEFINE(_SUDO_PATH_PWD, "/usr/sbin/pwd")
else
    AC_MSG_RESULT(not found)
fi
])dnl
dnl
dnl check for mv
dnl
AC_DEFUN(SUDO_PROG_MV, [AC_MSG_CHECKING(checking for mv)
if test -f "/usr/bin/mv"; then
    AC_MSG_RESULT(/usr/bin/mv)
    AC_DEFINE(_SUDO_PATH_MV, "/usr/bin/mv")
elif test -f "/bin/mv"; then
    AC_MSG_RESULT(/bin/mv)
    AC_DEFINE(_SUDO_PATH_MV, "/bin/mv")
elif test -f "/usr/ucb/mv"; then
    AC_MSG_RESULT(/usr/ucb/mv)
    AC_DEFINE(_SUDO_PATH_MV, "/usr/ucb/mv")
elif test -f "/usr/sbin/mv"; then
    AC_MSG_RESULT(/usr/sbin/mv)
    AC_DEFINE(_SUDO_PATH_MV, "/usr/sbin/mv")
else
    AC_MSG_RESULT(not found)
fi
])dnl
dnl
dnl check for fullly working void
dnl
AC_DEFUN(SUDO_FULL_VOID, [AC_MSG_CHECKING(checking for full void implementation)
AC_TRY_COMPILE(, [void *foo;
foo = 0;], AC_DEFINE(VOID, void)
AC_MSG_RESULT(yes), AC_DEFINE(VOID, char)
AC_MSG_RESULT(no))])
dnl
dnl Check for ssize_t declation
dnl XXX - check unistd.h too
dnl
AC_DEFUN(SUDO_SSIZE_T,
[AC_CHECK_TYPE(ssize_t, int)])
dnl
dnl check for known UNIX variants
dnl XXX - check to see that uname was checked first
dnl
AC_DEFUN(SUDO_OSTYPE,
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
AC_DEFUN(SUDO_CONVEX,
[echo checking for ConvexOS 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_EGREP_HEADER])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#if defined(__convex__) || defined(convex)
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_MTXINU
dnl
AC_DEFUN(SUDO_MTXINU,
[echo checking for MORE/BSD
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_EGREP_HEADER])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#include <sys/param.h>
#ifdef MORE_BSD
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_NEXT
dnl
AC_DEFUN(SUDO_NEXT,
[echo checking for NeXTstep 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_EGREP_HEADER])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#ifdef NeXT
  yes
#endif
], [$1], [$2])
])dnl
dnl
dnl SUDO_BSD
dnl
AC_DEFUN(SUDO_BSD,
[echo checking for BSD 
AC_BEFORE([$0], [AC_COMPILE_CHECK])AC_BEFORE([$0], [AC_TEST_PROGRAM])AC_BEFORE([
$0], [AC_EGREP_HEADER])AC_BEFORE([$0], [AC_TEST_CPP])AC_PROGRAM_EGREP(yes,
[#include <sys/param.h>
#ifdef BSD
  yes
#endif
], [$1], [$2])
])dnl
