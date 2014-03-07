dnl Local m4 macros for autoconf (used by sudo)
dnl
dnl Copyright (c) 1994-1996, 1998-2005, 2007-2014
dnl	Todd C. Miller <Todd.Miller@courtesan.com>
dnl
dnl XXX - should cache values in all cases!!!
dnl
dnl checks for programs

dnl
dnl check for sendmail in well-known locations
dnl
AC_DEFUN([SUDO_PROG_SENDMAIL], [AC_MSG_CHECKING([for sendmail])
found=no
for p in "/usr/sbin/sendmail" "/usr/lib/sendmail" "/usr/etc/sendmail" "/usr/ucblib/sendmail" "/usr/local/lib/sendmail" "/usr/local/bin/sendmail"; do
    if test -f "$p"; then
	found=yes
	AC_MSG_RESULT([$p])
	SUDO_DEFINE_UNQUOTED(_PATH_SUDO_SENDMAIL, "$p")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl check for vi in well-known locations
dnl
AC_DEFUN([SUDO_PROG_VI], [AC_MSG_CHECKING([for vi])
found=no
for editor in "/usr/bin/vi" "/bin/vi" "/usr/ucb/vi" "/usr/bsd/vi" "/usr/local/bin/vi"; do
    if test -f "$editor"; then
	found=yes
	AC_MSG_RESULT([$editor])
	SUDO_DEFINE_UNQUOTED(_PATH_VI, "$editor")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl check for mv in well-known locations
dnl
AC_DEFUN([SUDO_PROG_MV], [AC_MSG_CHECKING([for mv])
found=no
for p in "/usr/bin/mv" "/bin/mv" "/usr/ucb/mv" "/usr/sbin/mv"; do
    if test -f "$p"; then
	found=yes
	AC_MSG_RESULT([$p])
	SUDO_DEFINE_UNQUOTED(_PATH_MV, "$p")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl check for bourne shell in well-known locations
dnl
AC_DEFUN([SUDO_PROG_BSHELL], [AC_MSG_CHECKING([for bourne shell])
found=no
for p in "/bin/sh" "/usr/bin/sh" "/sbin/sh" "/usr/sbin/sh" "/bin/ksh" "/usr/bin/ksh" "/bin/bash" "/usr/bin/bash"; do
    if test -f "$p"; then
	found=yes
	AC_MSG_RESULT([$p])
	SUDO_DEFINE_UNQUOTED(_PATH_BSHELL, "$p")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl check for utmp file
dnl
AC_DEFUN([SUDO_PATH_UTMP], [AC_MSG_CHECKING([for utmp file path])
found=no
for p in "/var/run/utmp" "/var/adm/utmp" "/etc/utmp"; do
    if test -r "$p"; then
	found=yes
	AC_MSG_RESULT([$p])
	SUDO_DEFINE_UNQUOTED(_PATH_UTMP, "$p")
	break
    fi
done
if test X"$found" != X"yes"; then
    AC_MSG_RESULT([not found])
fi
])dnl

dnl
dnl Where the log file goes, use /var/log if it exists, else /{var,usr}/adm
dnl
AC_DEFUN([SUDO_LOGFILE], [AC_MSG_CHECKING(for log file location)
if test -n "$with_logpath"; then
    AC_MSG_RESULT($with_logpath)
    SUDO_DEFINE_UNQUOTED(_PATH_SUDO_LOGFILE, "$with_logpath")
elif test -d "/var/log"; then
    AC_MSG_RESULT(/var/log/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/var/log/sudo.log")
elif test -d "/var/adm"; then
    AC_MSG_RESULT(/var/adm/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/var/adm/sudo.log")
elif test -d "/usr/adm"; then
    AC_MSG_RESULT(/usr/adm/sudo.log)
    SUDO_DEFINE(_PATH_SUDO_LOGFILE, "/usr/adm/sudo.log")
else
    AC_MSG_RESULT(unknown, you will have to set _PATH_SUDO_LOGFILE by hand)
fi
])dnl

dnl
dnl Parent directory for time stamp dir.
dnl
AC_DEFUN([SUDO_RUNDIR], [AC_MSG_CHECKING(for sudo run dir location)
rundir="$with_rundir"
if test -z "$rundir"; then
    for d in /var/run /var/db /var/lib /var/adm /usr/adm; do
	if test -d "$d"; then
	    rundir="$d/sudo"
	    break
	fi
    done
fi
AC_MSG_RESULT([$rundir])
SUDO_DEFINE_UNQUOTED(_PATH_SUDO_TIMEDIR, "$rundir/ts")
])dnl

dnl
dnl Parent directory for the lecture status dir.
dnl
AC_DEFUN([SUDO_VARDIR], [AC_MSG_CHECKING(for sudo var dir location)
vardir="$with_vardir"
if test -z "$vardir"; then
    for d in /var/db /var/lib /var/adm /usr/adm; do
	if test -d "$d"; then
	    vardir="$d/sudo"
	    break
	fi
    done
fi
AC_MSG_RESULT([$vardir])
SUDO_DEFINE_UNQUOTED(_PATH_SUDO_LECTURE_DIR, "$vardir/lectured")
])dnl

dnl
dnl Where the I/O log files go, use /var/log/sudo-io if
dnl /var/log exists, else /{var,usr}/adm/sudo-io
dnl
AC_DEFUN([SUDO_IO_LOGDIR], [
    AC_MSG_CHECKING(for I/O log dir location)
    if test "${with_iologdir-yes}" != "yes"; then
	iolog_dir="$with_iologdir"
    elif test -d "/var/log"; then
	iolog_dir="/var/log/sudo-io"
    elif test -d "/var/adm"; then
	iolog_dir="/var/adm/sudo-io"
    else
	iolog_dir="/usr/adm/sudo-io"
    fi
    if test "${with_iologdir}" != "no"; then
	SUDO_DEFINE_UNQUOTED(_PATH_SUDO_IO_LOGDIR, "$iolog_dir")
    fi
    AC_MSG_RESULT($iolog_dir)
])dnl

dnl
dnl check for working fnmatch(3)
dnl
AC_DEFUN([SUDO_FUNC_FNMATCH],
[AC_MSG_CHECKING([for working fnmatch with FNM_CASEFOLD])
AC_CACHE_VAL(sudo_cv_func_fnmatch,
[rm -f conftestdata; > conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([[#include <fnmatch.h>
main() { exit(fnmatch("/*/bin/echo *", "/usr/bin/echo just a test", FNM_CASEFOLD)); }]])], [sudo_cv_func_fnmatch=yes], [sudo_cv_func_fnmatch=no],
  [sudo_cv_func_fnmatch=no])
rm -f core core.* *.core])
AC_MSG_RESULT($sudo_cv_func_fnmatch)
AS_IF([test $sudo_cv_func_fnmatch = yes], [$1], [$2])])

dnl
dnl Attempt to check for working PIE support.
dnl This is a bit of a hack but on Solaris 10 with GNU ld and GNU as
dnl we can end up with strange values from malloc().
dnl A better check would be to verify that ASLR works with PIE.
dnl
AC_DEFUN([SUDO_WORKING_PIE],
[AC_MSG_CHECKING([for working PIE support])
AC_CACHE_VAL(sudo_cv_working_pie,
[rm -f conftestdata; > conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([AC_INCLUDES_DEFAULT
main() { char *p = malloc(1024); if (p == NULL) return 1; memset(p, 0, 1024); return 0; }])], [sudo_cv_working_pie=yes], [sudo_cv_working_pie=no],
  [sudo_cv_working_pie=no])
rm -f core core.* *.core])
AC_MSG_RESULT($sudo_cv_working_pie)
AS_IF([test $sudo_cv_working_pie = yes], [$1], [$2])])

dnl
dnl check for isblank(3)
dnl
AC_DEFUN([SUDO_FUNC_ISBLANK],
  [AC_CACHE_CHECK([for isblank], [sudo_cv_func_isblank],
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <ctype.h>]], [[return (isblank('a'));]])],
    [sudo_cv_func_isblank=yes], [sudo_cv_func_isblank=no])])
] [
  if test "$sudo_cv_func_isblank" = "yes"; then
    AC_DEFINE(HAVE_ISBLANK, 1, [Define if you have isblank(3).])
  else
    AC_LIBOBJ(isblank)
  fi
])

AC_DEFUN([SUDO_CHECK_LIB], [
    _sudo_check_lib_extras=`echo "$5"|sed -e 's/[ 	]*//g' -e 's/-l/_/g'`
    AC_MSG_CHECKING([for $2 in -l$1${5+ }$5])
    AC_CACHE_VAL([sudo_cv_lib_$1''_$2$_sudo_check_lib_extras], [
	SUDO_CHECK_LIB_OLIBS="$LIBS"
	LIBS="$LIBS -l$1${5+ }$5"
	AC_LINK_IFELSE(
	    [AC_LANG_CALL([], [$2])],
	    [eval sudo_cv_lib_$1''_$2$_sudo_check_lib_extras=yes],
	    [eval sudo_cv_lib_$1''_$2$_sudo_check_lib_extras=no]
	)
	LIBS="$SUDO_CHECK_LIB_OLIBS"
    ])
    if eval test \$sudo_cv_lib_$1''_$2$_sudo_check_lib_extras = "yes"; then
	AC_MSG_RESULT([yes])
	$3
    else
	AC_MSG_RESULT([no])
	$4
    fi
])

dnl
dnl check unsetenv() return value
dnl
AC_DEFUN([SUDO_FUNC_UNSETENV_VOID],
  [AC_CACHE_CHECK([whether unsetenv returns void], [sudo_cv_func_unsetenv_void],
    [AC_RUN_IFELSE([AC_LANG_PROGRAM(
      [AC_INCLUDES_DEFAULT
        int unsetenv();
      ], [
        [return unsetenv("FOO") != 0;]
      ])
    ],
    [sudo_cv_func_unsetenv_void=no],
    [sudo_cv_func_unsetenv_void=yes],
    [sudo_cv_func_unsetenv_void=no])])
    if test $sudo_cv_func_unsetenv_void = yes; then
      AC_DEFINE(UNSETENV_VOID, 1,
        [Define to 1 if the `unsetenv' function returns void instead of `int'.])
    fi
  ])

dnl
dnl check putenv() argument for const
dnl
AC_DEFUN([SUDO_FUNC_PUTENV_CONST],
[AC_CACHE_CHECK([whether putenv takes a const argument],
sudo_cv_func_putenv_const,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
int putenv(const char *string) {return 0;}], [])],
    [sudo_cv_func_putenv_const=yes],
    [sudo_cv_func_putenv_const=no])
  ])
  if test $sudo_cv_func_putenv_const = yes; then
    AC_DEFINE(PUTENV_CONST, const, [Define to const if the `putenv' takes a const argument.])
  else
    AC_DEFINE(PUTENV_CONST, [])
  fi
])

dnl
dnl check for sa_len field in struct sockaddr
dnl
AC_DEFUN([SUDO_SOCK_SA_LEN], [
    AC_CHECK_MEMBER([struct sockaddr.sa_len], 
	[AC_DEFINE(HAVE_STRUCT_SOCKADDR_SA_LEN, 1, [Define if your struct sockaddr has an sa_len field.])],
	[], [
#	  include <sys/types.h>
#	  include <sys/socket.h>] 
    )]
)

dnl
dnl check for sin_len field in struct sockaddr_in
dnl
AC_DEFUN([SUDO_SOCK_SIN_LEN], [
    AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
	[AC_DEFINE(HAVE_STRUCT_SOCKADDR_IN_SIN_LEN, 1, [Define if your struct sockaddr_in has a sin_len field.])],
	[], [
#	  include <sys/types.h>
#	  include <sys/socket.h>]
    )]
)

dnl
dnl check for max length of uid_t in string representation.
dnl we can't really trust UID_MAX or MAXUID since they may exist
dnl only for backwards compatibility.
dnl
AC_DEFUN([SUDO_UID_T_LEN],
[AC_REQUIRE([AC_TYPE_UID_T])
AC_MSG_CHECKING(max length of uid_t)
AC_CACHE_VAL(sudo_cv_uid_t_len,
[rm -f conftestdata
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <pwd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/param.h>
main() {
  FILE *f;
  char b[1024];
  uid_t u = (uid_t) -1;

  if ((f = fopen("conftestdata", "w")) == NULL)
    exit(1);

  (void) sprintf(b, "%lu", (unsigned long) u);
  (void) fprintf(f, "%d\n", strlen(b));
  (void) fclose(f);
  exit(0);
}]])], [sudo_cv_uid_t_len=`cat conftestdata`], [sudo_cv_uid_t_len=10], [sudo_cv_uid_t_len=10])
])
rm -f conftestdata
AC_MSG_RESULT($sudo_cv_uid_t_len)
AC_DEFINE_UNQUOTED(MAX_UID_T_LEN, $sudo_cv_uid_t_len, [Define to the max length of a uid_t in string context (excluding the NUL).])
])

dnl
dnl Append a libpath to an LDFLAGS style variable if not already present.
dnl Also appends to the _R version unless rpath is disabled.
dnl
AC_DEFUN([SUDO_APPEND_LIBPATH], [
    case "${$1}" in
	*"-L$2"|*"-L$2 ")
	    ;;
	*)
	    $1="${$1} -L$2"
	    if test X"$enable_rpath" = X"yes"; then
		$1_R="${$1_R} -R$2"
	    fi
	    ;;
    esac
])

dnl
dnl Append a directory to CPPFLAGS if not already present.
dnl
AC_DEFUN([SUDO_APPEND_CPPFLAGS], [
    case "${CPPFLAGS}" in
	*"$1"|*"$1 ")
	    ;;
	*)
	    if test X"${CPPFLAGS}" = X""; then
		CPPFLAGS="$1"
	    else
		CPPFLAGS="${CPPFLAGS} $1"
	    fi
	    ;;
    esac
])

dnl
dnl Determine the mail spool location
dnl NOTE: must be run *after* check for paths.h
dnl
AC_DEFUN([SUDO_MAILDIR], [
maildir=no
if test X"$ac_cv_header_paths_h" = X"yes"; then
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT
#include <paths.h>],
[char *p = _PATH_MAILDIR;])], [maildir=yes], [])
fi
if test $maildir = no; then
    # Solaris has maillock.h which defines MAILDIR
    AC_CHECK_HEADERS(maillock.h, [
	SUDO_DEFINE(_PATH_MAILDIR, MAILDIR)
	maildir=yes
    ])
    if test $maildir = no; then
	for d in /var/mail /var/spool/mail /usr/spool/mail; do
	    if test -d "$d"; then
		maildir=yes
		SUDO_DEFINE_UNQUOTED(_PATH_MAILDIR, "$d")
		break
	    fi
	done
	if test $maildir = no; then
	    # unable to find mail dir, hope for the best
	    SUDO_DEFINE_UNQUOTED(_PATH_MAILDIR, "/var/mail")
	fi
    fi
fi
])

dnl
dnl private versions of AC_DEFINE and AC_DEFINE_UNQUOTED that don't support
dnl tracing that we use to define paths for pathnames.h so autoheader doesn't
dnl put them in config.h.in.  An awful hack.
dnl
m4_define([SUDO_DEFINE],
[cat >>confdefs.h <<\EOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
EOF
])

m4_define([SUDO_DEFINE_UNQUOTED],
[cat >>confdefs.h <<EOF
[@%:@define] $1 m4_if($#, 2, [$2], $#, 3, [$2], 1)
EOF
])
