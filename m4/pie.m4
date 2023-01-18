AC_DEFUN([SUDO_CHECK_PIE_SUPPORT], [
    dnl
    dnl Check for PIE executable support if using gcc.
    dnl This test relies on AC_LANG_WERROR
    dnl
    if test -n "$GCC"; then
	if test X"$enable_pie" = X""; then
	    case "$host_os" in
		linux*)
		    # Attempt to build with PIE support
		    enable_pie="maybe"
		    ;;
	    esac
	fi
	if test X"$enable_pie" != X""; then
	    if test "$enable_pie" = "no"; then
		AX_CHECK_COMPILE_FLAG([-fno-pie], [
		    _CFLAGS="$CFLAGS"
		    CFLAGS="$CFLAGS -fno-pie"
		    AX_CHECK_LINK_FLAG([-nopie], [
			PIE_CFLAGS="-fno-pie"
			PIE_LDFLAGS="-nopie"
		    ])
		    CFLAGS="$_CFLAGS"
		])
	    else
		AX_CHECK_COMPILE_FLAG([-fPIE], [
		    _CFLAGS="$CFLAGS"
		    CFLAGS="$CFLAGS -fPIE"
		    _LDFLAGS="$LDFLAGS"
		    AX_CHECK_LINK_FLAG([-pie], [
			if test "$enable_pie" = "maybe"; then
			    LDFLAGS="$LDFLAGS -pie"
			    SUDO_WORKING_PIE([enable_pie=yes], [])
			fi
			if test "$enable_pie" = "yes"; then
			    PIE_CFLAGS="-fPIE"
			    PIE_LDFLAGS="-Wc,-fPIE -pie"
			fi
		    ])
		    CFLAGS="$_CFLAGS"
		    LDFLAGS="$_LDFLAGS"
		])
	    fi
	fi
    fi
    if test X"$enable_pie" != X"yes" -a X"$with_gnu_ld" = X"no"; then
	# Solaris 11.1 and higher supports PIE executables.
	case "$host_os" in
	    solaris2.1[[1-9]]|solaris2.[[2-9]][[0-9]])
		AX_CHECK_COMPILE_FLAG([-KPIC], [
		    _CFLAGS="$CFLAGS"
		    CFLAGS="$CFLAGS -KPIC"
		    _LDFLAGS="$LDFLAGS"
		    AX_CHECK_LINK_FLAG([-Wl,-z,type=pie], [
			if test "$enable_pie" = "maybe"; then
			    LDFLAGS="$LDFLAGS -Wl,-z,type=pie"
			    SUDO_WORKING_PIE([enable_pie=yes], [])
			fi
			if test "$enable_pie" = "yes"; then
			    PIE_CFLAGS="-KPIC"
			    PIE_LDFLAGS="-Wc,-KPIC -Wl,-z,type=pie"
			fi
		    ])
		    CFLAGS="$_CFLAGS"
		    LDFLAGS="$_LDFLAGS"
		])
		;;
	esac
    fi
])
