dnl
dnl https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
dnl
AC_DEFUN([SUDO_CHECK_HARDENING], [
    if test "$enable_hardening" != "no"; then
	#
	# Attempt to use _FORTIFY_SOURCE with sprintf.  If the headers support
	# it but libc does not, __sprintf_chk should be an undefined symbol.
	# Some systems warn about using a value of _FORTIFY_SOURCE > 2.
	#
	O_CPPFLAGS="$CPPFLAGS"
	AC_CACHE_CHECK([supported _FORTIFY_SOURCE level],
	    [sudo_cv_fortify_source_level],
	    [
		AX_APPEND_FLAG([-U_FORTIFY_SOURCE], [CPPFLAGS])
		AX_APPEND_FLAG([-D_FORTIFY_SOURCE=3], [CPPFLAGS])
		AC_LINK_IFELSE([
		    AC_LANG_PROGRAM(
			[[#include <stdio.h>]],
			[[char buf[4]; sprintf(buf, "%s", "foo"); return buf[0];]]
		    )], [
			sudo_cv_fortify_source_level=3
		    ], [
			# Try again with -D_FORTIFY_SOURCE=2
			CPPFLAGS="$O_CPPFLAGS"
			AX_APPEND_FLAG([-U_FORTIFY_SOURCE], [CPPFLAGS])
			AX_APPEND_FLAG([-D_FORTIFY_SOURCE=2], [CPPFLAGS])
			AC_LINK_IFELSE([
			    AC_LANG_PROGRAM(
				[[#include <stdio.h>]],
				[[char buf[4]; sprintf(buf, "%s", "foo"); return buf[0];]]
			    )], [
				sudo_cv_fortify_source_level=2
			    ], [
				sudo_cv_fortify_source_level=none
			    ]
			)
		    ]
		)
	    ]
	)
	CPPFLAGS="$O_CPPFLAGS"
	if test "$sudo_cv_fortify_source_level" != none; then
	    AX_APPEND_FLAG([-U_FORTIFY_SOURCE], [CPPFLAGS])
	    AX_APPEND_FLAG([-D_FORTIFY_SOURCE=$sudo_cv_fortify_source_level], [CPPFLAGS])
	fi

	dnl
	dnl The following tests rely on AC_LANG_WERROR.
	dnl
	if test -n "$GCC" -a "$enable_ssp" != "no"; then
	    AC_CACHE_CHECK([for compiler stack protector support],
		[sudo_cv_var_stack_protector],
		[
		    # Avoid CFLAGS since the compiler might optimize away our
		    # test.  We don't want CPPFLAGS or LIBS to interfere with
		    # the test but keep LDFLAGS as it may have an rpath needed
		    # to find the ssp lib.
		    _CPPFLAGS="$CPPFLAGS"
		    _CFLAGS="$CFLAGS"
		    _LDFLAGS="$LDFLAGS"
		    _LIBS="$LIBS"
		    CPPFLAGS=
		    LIBS=

		    sudo_cv_var_stack_protector="-fstack-protector-strong"
		    CFLAGS="$sudo_cv_var_stack_protector"
		    LDFLAGS="$_LDFLAGS $sudo_cv_var_stack_protector"
		    AC_LINK_IFELSE([
			AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT],
			[[char buf[1024]; buf[1023] = '\0';]])
		    ], [], [
			sudo_cv_var_stack_protector="-fstack-protector-all"
			CFLAGS="$sudo_cv_var_stack_protector"
			LDFLAGS="$_LDFLAGS $sudo_cv_var_stack_protector"
			AC_LINK_IFELSE([
			    AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT],
			    [[char buf[1024]; buf[1023] = '\0';]])
			], [], [
			    sudo_cv_var_stack_protector="-fstack-protector"
			    CFLAGS="$sudo_cv_var_stack_protector"
			    LDFLAGS="$_LDFLAGS $sudo_cv_var_stack_protector"
			    AC_LINK_IFELSE([
				AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT],
				[[char buf[1024]; buf[1023] = '\0';]])
			    ], [], [
				sudo_cv_var_stack_protector=no
			    ])
			])
		    ])
		    CPPFLAGS="$_CPPFLAGS"
		    CFLAGS="$_CFLAGS"
		    LDFLAGS="$_LDFLAGS"
		    LIBS="$_LIBS"
		]
	    )
	    if test X"$sudo_cv_var_stack_protector" != X"no"; then
		HARDENING_CFLAGS="$sudo_cv_var_stack_protector"
		HARDENING_LDFLAGS="-Wc,$sudo_cv_var_stack_protector"
	    fi
	fi

	# The gcc front-end may accept -fstack-clash-protection even if the
	# machine-specific code does not support it.  We use a test program
	# with a large stack allocation to try to cause the compiler to
	# insert the stack clash protection code, or fail if not supported.
	if test -n "$GCC"; then
	    AC_CACHE_CHECK([whether C compiler supports -fstack-clash-protection],
		[sudo_cv_check_cflags___fstack_clash_protection],
		[
		    _CFLAGS="$CFLAGS"
		    CFLAGS="$CFLAGS -fstack-clash-protection"
		    AC_COMPILE_IFELSE([
			AC_LANG_SOURCE([[int main(int argc, char *argv[]) { char buf[16384], *src = argv[0], *dst = buf; while ((*dst++ = *src++) != '\0') { continue; } return buf[argc]; }]])
		    ], [sudo_cv_check_cflags___fstack_clash_protection=yes], [sudo_cv_check_cflags___fstack_clash_protection=no])
		    CFLAGS="$_CFLAGS"
		]
	    )
	    if test X"$sudo_cv_check_cflags___fstack_clash_protection" = X"yes"; then
		AX_CHECK_LINK_FLAG([-fstack-clash-protection], [
		    AX_APPEND_FLAG([-fstack-clash-protection], [HARDENING_CFLAGS])
		    AX_APPEND_FLAG([-Wc,-fstack-clash-protection], [HARDENING_LDFLAGS])
		])
	    fi

	    # Check for control-flow transfer instrumentation (Intel CET).
	    # Do not enable branch protection for 32-bit, since no 32-bit
	    # OS supports it and the generated ENDBR32 instructions have
	    # compatibility issues with some older i586/i686 compatible
	    # processors (e.g. Geode or Vortex).
	    AS_CASE([$host_cpu], [x86_64], [
		AX_CHECK_COMPILE_FLAG([-fcf-protection=full], [
		    AX_CHECK_LINK_FLAG([-fcf-protection=full], [
			AX_APPEND_FLAG([-fcf-protection=full], [HARDENING_CFLAGS])
			AX_APPEND_FLAG([-Wc,-fcf-protection=full], [HARDENING_LDFLAGS])
		    ])
		])
	    ], [i*86], [
		AX_CHECK_COMPILE_FLAG([-fcf-protection=return], [
		    AX_CHECK_LINK_FLAG([-fcf-protection=return], [
			AX_APPEND_FLAG([-fcf-protection=return], [HARDENING_CFLAGS])
			AX_APPEND_FLAG([-Wc,-fcf-protection=return], [HARDENING_LDFLAGS])
		    ])
		])
	    ])

	    #
	    # Check for branch protection against ROP and JOP attacks on
	    # AArch64 by using PAC and BTI.
	    #
	    AS_IF([test "$host_cpu" = "aarch64"], [
		AX_CHECK_COMPILE_FLAG([-mbranch-protection=standard], [
		    AX_CHECK_LINK_FLAG([-mbranch-protection=standard], [
			AX_APPEND_FLAG([-mbranch-protection=standard], [HARDENING_CFLAGS])
			AX_APPEND_FLAG([-Wc,-mbranch-protection=standard], [HARDENING_LDFLAGS])
		    ])
		])
	    ])

	    # Force retention of null pointer checks.
	    AX_CHECK_COMPILE_FLAG([-fno-delete-null-pointer-checks], [AX_APPEND_FLAG([-fno-delete-null-pointer-checks], [HARDENING_CFLAGS])])

	    # Guarantee zero initialization of padding bits in
	    # all automatic variable initializers.
	    AX_CHECK_COMPILE_FLAG([-fzero-init-padding-bits=all], [AX_APPEND_FLAG([-fzero-init-padding-bits=all], [HARDENING_CFLAGS])])

	    # Define behavior for signed integer and pointer overflow.
	    AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [AX_APPEND_FLAG([-fno-strict-overflow], [HARDENING_CFLAGS])])

	    # Disable strict aliasing rules that allow the compiler to assume
	    # that two objects of different types may not use the same address.
	    AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [AX_APPEND_FLAG([-fno-strict-aliasing], [HARDENING_CFLAGS])])

	    # Initialize automatic variables without an assignment to zero.
	    # This prevents uninitialized variables from having stack garbage.
	    AX_CHECK_COMPILE_FLAG([-ftrivial-auto-var-init=zero], [AX_APPEND_FLAG([-ftrivial-auto-var-init=zero], [HARDENING_CFLAGS])])
	fi

	# Linker-specific hardening for GNU ld and similar (gold, lld, etc).
	if test X"$with_gnu_ld" = X"yes"; then
	    # Mark relocation table entries resolved at load-time as read-only.
	    AX_CHECK_LINK_FLAG([-Wl,-z,relro], [AX_APPEND_FLAG([-Wl,-z,relro], [HARDENING_LDFLAGS])])

	    # Resolve all symbols when the program is started.
	    AX_CHECK_LINK_FLAG([-Wl,-z,now], [AX_APPEND_FLAG([-Wl,-z,now], [HARDENING_LDFLAGS])])

	    # Mark stack memory as non-executable.
	    AX_CHECK_LINK_FLAG([-Wl,-z,noexecstack], [AX_APPEND_FLAG([-Wl,-z,noexecstack], [HARDENING_LDFLAGS])])

	    # Only link libraries containing symbols that are actually used.
	    AX_CHECK_LINK_FLAG([-Wl,--as-needed], [AX_APPEND_FLAG([-Wl,--as-needed], [HARDENING_LDFLAGS])])

	    # Don't resolve symbols using transitive library dependencies.
	    # The binary must explicitly link against all of its dependencies.
	    AX_CHECK_LINK_FLAG([-Wl,--no-copy-dt-needed-entries], [AX_APPEND_FLAG([-Wl,--no-copy-dt-needed-entries], [HARDENING_LDFLAGS])])
	fi
    fi])
