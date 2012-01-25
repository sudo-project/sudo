/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_PRIV_SET
# include <priv.h>
#endif
#include <errno.h>

#include "sudo.h"
#include "sudo_exec.h"

/*
 * Disable execution of child processes in the command we are about
 * to run.  On systems with privilege sets, we can remove the exec
 * privilege.  On other systems we use LD_PRELOAD and the like.
 */
static char * const *
disable_execute(char *const envp[])
{
#ifdef _PATH_SUDO_NOEXEC
    char * const *ev;
    char *cp, **nenvp;
    int env_len = 0, env_size = 128;
#endif /* _PATH_SUDO_NOEXEC */
    debug_decl(disable_execute, SUDO_DEBUG_UTIL)

#ifdef HAVE_PRIV_SET
    /* Solaris privileges, remove PRIV_PROC_EXEC post-execve. */
    if (priv_set(PRIV_OFF, PRIV_LIMIT, "PRIV_PROC_EXEC", NULL) == 0)
	debug_return_ptr(envp);
    warning(_("unable to remove PRIV_PROC_EXEC from PRIV_LIMIT"));
#endif /* HAVE_PRIV_SET */

#ifdef _PATH_SUDO_NOEXEC
    nenvp = emalloc2(env_size, sizeof(char *));
    for (ev = envp; *ev != NULL; ev++) {
	if (env_len + 2 > env_size) {
	    env_size += 128;
	    nenvp = erealloc3(nenvp, env_size, sizeof(char *));
	}
	/*
	 * Prune out existing preloaded libraries.
	 * XXX - should save and append instead of replacing.
	 */
# if defined(__darwin__) || defined(__APPLE__)
	if (strncmp(*ev, "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1) == 0)
	    continue;
	if (strncmp(*ev, "DYLD_FORCE_FLAT_NAMESPACE=", sizeof("DYLD_INSERT_LIBRARIES=") - 1) == 0)
	    continue;
# elif defined(__osf__) || defined(__sgi)
	if (strncmp(*ev, "_RLD_LIST=", sizeof("_RLD_LIST=") - 1) == 0)
	    continue;
# elif defined(_AIX)
	if (strncmp(*ev, "LDR_PRELOAD=", sizeof("LDR_PRELOAD=") - 1) == 0)
	    continue;
# else
	if (strncmp(*ev, "LD_PRELOAD=", sizeof("LD_PRELOAD=") - 1) == 0)
	    continue;
# endif
	nenvp[env_len++] = *ev;
    }

    /*
     * Preload a noexec file?  For a list of LD_PRELOAD-alikes, see
     * http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
     * XXX - need to support 32-bit and 64-bit variants
     */
# if defined(__darwin__) || defined(__APPLE__)
    nenvp[env_len++] = "DYLD_FORCE_FLAT_NAMESPACE=";
    cp = fmt_string("DYLD_INSERT_LIBRARIES", sudo_conf_noexec_path());
# elif defined(__osf__) || defined(__sgi)
    easprintf(&cp, "_RLD_LIST=%s:DEFAULT", sudo_conf_noexec_path());
# elif defined(_AIX)
    cp = fmt_string("LDR_PRELOAD", sudo_conf_noexec_path());
# else
    cp = fmt_string("LD_PRELOAD", sudo_conf_noexec_path());
# endif
    if (cp == NULL)
	errorx(1, _("unable to allocate memory"));
    nenvp[env_len++] = cp;
    nenvp[env_len] = NULL;
    envp = nenvp;
#endif /* _PATH_SUDO_NOEXEC */

    debug_return_ptr(envp);
}

/*
 * Like execve(2) but falls back to running through /bin/sh
 * ala execvp(3) if we get ENOEXEC.
 */
int
sudo_execve(const char *path, char *const argv[], char *const envp[], int noexec)
{
    /* Modify the environment as needed to disable further execve(). */
    if (noexec)
	envp = disable_execute(envp);

    execve(path, argv, envp);
    if (errno == ENOEXEC) {
	int argc;
	char **nargv;

	for (argc = 0; argv[argc] != NULL; argc++)
	    continue;
	nargv = emalloc2(argc + 2, sizeof(char *));
	nargv[0] = "sh";
	nargv[1] = (char *)path;
	memcpy(nargv + 2, argv + 1, argc * sizeof(char *));
	execve(_PATH_BSHELL, nargv, envp);
	efree(nargv);
    }
    return -1;
}
