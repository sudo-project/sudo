/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sudo.h"
#include "sudo_exec.h"

#ifdef RTLD_PRELOAD_VAR
/*
 * Add a DSO file to LD_PRELOAD or the system equivalent.
 */
char **
sudo_preload_dso(char *const envp[], const char *dso_file, int intercept_fd)
{
    char *preload = NULL;
    char **nep, **nenvp = NULL;
    char *const *ep;
    char **preload_ptr = NULL;
    char **intercept_ptr = NULL;
    bool fd_present = false;
    bool dso_present = false;
# ifdef RTLD_PRELOAD_ENABLE_VAR
    bool dso_enabled = false;
# else
    const bool dso_enabled = true;
# endif
# ifdef _PATH_ASAN_LIB
    char *dso_buf = NULL;
# endif
    size_t env_size;
    int len;
    debug_decl(sudo_preload_dso, SUDO_DEBUG_UTIL);

# ifdef _PATH_ASAN_LIB
    /*
     * The address sanitizer DSO needs to be first in the list.
     */
    len = asprintf(&dso_buf, "%s%c%s", _PATH_ASAN_LIB, RTLD_PRELOAD_DELIM,
	dso_file);
    if (len == -1)
       goto oom;
    dso_file = dso_buf;
# endif

    /*
     * Preload a DSO file.  For a list of LD_PRELOAD-alikes, see
     * http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
     * XXX - need to support 32-bit and 64-bit variants
     */

    /* Determine max size for new envp. */
    for (env_size = 0; envp[env_size] != NULL; env_size++)
	continue;
    if (!dso_enabled)
	env_size++;
    if (intercept_fd != -1)
	env_size++;
    env_size += 2;	/* dso_file + terminating NULL */

    /* Allocate new envp. */
    nenvp = reallocarray(NULL, env_size, sizeof(*nenvp));
    if (nenvp == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }

    /*
     * Shallow copy envp, with special handling for RTLD_PRELOAD_VAR,
     * RTLD_PRELOAD_ENABLE_VAR and SUDO_INTERCEPT_FD.
     */
    for (ep = envp, nep = nenvp; *ep != NULL; ep++) {
	if (strncmp(*ep, RTLD_PRELOAD_VAR "=", sizeof(RTLD_PRELOAD_VAR)) == 0) {
	    const char *cp = *ep + sizeof(RTLD_PRELOAD_VAR);
	    const size_t dso_len = strlen(dso_file);

	    /* Skip duplicates. */
	    if (preload_ptr != NULL)
		continue;

	    /*
	     * Check to see if dso_file is already first in the list.
	     * We don't bother checking for it later in the list.
	     */
	    if (strncmp(cp, dso_file, dso_len) == 0) {
		if (cp[dso_len] == '\0' || cp[dso_len] == RTLD_PRELOAD_DELIM)
		    dso_present = true;
	    }

	    /* Save pointer to LD_PRELOAD variable. */
	    preload_ptr = nep;

	    goto copy;
	}
	if (intercept_fd != -1 && strncmp(*ep, "SUDO_INTERCEPT_FD=",
		sizeof("SUDO_INTERCEPT_FD=") - 1) == 0) {
	    const char *cp = *ep + sizeof("SUDO_INTERCEPT_FD=") - 1;
	    const char *errstr;
	    int fd;

	    /* Skip duplicates. */
	    if (intercept_ptr != NULL)
		continue;

	    fd = sudo_strtonum(cp, 0, INT_MAX, &errstr);
	    if (fd == intercept_fd && errstr == NULL)
		fd_present = true;

	    /* Save pointer to SUDO_INTERCEPT_FD variable. */
	    intercept_ptr = nep;

	    goto copy;
	}
# ifdef RTLD_PRELOAD_ENABLE_VAR
	if (strncmp(*ep, RTLD_PRELOAD_ENABLE_VAR "=",
		sizeof(RTLD_PRELOAD_ENABLE_VAR)) == 0) {
	    dso_enabled = true;
	}
# endif
copy:
	*nep++ = *ep;	/* shallow copy */
    }

    /* Prepend our LD_PRELOAD to existing value or add new entry at the end. */
    if (!dso_present) {
	if (preload_ptr == NULL) {
# ifdef RTLD_PRELOAD_DEFAULT
	    len = asprintf(&preload, "%s=%s%c%s", RTLD_PRELOAD_VAR, dso_file,
		RTLD_PRELOAD_DELIM, RTLD_PRELOAD_DEFAULT);
	    if (len == -1) {
		goto oom;
	    }
# else
	    preload = sudo_new_key_val(RTLD_PRELOAD_VAR, dso_file);
	    if (preload == NULL) {
		goto oom;
	    }
# endif
	    *nep++ = preload;
	} else {
	    const char *old_val = *preload_ptr + sizeof(RTLD_PRELOAD_VAR);
	    len = asprintf(&preload, "%s=%s%c%s", RTLD_PRELOAD_VAR,
		dso_file, RTLD_PRELOAD_DELIM, old_val);
	    if (len == -1) {
		goto oom;
	    }
	    *preload_ptr = preload;
	}
    }
# ifdef RTLD_PRELOAD_ENABLE_VAR
    if (!dso_enabled) {
	*nenvp++ = RTLD_PRELOAD_ENABLE_VAR "=";
    }
# endif
    if (!fd_present && intercept_fd != -1) {
	char *fdstr;

	len = asprintf(&fdstr, "SUDO_INTERCEPT_FD=%d", intercept_fd);
	if (len == -1) {
	    goto oom;
	}
	if (intercept_ptr != NULL) {
	    *intercept_ptr = fdstr;
	} else {
	    *nep++ = fdstr;
	}
    }

    /* NULL terminate nenvp at last. */
    *nep = NULL;

# ifdef _PATH_ASAN_LIB
    free(dso_buf);
# endif

    debug_return_ptr(nenvp);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
# ifdef _PATH_ASAN_LIB
    free(dso_buf);
# endif
    free(preload);
    free(nenvp);
    debug_return_ptr(NULL);
}
#endif /* RTLD_PRELOAD_VAR */
