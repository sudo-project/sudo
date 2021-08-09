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
sudo_preload_dso(char *envp[], const char *dso_file, int intercept_fd)
{
    char *preload = NULL;
    int env_len;
    int preload_idx = -1;
    int intercept_idx = -1;
    bool fd_present = false;
    bool dso_present = false;
# ifdef RTLD_PRELOAD_ENABLE_VAR
    bool dso_enabled = false;
# else
    const bool dso_enabled = true;
# endif
    debug_decl(sudo_preload_dso, SUDO_DEBUG_UTIL);

    /*
     * Preload a DSO file.  For a list of LD_PRELOAD-alikes, see
     * http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
     * XXX - need to support 32-bit and 64-bit variants
     */

    /* Count entries in envp, looking for LD_PRELOAD as we go. */
    /* XXX - If multiple LD_PRELOAD should remove extras */
    for (env_len = 0; envp[env_len] != NULL; env_len++) {
	if (strncmp(envp[env_len], RTLD_PRELOAD_VAR "=", sizeof(RTLD_PRELOAD_VAR)) == 0) {
	    if (preload_idx == -1) {
		const char *cp = envp[env_len] + sizeof(RTLD_PRELOAD_VAR);
		const char *end = cp + strlen(cp);
		const char *ep;
		const size_t dso_len = strlen(dso_file);

		/* Check to see if dso_file is already present. */
		for (cp = sudo_strsplit(cp, end, RTLD_PRELOAD_DELIM, &ep);
		    cp != NULL; cp = sudo_strsplit(NULL, end, RTLD_PRELOAD_DELIM,
		    &ep)) {
		    if ((size_t)(ep - cp) == dso_len) {
			if (memcmp(cp, dso_file, dso_len) == 0) {
			    /* already present */
			    dso_present = true;
			    break;
			}
		    }
		}

		/* Save index of existing LD_PRELOAD variable. */
		preload_idx = env_len;
	    } else {
		/* Remove duplicate LD_PRELOAD. */
		int i;
		for (i = env_len; envp[i] != NULL; i++) {
		    envp[i] = envp[i + 1];
		}
	    }
	    continue;
	}
	if (intercept_fd != -1 && strncmp(envp[env_len], "SUDO_INTERCEPT_FD=",
		sizeof("SUDO_INTERCEPT_FD=")) == 0) {
	    if (intercept_idx == -1) {
		const char *cp = envp[env_len] + sizeof("SUDO_INTERCEPT_FD=");
		const char *errstr;
		int fd;

		fd = sudo_strtonum(cp, 0, INT_MAX, &errstr);
		if (fd == intercept_fd && errstr == NULL)
		    fd_present = true;

		/* Save index of existing SUDO_INTERCEPT_FD variable. */
		intercept_idx = env_len;
	    } else {
		/* Remove duplicate SUDO_INTERCEPT_FD. */
		int i;
		for (i = env_len; envp[i] != NULL; i++) {
		    envp[i] = envp[i + 1];
		}
	    }
	    continue;
	}
# ifdef RTLD_PRELOAD_ENABLE_VAR
	if (strncmp(envp[env_len], RTLD_PRELOAD_ENABLE_VAR "=", sizeof(RTLD_PRELOAD_ENABLE_VAR)) == 0) {
	    dso_enabled = true;
	    continue;
	}
# endif
    }

    /*
     * Make a new copy of envp as needed.
     * It would be nice to realloc the old envp[] but we don't know
     * whether it was dynamically allocated. [TODO: plugin API]
     */
    if (preload_idx == -1 || !dso_enabled || intercept_idx == -1) {
	const int env_size = env_len + 1 + (preload_idx == -1) + dso_enabled + (intercept_idx == -1); // -V547

	char **nenvp = reallocarray(NULL, env_size, sizeof(*envp));
	if (nenvp == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
	memcpy(nenvp, envp, env_len * sizeof(*envp));
	nenvp[env_len] = NULL;
	envp = nenvp;
    }

    /* Prepend our LD_PRELOAD to existing value or add new entry at the end. */
    if (!dso_present) {
	if (preload_idx == -1) {
# ifdef RTLD_PRELOAD_DEFAULT
	    asprintf(&preload, "%s=%s%s%s", RTLD_PRELOAD_VAR, dso_file,
		RTLD_PRELOAD_DELIM, RTLD_PRELOAD_DEFAULT);
# else
	    preload = sudo_new_key_val(RTLD_PRELOAD_VAR, dso_file);
# endif
	    if (preload == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		/* XXX - leak */
		debug_return_ptr(NULL);
	    }
	    envp[env_len++] = preload;
	    envp[env_len] = NULL;
	} else {
	    int len = asprintf(&preload, "%s=%s%s%s", RTLD_PRELOAD_VAR,
		dso_file, RTLD_PRELOAD_DELIM, envp[preload_idx]);
	    if (len == -1) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		/* XXX - leak */
		debug_return_ptr(NULL);
	    }
	    envp[preload_idx] = preload;
	}
    }
# ifdef RTLD_PRELOAD_ENABLE_VAR
    if (!dso_enabled) {
	envp[env_len++] = RTLD_PRELOAD_ENABLE_VAR "=";
	envp[env_len] = NULL;
    }
# endif
    if (!fd_present && intercept_fd != -1) {
	char *fdstr;
	int len;

	len = asprintf(&fdstr, "SUDO_INTERCEPT_FD=%d", intercept_fd);
	if (len == -1) {
	    sudo_warnx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	    /* XXX - leak */
	    debug_return_ptr(NULL);
	}
	if (intercept_idx != -1) {
	    envp[preload_idx] = fdstr;
	} else {
	    envp[env_len++] = fdstr;
	    envp[env_len] = NULL;
	}
    }

    debug_return_ptr(envp);
}
#endif /* RTLD_PRELOAD_VAR */
