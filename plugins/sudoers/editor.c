/*
 * Copyright (c) 2010-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>

#include "sudoers.h"

/*
 * Search for the specified editor in the user's PATH, checking
 * the result against whitelist if non-NULL.  An argument vector
 * suitable for execve() is allocated and stored in argv_out.
 * If nfiles is non-zero, files[] is added to the end of argv_out.
 * Returns the path to be executed on success, else NULL.
 * The caller is responsible for freeing the returned editor path
 * as well as the argument vector.
 */
char *
resolve_editor(const char *ed, size_t edlen, int nfiles, char **files,
    int *argc_out, char ***argv_out, char * const *whitelist)
{
    char **nargv, *editor, *editor_path = NULL;
    const char *cp, *ep, *tmp;
    const char *edend = ed + edlen;
    struct stat user_editor_sb;
    int nargc;
    debug_decl(resolve_editor, SUDOERS_DEBUG_UTIL)

    /*
     * Split editor into an argument vector, including files to edit.
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    cp = sudo_strsplit(ed, edend, " \t", &ep);
    if (cp == NULL)
	debug_return_str(NULL);
    editor = strndup(cp, (size_t)(ep - cp));
    if (editor == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_str(NULL);
    }

    /* If we can't find the editor in the user's PATH, give up. */
    if (find_path(editor, &editor_path, &user_editor_sb, getenv("PATH"), 0, whitelist) != FOUND) {
	free(editor);
	errno = ENOENT;
	debug_return_str(NULL);
    }

    /* Count rest of arguments and allocate editor argv. */
    for (nargc = 1, tmp = ep; sudo_strsplit(NULL, edend, " \t", &tmp) != NULL; )
	nargc++;
    if (nfiles != 0)
	nargc += nfiles + 1;
    nargv = reallocarray(NULL, nargc + 1, sizeof(char *));
    if (nargv == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	free(editor);
	free(editor_path);
	debug_return_str(NULL);
    }

    /* Fill in editor argv (assumes files[] is NULL-terminated). */
    nargv[0] = editor;
    for (nargc = 1; (cp = sudo_strsplit(NULL, edend, " \t", &ep)) != NULL; nargc++) {
	nargv[nargc] = strndup(cp, (size_t)(ep - cp));
	if (nargv[nargc] == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free(editor_path);
	    while (nargc--)
		free(nargv[nargc]);
	    free(nargv);
	    debug_return_str(NULL);
	}
    }
    if (nfiles != 0) {
	nargv[nargc++] = "--";
	while (nfiles--)
	    nargv[nargc++] = *files++;
    }
    nargv[nargc] = NULL;

    *argc_out = nargc;
    *argv_out = nargv;
    debug_return_str(editor_path);
}
