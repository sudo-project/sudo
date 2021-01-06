/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "sudoers.h"

/*
 * Non-destructive word-split that handles single and double quotes and
 * escaped white space.  Quotes are only recognized at the start of a word.
 * They are treated as normal characters inside a word.
 */
static const char *
wordsplit(const char *str, const char *endstr, const char **last)
{
    const char *cp;
    debug_decl(wordsplit, SUDO_DEBUG_UTIL);

    /* If no str specified, use last ptr (if any). */
    if (str == NULL) {
	str = *last;
	/* Consume end quote if present. */
	if (*str == '"' || *str == '\'')
	    str++;
    }

    /* Skip leading white space characters. */
    while (str < endstr && (*str == ' ' || *str == '\t'))
	str++;

    /* Empty string? */
    if (str >= endstr) {
	*last = endstr;
	debug_return_ptr(NULL);
    }

    /* If word is quoted, skip to end quote and return. */
    if (*str == '"' || *str == '\'') {
	const char *endquote = memchr(str + 1, *str, endstr - str);
	if (endquote != NULL) {
	    *last = endquote;
	    debug_return_const_ptr(str + 1);
	}
    }

    /* Scan str until we encounter white space. */
    for (cp = str; cp < endstr; cp++) {
	if (*cp == '\\') {
	    /* quoted char, do not interpret */
	    cp++;
	    continue;
	}
	if (*cp == ' ' || *cp == '\t') {
	    /* end of word */
	    break;
	}
    }
    *last = cp;
    debug_return_const_ptr(str);
}

/* Copy len chars from string, collapsing chars escaped with a backslash. */
static char *
copy_arg(const char *src, size_t len)
{
    const char *src_end = src + len;
    char *copy, *dst;
    debug_decl(copy_arg, SUDOERS_DEBUG_UTIL);

    if ((copy = malloc(len + 1)) != NULL) {
	for (dst = copy; src < src_end; ) {
	    if (*src == '\\') {
		src++;
		continue;
	    }
	    *dst++ = *src++;
	}
	*dst = '\0';
    }

    debug_return_ptr(copy);
}

/*
 * Search for the specified editor in the user's PATH, checking
 * the result against allowlist if non-NULL.  An argument vector
 * suitable for execve() is allocated and stored in argv_out.
 * If nfiles is non-zero, files[] is added to the end of argv_out.
 *
 * Returns the path to be executed on success, else NULL.
 * The caller is responsible for freeing the returned editor path
 * as well as the argument vector.
 */
static char *
resolve_editor(const char *ed, size_t edlen, int nfiles, char **files,
    int *argc_out, char ***argv_out, char * const *allowlist)
{
    char **nargv = NULL, *editor = NULL, *editor_path = NULL;
    const char *tmp, *cp, *ep = NULL;
    const char *edend = ed + edlen;
    struct stat user_editor_sb;
    int nargc;
    debug_decl(resolve_editor, SUDOERS_DEBUG_UTIL);

    /*
     * Split editor into an argument vector, including files to edit.
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    cp = wordsplit(ed, edend, &ep);
    if (cp == NULL)
	debug_return_str(NULL);
    editor = copy_arg(cp, ep - cp);
    if (editor == NULL)
	goto oom;

    /* If we can't find the editor in the user's PATH, give up. */
    if (find_path(editor, &editor_path, &user_editor_sb, getenv("PATH"), NULL,
	    0, allowlist) != FOUND) {
	free(editor);
	errno = ENOENT;
	debug_return_str(NULL);
    }

    /* Count rest of arguments and allocate editor argv. */
    for (nargc = 1, tmp = ep; wordsplit(NULL, edend, &tmp) != NULL; )
	nargc++;
    if (nfiles != 0)
	nargc += nfiles + 1;
    nargv = reallocarray(NULL, nargc + 1, sizeof(char *));
    if (nargv == NULL)
	goto oom;

    /* Fill in editor argv (assumes files[] is NULL-terminated). */
    nargv[0] = editor;
    editor = NULL;
    for (nargc = 1; (cp = wordsplit(NULL, edend, &ep)) != NULL; nargc++) {
	/* Copy string, collapsing chars escaped with a backslash. */
	nargv[nargc] = copy_arg(cp, ep - cp);
	if (nargv[nargc] == NULL)
	    goto oom;
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
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    free(editor);
    free(editor_path);
    if (nargv != NULL) {
	while (nargc--)
	    free(nargv[nargc]);
	free(nargv);
    }
    debug_return_str(NULL);
}

/*
 * Determine which editor to use based on the SUDO_EDITOR, VISUAL and
 * EDITOR environment variables as well as the editor path in sudoers.
 * If env_error is true, an editor environment variable that cannot be
 * resolved is an error.
 *
 * Returns the path to be executed on success, else NULL.
 * The caller is responsible for freeing the returned editor path
 * as well as the argument vector.
 */
char *
find_editor(int nfiles, char **files, int *argc_out, char ***argv_out,
     char * const *allowlist, const char **env_editor, bool env_error)
{
    char *ev[3], *editor_path = NULL;
    unsigned int i;
    debug_decl(find_editor, SUDOERS_DEBUG_UTIL);

    /*
     * If any of SUDO_EDITOR, VISUAL or EDITOR are set, choose the first one.
     */
    *env_editor = NULL;
    ev[0] = "SUDO_EDITOR";
    ev[1] = "VISUAL";
    ev[2] = "EDITOR";
    for (i = 0; i < nitems(ev); i++) {
	char *editor = getenv(ev[i]);

	if (editor != NULL && *editor != '\0') {
	    *env_editor = editor;
	    editor_path = resolve_editor(editor, strlen(editor),
		nfiles, files, argc_out, argv_out, allowlist);
	    if (editor_path != NULL)
		break;
	    if (errno != ENOENT)
		debug_return_str(NULL);
	}
    }
    if (editor_path == NULL) {
	const char *def_editor_end = def_editor + strlen(def_editor);
	const char *cp, *ep;

	if (env_error && *env_editor != NULL) {
	    /* User-specified editor could not be found. */
	    debug_return_str(NULL);
	}

	/* def_editor could be a path, split it up, avoiding strtok() */
	for (cp = sudo_strsplit(def_editor, def_editor_end, ":", &ep);
	    cp != NULL; cp = sudo_strsplit(NULL, def_editor_end, ":", &ep)) {
	    editor_path = resolve_editor(cp, (size_t)(ep - cp), nfiles,
		files, argc_out, argv_out, allowlist);
	    if (editor_path != NULL)
		break;
	    if (errno != ENOENT)
		debug_return_str(NULL);
	}
    }

    debug_return_str(editor_path);
}
