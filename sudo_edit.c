/*
 * Copyright (c) 2004-2008, 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
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
#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif

#include "sudo.h"

static char *find_editor __P((int *argc_out, char ***argv_out));

extern char **NewArgv; /* XXX */

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 */
int
sudo_edit(argc, argv, envp)
    int argc;
    char *argv[];
    char *envp[];
{
    ssize_t nread, nwritten;
    const char *tmpdir;
    char *cp, *suff, **nargv, *editor, **files;
    char **editor_argv = NULL;
    char buf[BUFSIZ];
    int rc, i, j, ac, ofd, tfd, nargc, rval, nfiles, tmplen;
    int editor_argc = 0;
    struct stat sb;
    struct timeval tv, tv1, tv2;
    struct tempfile {
	char *tfile;
	char *ofile;
	struct timeval omtim;
	off_t osize;
    } *tf = NULL;

    /* Determine user's editor. */
    editor = find_editor(&editor_argc, &editor_argv);
    if (editor == NULL)
	return 1;

    /*
     * Find our temporary directory, one of /var/tmp, /usr/tmp, or /tmp
     */
    if (stat(_PATH_VARTMP, &sb) == 0 && S_ISDIR(sb.st_mode))
	tmpdir = _PATH_VARTMP;
#ifdef _PATH_USRTMP
    else if (stat(_PATH_USRTMP, &sb) == 0 && S_ISDIR(sb.st_mode))
	tmpdir = _PATH_USRTMP;
#endif
    else
	tmpdir = _PATH_TMP;
    tmplen = strlen(tmpdir);
    while (tmplen > 0 && tmpdir[tmplen - 1] == '/')
	tmplen--;

    /*
     * For each file specified by the user, make a temporary version
     * and copy the contents of the original to it.
     */
    files = argv + 1;
    nfiles = argc - 1;
    tf = emalloc2(nfiles, sizeof(*tf));
    zero_bytes(tf, nfiles * sizeof(*tf));
    for (i = 0, j = 0; i < nfiles; i++) {
	rc = -1;
	set_perms(PERM_RUNAS);
	if ((ofd = open(files[i], O_RDONLY, 0644)) != -1 || errno == ENOENT) {
	    if (ofd == -1) {
		zero_bytes(&sb, sizeof(sb));		/* new file */
		rc = 0;
	    } else {
#ifdef HAVE_FSTAT
		rc = fstat(ofd, &sb);
#else
		rc = stat(tf[j].ofile, &sb);
#endif
	    }
	}
	set_perms(PERM_ROOT);
	if (rc || (ofd != -1 && !S_ISREG(sb.st_mode))) {
	    if (rc)
		warning("%s", files[i]);
	    else
		warningx("%s: not a regular file", files[i]);
	    if (ofd != -1)
		close(ofd);
	    continue;
	}
	tf[j].ofile = files[i];
	tf[j].osize = sb.st_size;
	mtim_get(&sb, &tf[j].omtim);
	if ((cp = strrchr(tf[j].ofile, '/')) != NULL)
	    cp++;
	else
	    cp = tf[j].ofile;
	suff = strrchr(cp, '.');
	if (suff != NULL) {
	    easprintf(&tf[j].tfile, "%.*s/%.*sXXXXXXXX%s", tmplen, tmpdir, (int)(size_t)(suff - cp), cp, suff);
	} else {
	    easprintf(&tf[j].tfile, "%.*s/%s.XXXXXXXX", tmplen, tmpdir, cp);
	}
	set_perms(PERM_USER);
	tfd = mkstemps(tf[j].tfile, suff ? strlen(suff) : 0);
	set_perms(PERM_ROOT);
	if (tfd == -1) {
	    warning("mkstemps");
	    goto cleanup;
	}
	if (ofd != -1) {
	    while ((nread = read(ofd, buf, sizeof(buf))) != 0) {
		if ((nwritten = write(tfd, buf, nread)) != nread) {
		    if (nwritten == -1)
			warning("%s", tf[j].tfile);
		    else
			warningx("%s: short write", tf[j].tfile);
		    goto cleanup;
		}
	    }
	    close(ofd);
	}
	/*
	 * We always update the stashed mtime because the time
	 * resolution of the filesystem the temporary file is on may
	 * not match that of the filesystem where the file to be edited
	 * resides.  It is OK if touch() fails since we only use the info
	 * to determine whether or not a file has been modified.
	 */
	(void) touch(tfd, NULL, &tf[j].omtim);
#ifdef HAVE_FSTAT
	rc = fstat(tfd, &sb);
#else
	rc = stat(tf[j].tfile, &sb);
#endif
	if (!rc)
	    mtim_get(&sb, &tf[j].omtim);
	close(tfd);
	j++;
    }
    if ((nfiles = j) == 0)
	return 1;			/* no files readable, you lose */

    /*
     * Allocate space for the new argument vector and fill it in.
     * We concatenate the editor with its args and the file list
     * to create a new argv.
     * We allocate an extra slot to be used if execve() fails.
     */
    nargc = editor_argc + nfiles;
    nargv = (char **) emalloc2(1 + nargc + 1, sizeof(char *));
    nargv++;
    for (ac = 0; ac < editor_argc; ac++)
	nargv[ac] = editor_argv[ac];
    for (i = 0; i < nfiles && ac < nargc; )
	nargv[ac++] = tf[i++].tfile;
    nargv[ac] = NULL;

    /*
     * Run the editor with the invoking user's creds,
     * keeping track of the time spent in the editor.
     */
    gettime(&tv1);
    rval = run_command(editor, nargv, envp, user_uid, TRUE);
    gettime(&tv2);

    /* Copy contents of temp files to real ones */
    for (i = 0; i < nfiles; i++) {
	rc = -1;
	set_perms(PERM_USER);
	if ((tfd = open(tf[i].tfile, O_RDONLY, 0644)) != -1) {
#ifdef HAVE_FSTAT
	    rc = fstat(tfd, &sb);
#else
	    rc = stat(tf[i].tfile, &sb);
#endif
	}
	set_perms(PERM_ROOT);
	if (rc || !S_ISREG(sb.st_mode)) {
	    if (rc)
		warning("%s", tf[i].tfile);
	    else
		warningx("%s: not a regular file", tf[i].tfile);
	    warningx("%s left unmodified", tf[i].ofile);
	    if (tfd != -1)
		close(tfd);
	    continue;
	}
	mtim_get(&sb, &tv);
	if (tf[i].osize == sb.st_size && timevalcmp(&tf[i].omtim, &tv, ==)) {
	    /*
	     * If mtime and size match but the user spent no measurable
	     * time in the editor we can't tell if the file was changed.
	     */
	    timevalsub(&tv1, &tv2);
	    if (timevalisset(&tv2)) {
		warningx("%s unchanged", tf[i].ofile);
		unlink(tf[i].tfile);
		close(tfd);
		continue;
	    }
	}
	set_perms(PERM_RUNAS);
	ofd = open(tf[i].ofile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	set_perms(PERM_ROOT);
	if (ofd == -1) {
	    warning("unable to write to %s", tf[i].ofile);
	    warningx("contents of edit session left in %s", tf[i].tfile);
	    close(tfd);
	    continue;
	}
	while ((nread = read(tfd, buf, sizeof(buf))) > 0) {
	    if ((nwritten = write(ofd, buf, nread)) != nread) {
		if (nwritten == -1)
		    warning("%s", tf[i].ofile);
		else
		    warningx("%s: short write", tf[i].ofile);
		break;
	    }
	}
	if (nread == 0) {
	    /* success, got EOF */
	    unlink(tf[i].tfile);
	} else if (nread < 0) {
	    warning("unable to read temporary file");
	    warningx("contents of edit session left in %s", tf[i].tfile);
	} else {
	    warning("unable to write to %s", tf[i].ofile);
	    warningx("contents of edit session left in %s", tf[i].tfile);
	}
	close(ofd);
    }

    return rval;
cleanup:
    /* Clean up temp files and return. */
    if (tf != NULL) {
	for (i = 0; i < nfiles; i++) {
	    if (tf[i].tfile != NULL)
		unlink(tf[i].tfile);
	}
    }
    return 1;
}

static char *
resolve_editor(editor, argc_out, argv_out)
    char *editor;
    int *argc_out;
    char ***argv_out;
{
    char *cp, **nargv, *editor_path = NULL;
    int ac, nargc, wasblank;

    editor = estrdup(editor); /* becomes part of argv_out */

    /*
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = 1;
    for (wasblank = FALSE, cp = editor; *cp != '\0'; cp++) {
	if (isblank((unsigned char) *cp))
	    wasblank = TRUE;
	else if (wasblank) {
	    wasblank = FALSE;
	    nargc++;
	}
    }
    /* If we can't find the editor in the user's PATH, give up. */
    cp = strtok(editor, " \t");
    if (cp == NULL ||
	find_path(cp, &editor_path, NULL, getenv("PATH"), 0) != FOUND) {
	efree(editor);
	return NULL;
    }
    nargv = (char **) emalloc2(nargc + 1, sizeof(char *));
    for (ac = 0; cp != NULL && ac < nargc; ac++) {
	nargv[ac] = cp;
	cp = strtok(NULL, " \t");
    }
    nargv[ac] = NULL;

    *argc_out = nargc;
    *argv_out = nargv;
    return editor_path;
}

/*
 * Determine which editor to use.  We don't need to worry about restricting
 * this to a "safe" editor since it runs with the uid of the invoking user,
 * not the runas (privileged) user.
 * Fills in argv_out with an argument vector suitable for execve() that
 * includes the editor with the specified files.
 */
static char *
find_editor(argc_out, argv_out)
    int *argc_out;
    char ***argv_out;
{
    char *cp, *editor, *editor_path = NULL, **ev, *ev0[4];

    /*
     * If any of SUDO_EDITOR, VISUAL or EDITOR are set, choose the first one.
     */
    ev0[0] = "SUDO_EDITOR";
    ev0[1] = "VISUAL";
    ev0[2] = "EDITOR";
    ev0[3] = NULL;
    for (ev = ev0; *ev != NULL; ev++) {
	if ((editor = getenv(*ev)) != NULL && *editor != '\0') {
	    editor_path = resolve_editor(editor, argc_out, argv_out);
	    if (editor_path != NULL)
		break;
	}
    }
    if (editor_path == NULL) {
	/* def_editor could be a path, split it up */
	editor = estrdup(def_editor);
	cp = strtok(editor, ":");
	while (cp != NULL && editor_path == NULL) {
	    editor_path = resolve_editor(cp, argc_out, argv_out);
	    cp = strtok(NULL, ":");
	}
	if (editor_path)
	    efree(editor);
    }
    if (!editor_path) {
	audit_failure(NewArgv, "%s: command not found", editor);
	warningx("%s: command not found", editor);
    }
    return editor_path;
}

#else /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */

/*
 * Must have the ability to change the effective uid to use sudoedit.
 */
int
sudo_edit(argc, argv, envp)
    int argc;
    char *argv[];
    char *envp[];
{
    return 1;
}

#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */
