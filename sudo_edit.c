/*
 * Copyright (c) 2004 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_ERR_H
# include <err.h>
#else
# include "emul/err.h"
#endif /* HAVE_ERR_H */
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 */
int sudo_edit(argc, argv)
    int argc;
    char **argv;
{
    ssize_t nread, nwritten;
    pid_t pid;
    const char *tmpdir;
    char **nargv, **ap, *editor, *cp;
    char buf[BUFSIZ];
    int i, ac, ofd, tfd, nargc, rval;
    struct stat sb;
    struct tempfile {
	char *tfile;
	char *ofile;
	time_t omtime;		/* XXX - use st_mtimespec / st_mtim? */
	off_t osize;
    } *tf;

    /*
     * Find our temporary directory, one of /var/tmp, /usr/tmp, or /tmp
     */
    if (stat(_PATH_VARTMP, &sb) == 0 && S_ISDIR(sb.st_mode))
	tmpdir = _PATH_VARTMP;
    else if (stat(_PATH_USRTMP, &sb) == 0 && S_ISDIR(sb.st_mode))
	tmpdir = _PATH_USRTMP;
    else
	tmpdir = _PATH_TMP;

    /*
     * For each file specified, by the user, make a tempoary version
     * and copy the contents of the original to it.  We make these files
     * as root so the user can't steal them out from under us until we are
     * done writing (and at that point the user will be able to edit the
     * file anyway).
     * XXX - It would be nice to lock the original files but that means
     *       keeping an fd open for each file.
     */
    tf = emalloc2(argc - 1, sizeof(*tf));
    memset(tf, 0, (argc - 1) * sizeof(*tf));
    for (i = 0, ap = argv + 1; i < argc - 1 && *ap != NULL; i++, ap++) {
	set_perms(PERM_RUNAS);
	ofd = open(*ap, O_RDONLY, 0644);
	if (ofd != -1) {
#ifdef HAVE_FSTAT
	    if (fstat(ofd, &sb) != 0) {
#else
	    if (stat(tf[i].ofile, &sb) != 0) {
#endif
		close(ofd);
		ofd = -1;
	    }
	}
	set_perms(PERM_ROOT);
	if (ofd == -1) {
	    if (errno != ENOENT) {
		warn("%s", *ap);
		argc--;
		i--;
		continue;
	    }
	    sb.st_mtime = 0;
	    sb.st_size = 0;
	}
	tf[i].ofile = *ap;
	tf[i].omtime = sb.st_mtime;
	tf[i].osize = sb.st_size;
	if ((cp = strrchr(tf[i].ofile, '/')) != NULL)
	    cp++;
	else
	    cp = tf[i].ofile;
	easprintf(&tf[i].tfile, "%s%s.XXXXXXXX", tmpdir, cp);
	if ((tfd = mkstemp(tf[i].tfile)) == -1) {
	    warn("mkstemp");
	    goto cleanup;
	}
	if (ofd != -1) {
	    while ((nread = read(ofd, buf, sizeof(buf))) != 0) {
		if ((nwritten = write(tfd, buf, nread)) != nread) {
		    if (nwritten == -1)
			warn("%s", tf[i].tfile);
		    else
			warnx("%s: short write", tf[i].tfile);
		    goto cleanup;
		}
	    }
	}
#ifdef HAVE_FCHOWN
	fchown(tfd, user_uid, user_gid);
#else
	chown(tf[i].tfile, user_uid, user_gid);
#endif
	if (ofd != -1)
	    close(ofd);
	close(tfd);
	touch(tf[i].tfile, tf[i].omtime);
    }
    if (argc == 1)
	return(1);			/* no files readable, you lose */

    /*
     * Determine which editor to use.  We don't bother restricting this
     * based on def_env_editor or def_editor since the editor runs with
     * the uid of the invoking user, not the runas (privileged) user.
     */
    if (((editor = getenv("VISUAL")) != NULL && *editor != '\0') ||
	((editor = getenv("EDITOR")) != NULL && *editor != '\0')) {
	editor = estrdup(editor);
    } else {
	editor = estrdup(def_editor);
	if ((cp = strchr(editor, ':')) != NULL)
	    *cp = '\0';			/* def_editor could be a path */
    }

    /*
     * Allocate space for the new argument vector and fill it in.
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = argc;
    for (cp = editor + 1; *cp != '\0'; cp++) {
	if (isblank((unsigned char)cp[0]) && !isblank((unsigned char)cp[-1]))
	    nargc++;
    }
    nargv = (char **) emalloc2(nargc + 1, sizeof(char *));
    ac = 0;
    for ((cp = strtok(editor, " \t")); cp != NULL; (cp = strtok(NULL, " \t")))
	nargv[ac++] = cp;
    for (i = 0; i < argc - 1 && ac < nargc; )
	nargv[ac++] = tf[i++].tfile;
    nargv[ac] = NULL;

    /*
     * Fork and exec the editor as with the invoking user's creds.
     */
    pid = fork();
    if (pid == -1) {
	warn("fork");
	goto cleanup;
    } else if (pid == 0) {
	/* child */
	set_perms(PERM_FULL_USER);
	execvp(nargv[0], nargv);
	warn("unable to execute %s", nargv[0]);
	_exit(127);
    }

    /* In parent, wait for child to finish. */
#ifdef sudo_waitpid
    pid = sudo_waitpid(pid, &i, 0);
#else
    pid = wait(&i);
#endif
    rval = pid == -1 ? -1 : (i >> 8);

    /* Copy contents of temp files to real ones */
    for (i = 0; i < argc - 1; i++) {
	/* XXX - open file with PERM_USER for nfs? */
	if ((tfd = open(tf[i].tfile, O_RDONLY, 0644)) == -1) {
	    warn("unable to read edited file %s, cannot update %s",
		tf[i].tfile, tf[i].ofile);
	    continue;
	}
#ifdef HAVE_FSTAT
	if (fstat(tfd, &sb) == 0) {
#else
	if (stat(tf[i].tfile, &sb) == 0) {
#endif
	    if (tf[i].osize == sb.st_size && tf[i].omtime == sb.st_mtime) {
		warnx("%s unchanged", tf[i].ofile);
		unlink(tf[i].tfile);
		close(tfd);
		continue;
	    }
	}
	set_perms(PERM_RUNAS);
	ofd = open(tf[i].ofile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	set_perms(PERM_ROOT);
	if (ofd == -1) {
	    warn("unable to save to %s, contents of edit session saved in %s",
		tf[i].ofile, tf[i].tfile);
	    close(tfd);
	    continue;
	}
	while ((nread = read(tfd, buf, sizeof(buf))) != 0) {
	    if ((nwritten = write(ofd, buf, nread)) != nread) {
		if (nwritten == -1)
		    warn("%s", tf[i].ofile);
		else
		    warnx("%s: short write", tf[i].ofile);
		break;
	    }
	}
	if (nread == 0)
	    unlink(tf[i].tfile);
	else
	    warn("unable to save to %s, contents of edit session saved in %s",
		tf[i].ofile, tf[i].tfile);
	close(ofd);
	close(tfd);
    }

    return(rval);
cleanup:
    /* Clean up temp files and return. */
    for (i = 0; i < argc - 1; i++) {
	if (tf[i].tfile != NULL)
	    unlink(tf[i].tfile);
    }
    return(1);
}
