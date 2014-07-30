/*
 * Copyright (c) 2004-2008, 2010-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif

#include "sudo.h"

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)

static void
switch_user(uid_t euid, gid_t egid, int ngroups, GETGROUPS_T *groups)
{
    int serrno = errno;
    debug_decl(switch_user, SUDO_DEBUG_EDIT)

    /* When restoring root, change euid first; otherwise change it last. */
    if (euid == ROOT_UID) {
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
    }
    if (setegid(egid) != 0)
	sudo_fatal("setegid(%d)", (int)egid);
    if (ngroups != -1) {
	if (sudo_setgroups(ngroups, groups) != 0)
	    sudo_fatal("setgroups");
    }
    if (euid != ROOT_UID) {
	if (seteuid(euid) != 0)
	    sudo_fatal("seteuid(%d)", (int)euid);
    }
    errno = serrno;

    debug_return;
}

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 */
int
sudo_edit(struct command_details *command_details)
{
    struct command_details saved_command_details;
    ssize_t nread, nwritten;
    const char *tmpdir;
    char *cp, *suff, **nargv, **ap, **files = NULL;
    char buf[BUFSIZ];
    int rc, i, j, ac, ofd, tfd, nargc, rval, tmplen;
    int editor_argc = 0, nfiles = 0;
    struct stat sb;
    struct timeval tv, times[2];
    struct tempfile {
	char *tfile;
	char *ofile;
	struct timeval omtim;
	off_t osize;
    } *tf = NULL;
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)

    /*
     * Set real, effective and saved uids to root.
     * We will change the euid as needed below.
     */
    if (setuid(ROOT_UID) != 0) {
	sudo_warn(U_("unable to change uid to root (%u)"), ROOT_UID);
	goto cleanup;
    }

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
     * The user's editor must be separated from the files to be
     * edited by a "--" option.
     */
    for (ap = command_details->argv; *ap != NULL; ap++) {
	if (files)
	    nfiles++;
	else if (strcmp(*ap, "--") == 0)
	    files = ap + 1;
	else
	    editor_argc++;
    }
    if (nfiles == 0) {
	sudo_warnx(U_("plugin error: missing file list for sudoedit"));
	goto cleanup;
    }

    /*
     * For each file specified by the user, make a temporary version
     * and copy the contents of the original to it.
     */
    tf = sudo_emallocarray(nfiles, sizeof(*tf));
    memset(tf, 0, nfiles * sizeof(*tf));
    for (i = 0, j = 0; i < nfiles; i++) {
	rc = -1;
	switch_user(command_details->euid, command_details->egid,
	    command_details->ngroups, command_details->groups);
	if ((ofd = open(files[i], O_RDONLY, 0644)) != -1 || errno == ENOENT) {
	    if (ofd == -1) {
		memset(&sb, 0, sizeof(sb));		/* new file */
		rc = 0;
	    } else {
		rc = fstat(ofd, &sb);
	    }
	}
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (rc || (ofd != -1 && !S_ISREG(sb.st_mode))) {
	    if (rc)
		sudo_warn("%s", files[i]);
	    else
		sudo_warnx(U_("%s: not a regular file"), files[i]);
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
	    sudo_easprintf(&tf[j].tfile, "%.*s/%.*sXXXXXXXX%s", tmplen, tmpdir,
		(int)(size_t)(suff - cp), cp, suff);
	} else {
	    sudo_easprintf(&tf[j].tfile, "%.*s/%s.XXXXXXXX", tmplen, tmpdir, cp);
	}
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%d)", (int)user_details.uid);
	tfd = mkstemps(tf[j].tfile, suff ? strlen(suff) : 0);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    goto cleanup;
	}
	if (ofd != -1) {
	    while ((nread = read(ofd, buf, sizeof(buf))) != 0) {
		if ((nwritten = write(tfd, buf, nread)) != nread) {
		    if (nwritten == -1)
			sudo_warn("%s", tf[j].tfile);
		    else
			sudo_warnx(U_("%s: short write"), tf[j].tfile);
		    goto cleanup;
		}
	    }
	    close(ofd);
	}
	/*
	 * We always update the stashed mtime because the time
	 * resolution of the filesystem the temporary file is on may
	 * not match that of the filesystem where the file to be edited
	 * resides.  It is OK if futimes() fails since we only use the
	 * info to determine whether or not a file has been modified.
	 */
	times[0].tv_sec = times[1].tv_sec = tf[j].omtim.tv_sec;
	times[0].tv_usec = times[1].tv_usec = tf[j].omtim.tv_usec;
#ifdef HAVE_FUTIMES
	(void) futimes(tfd, times);
#else
	(void) utimes(tf[j].tfile, times);
#endif
	rc = fstat(tfd, &sb);
	if (!rc)
	    mtim_get(&sb, &tf[j].omtim);
	close(tfd);
	j++;
    }
    if ((nfiles = j) == 0)
	goto cleanup;		/* no files readable, you lose */

    /*
     * Allocate space for the new argument vector and fill it in.
     * We concatenate the editor with its args and the file list
     * to create a new argv.
     */
    nargc = editor_argc + nfiles;
    nargv = sudo_emallocarray(nargc + 1, sizeof(char *));
    for (ac = 0; ac < editor_argc; ac++)
	nargv[ac] = command_details->argv[ac];
    for (i = 0; i < nfiles && ac < nargc; )
	nargv[ac++] = tf[i++].tfile;
    nargv[ac] = NULL;

    /*
     * Run the editor with the invoking user's creds,
     * keeping track of the time spent in the editor.
     */
    gettimeofday(&times[0], NULL);
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->uid = user_details.uid;
    command_details->euid = user_details.uid;
    command_details->gid = user_details.gid;
    command_details->egid = user_details.gid;
    command_details->ngroups = user_details.ngroups;
    command_details->groups = user_details.groups;
    command_details->argv = nargv;
    rval = run_command(command_details);
    gettimeofday(&times[1], NULL);

    /* Restore saved command_details. */
    command_details->uid = saved_command_details.uid;
    command_details->euid = saved_command_details.uid;
    command_details->gid = saved_command_details.gid;
    command_details->egid = saved_command_details.gid;
    command_details->ngroups = saved_command_details.ngroups;
    command_details->groups = saved_command_details.groups;
    command_details->argv = saved_command_details.argv;

    /* Copy contents of temp files to real ones. */
    for (i = 0; i < nfiles; i++) {
	rc = -1;
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%d)", (int)user_details.uid);
	if ((tfd = open(tf[i].tfile, O_RDONLY, 0644)) != -1) {
	    rc = fstat(tfd, &sb);
	}
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (rc || !S_ISREG(sb.st_mode)) {
	    if (rc)
		sudo_warn("%s", tf[i].tfile);
	    else
		sudo_warnx(U_("%s: not a regular file"), tf[i].tfile);
	    sudo_warnx(U_("%s left unmodified"), tf[i].ofile);
	    if (tfd != -1)
		close(tfd);
	    continue;
	}
	mtim_get(&sb, &tv);
	if (tf[i].osize == sb.st_size && sudo_timevalcmp(&tf[i].omtim, &tv, ==)) {
	    /*
	     * If mtime and size match but the user spent no measurable
	     * time in the editor we can't tell if the file was changed.
	     */
	    if (sudo_timevalcmp(&times[0], &times[1], !=)) {
		sudo_warnx(U_("%s unchanged"), tf[i].ofile);
		unlink(tf[i].tfile);
		close(tfd);
		continue;
	    }
	}
	switch_user(command_details->euid, command_details->egid,
	    command_details->ngroups, command_details->groups);
	ofd = open(tf[i].ofile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (ofd == -1) {
	    sudo_warn(U_("unable to write to %s"), tf[i].ofile);
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	    close(tfd);
	    continue;
	}
	while ((nread = read(tfd, buf, sizeof(buf))) > 0) {
	    if ((nwritten = write(ofd, buf, nread)) != nread) {
		if (nwritten == -1)
		    sudo_warn("%s", tf[i].ofile);
		else
		    sudo_warnx(U_("%s: short write"), tf[i].ofile);
		break;
	    }
	}
	if (nread == 0) {
	    /* success, got EOF */
	    unlink(tf[i].tfile);
	} else if (nread < 0) {
	    sudo_warn(U_("unable to read temporary file"));
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	} else {
	    sudo_warn(U_("unable to write to %s"), tf[i].ofile);
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	}
	close(ofd);
    }
    efree(tf);
    efree(nargv);
    debug_return_int(rval);

cleanup:
    /* Clean up temp files and return. */
    if (tf != NULL) {
	for (i = 0; i < nfiles; i++) {
	    if (tf[i].tfile != NULL)
		unlink(tf[i].tfile);
	}
    }
    efree(tf);
    efree(nargv);
    debug_return_int(1);
}

#else /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */

/*
 * Must have the ability to change the effective uid to use sudoedit.
 */
int
sudo_edit(struct command_details *command_details)
{
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)
    debug_return_int(1);
}

#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */
