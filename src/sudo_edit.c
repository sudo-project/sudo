/*
 * Copyright (c) 2004-2008, 2010-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifndef HAVE_STRUCT_TIMESPEC
# include "compat/timespec.h"
#endif
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif

#include "sudo.h"
#include "sudo_exec.h"

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)

/*
 * Editor temporary file name along with original name, mtime and size.
 */
struct tempfile {
    char *tfile;
    char *ofile;
    struct timespec omtim;
    off_t osize;
};

static char edit_tmpdir[MAX(sizeof(_PATH_VARTMP), sizeof(_PATH_TMP))];

/*
 * Find our temporary directory, one of /var/tmp, /usr/tmp, or /tmp
 * Returns true on success, else false;
 */
static bool
set_tmpdir(void)
{
    const char *tdir;
    struct stat sb;
    size_t len;
    debug_decl(set_tmpdir, SUDO_DEBUG_EDIT)

    if (stat(_PATH_VARTMP, &sb) == 0 && S_ISDIR(sb.st_mode)) {
	tdir = _PATH_VARTMP;
    }
#ifdef _PATH_USRTMP
    else if (stat(_PATH_USRTMP, &sb) == 0 && S_ISDIR(sb.st_mode)) {
	tdir = _PATH_USRTMP;
    }
#endif
    else {
	tdir = _PATH_TMP;
    }
    len = strlcpy(edit_tmpdir, tdir, sizeof(edit_tmpdir));
    if (len >= sizeof(edit_tmpdir)) {
	errno = ENAMETOOLONG;
	sudo_warn("%s", tdir);
	debug_return_bool(false);
    }
    while (len > 0 && edit_tmpdir[--len] == '/')
	edit_tmpdir[len] = '\0';
    debug_return_bool(true);
}

static void
switch_user(uid_t euid, gid_t egid, int ngroups, GETGROUPS_T *groups)
{
    int serrno = errno;
    debug_decl(switch_user, SUDO_DEBUG_EDIT)

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"set uid:gid to %u:%u(%u)", euid, egid, ngroups ? groups[0] : egid);

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
 * Construct a temporary file name for file and return an
 * open file descriptor.  The temporary file name is stored
 * in tfile which the caller is responsible for freeing.
 */
static int
sudo_edit_mktemp(const char *ofile, char **tfile)
{
    const char *cp, *suff;
    int tfd;
    debug_decl(sudo_edit_mktemp, SUDO_DEBUG_EDIT)

    if ((cp = strrchr(ofile, '/')) != NULL)
	cp++;
    else
	cp = ofile;
    suff = strrchr(cp, '.');
    if (suff != NULL) {
	sudo_easprintf(tfile, "%s/%.*sXXXXXXXX%s", edit_tmpdir,
	    (int)(size_t)(suff - cp), cp, suff);
    } else {
	sudo_easprintf(tfile, "%s/%s.XXXXXXXX", edit_tmpdir, cp);
    }
    tfd = mkstemps(*tfile, suff ? strlen(suff) : 0);
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"%s -> %s, fd %d", ofile, *tfile, tfd);
    debug_return_int(tfd);
}

/*
 * Create temporary copies of files[] and store the temporary path name
 * along with the original name, size and mtime in tf.
 * Returns the number of files copied (which may be less than nfiles)
 * or -1 if a fatal error occurred.
 */
static int
sudo_edit_create_tfiles(struct command_details *command_details,
    struct tempfile *tf, char * const files[], int nfiles)
{
    int i, j, tfd, ofd, rc;
    char buf[BUFSIZ];
    ssize_t nwritten, nread;
    struct timespec times[2];
    struct stat sb;
    debug_decl(sudo_edit_create_tfiles, SUDO_DEBUG_EDIT)

    /*
     * For each file specified by the user, make a temporary version
     * and copy the contents of the original to it.
     */
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
	mtim_get(&sb, tf[j].omtim);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%d)", (int)user_details.uid);
	tfd = sudo_edit_mktemp(tf[j].ofile, &tf[j].tfile);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    debug_return_int(-1);
	}
	if (ofd != -1) {
	    while ((nread = read(ofd, buf, sizeof(buf))) != 0) {
		if ((nwritten = write(tfd, buf, nread)) != nread) {
		    if (nwritten == -1)
			sudo_warn("%s", tf[j].tfile);
		    else
			sudo_warnx(U_("%s: short write"), tf[j].tfile);
		    close(ofd);
		    close(tfd);
		    debug_return_int(-1);
		}
	    }
	    close(ofd);
	}
	/*
	 * We always update the stashed mtime because the time
	 * resolution of the filesystem the temporary file is on may
	 * not match that of the filesystem where the file to be edited
	 * resides.  It is OK if futimens() fails since we only use the
	 * info to determine whether or not a file has been modified.
	 */
	times[0].tv_sec = times[1].tv_sec = tf[j].omtim.tv_sec;
	times[0].tv_nsec = times[1].tv_nsec = tf[j].omtim.tv_nsec;
	if (futimens(tfd, times) == -1) {
	    if (utimensat(AT_FDCWD, tf[j].tfile, times, 0) == -1)
		sudo_warn("%s", tf[j].tfile);
	}
	rc = fstat(tfd, &sb);
	if (!rc)
	    mtim_get(&sb, tf[j].omtim);
	close(tfd);
	j++;
    }
    debug_return_int(j);
}

/*
 * Copy the temporary files specified in tf to the originals.
 * Returns the number of copy errors or 0 if completely successful.
 */
static int
sudo_edit_copy_tfiles(struct command_details *command_details,
    struct tempfile *tf, int nfiles, struct timespec *times)
{
    int i, tfd, ofd, rc, errors = 0;
    char buf[BUFSIZ];
    ssize_t nwritten, nread;
    struct timespec ts;
    struct stat sb;
    debug_decl(sudo_edit_copy_tfiles, SUDO_DEBUG_EDIT)

    /* Copy contents of temp files to real ones. */
    for (i = 0; i < nfiles; i++) {
	rc = -1;
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%d)", (int)user_details.uid);
	if ((tfd = open(tf[i].tfile, O_RDONLY, 0644)) != -1) {
	    rc = fstat(tfd, &sb);
	}
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
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
	    errors++;
	    continue;
	}
	mtim_get(&sb, ts);
	if (tf[i].osize == sb.st_size && sudo_timespeccmp(&tf[i].omtim, &ts, ==)) {
	    /*
	     * If mtime and size match but the user spent no measurable
	     * time in the editor we can't tell if the file was changed.
	     */
	    if (sudo_timespeccmp(&times[0], &times[1], !=)) {
		sudo_warnx(U_("%s unchanged"), tf[i].ofile);
		unlink(tf[i].tfile);
		close(tfd);
		errors++;
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
	    errors++;
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
	close(tfd);
    }
    debug_return_int(errors);
}

#ifdef HAVE_SELINUX
static int
selinux_edit_create_tfiles(struct command_details *command_details,
    struct tempfile *tf, char * const files[], int nfiles)
{
    char **sesh_args, **sesh_ap;
    int i, rc, sesh_nargs;
    struct stat sb;
    struct command_details saved_command_details;
    debug_decl(selinux_edit_create_tfiles, SUDO_DEBUG_EDIT)
    
    /* Prepare selinux stuff (setexeccon) */
    if (selinux_setup(command_details->selinux_role,
	command_details->selinux_type, NULL, -1) != 0)
	debug_return_int(-1);

    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->command = _PATH_SUDO_SESH;
    command_details->flags |= CD_SUDOEDIT_COPY;
    
    sesh_nargs = 3 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = sudo_emallocarray(sesh_nargs, sizeof(char *));
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    *sesh_ap++ = "0";

    for (i = 0; i < nfiles; i++) {
	char *tfile, *ofile = files[i];
	int tfd;
	*sesh_ap++  = ofile;
	tf[i].ofile = ofile;
	if (stat(ofile, &sb) == -1)
	    memset(&sb, 0, sizeof(sb));		/* new file */
	tf[i].osize = sb.st_size;
	mtim_get(&sb, tf[i].omtim);
	/*
	 * The temp file must be created by the sesh helper,
	 * which uses O_EXCL | O_NOFOLLOW to make this safe.
	 */
	tfd = sudo_edit_mktemp(ofile, &tfile);
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    sudo_efree(tfile);
	    sudo_efree(sesh_args);
	    debug_return_int(-1);
	}
	/* Helper will re-create temp file with proper security context. */
	close(tfd);
	unlink(tfile);
	*sesh_ap++  = tfile;
	tf[i].tfile = tfile;
    }
    *sesh_ap = NULL;

    /* Run sesh -e 0 <o1> <t1> ... <on> <tn> */
    command_details->argv = sesh_args;
    rc = run_command(command_details);
    switch (rc) {
    case SESH_SUCCESS:
	break;
    case SESH_ERR_BAD_PATHS:
	sudo_fatalx(_("sesh: internal error: odd number of paths"));
    case SESH_ERR_NO_FILES:
	sudo_fatalx(_("sesh: unable to create temporary files"));
    default:
	sudo_fatalx(_("sesh: unknown error %d"), rc);
    }

    /* Restore saved command_details. */
    command_details->command = saved_command_details.command;
    command_details->flags = saved_command_details.flags;
    command_details->argv = saved_command_details.argv;
    
    /* Chown to user's UID so they can edit the temporary files. */
    for (i = 0; i < nfiles; i++) {
	if (chown(tf[i].tfile, user_details.uid, user_details.gid) != 0) {
	    sudo_warn("unable to chown(%s) to %d:%d for editing",
		tf[i].tfile, user_details.uid, user_details.gid);
	}
    }

    /* Contents of tf will be freed by caller. */
    sudo_efree(sesh_args);

    return (nfiles);
}

static int
selinux_edit_copy_tfiles(struct command_details *command_details,
    struct tempfile *tf, int nfiles, struct timespec *times)
{
    char **sesh_args, **sesh_ap;
    int i, rc, sesh_nargs, rval = 1;
    struct command_details saved_command_details;
    struct timespec ts;
    struct stat sb;
    debug_decl(selinux_edit_copy_tfiles, SUDO_DEBUG_EDIT)
    
    /* Prepare selinux stuff (setexeccon) */
    if (selinux_setup(command_details->selinux_role,
	command_details->selinux_type, NULL, -1) != 0)
	debug_return_int(1);

    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->command = _PATH_SUDO_SESH;
    command_details->flags |= CD_SUDOEDIT_COPY;
    
    sesh_nargs = 3 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = sudo_emallocarray(sesh_nargs, sizeof(char *));
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    *sesh_ap++ = "1";

    /* Construct args for sesh -e 1 */
    for (i = 0; i < nfiles; i++) {
	if (stat(tf[i].tfile, &sb) == 0) {
	    mtim_get(&sb, ts);
	    if (tf[i].osize == sb.st_size && sudo_timespeccmp(&tf[i].omtim, &ts, ==)) {
		/*
		 * If mtime and size match but the user spent no measurable
		 * time in the editor we can't tell if the file was changed.
		 */
		if (sudo_timespeccmp(&times[0], &times[1], !=)) {
		    sudo_warnx(U_("%s unchanged"), tf[i].ofile);
		    unlink(tf[i].tfile);
		    continue;
		}
	    }
	}
	*sesh_ap++ = tf[i].tfile;
	*sesh_ap++ = tf[i].ofile;
	if (chown(tf[i].tfile, command_details->uid, command_details->gid) != 0) {
	    sudo_warn("unable to chown(%s) back to %d:%d", tf[i].tfile,
		command_details->uid, command_details->gid);
	}
    }
    *sesh_ap = NULL;

    if (sesh_ap - sesh_args > 3) {
	/* Run sesh -e 1 <t1> <o1> ... <tn> <on> */
	command_details->argv = sesh_args;
	rc = run_command(command_details);
	switch (rc) {
	case SESH_SUCCESS:
	    rval = 0;
	    break;
	case SESH_ERR_NO_FILES:
	    sudo_warnx(_("unable to copy temporary files back to their original location"));
	    sudo_warnx(U_("contents of edit session left in %s"), edit_tmpdir);
	    break;
	case SESH_ERR_SOME_FILES:
	    sudo_warnx(_("unable to copy some of the temporary files back to their original location"));
	    sudo_warnx(U_("contents of edit session left in %s"), edit_tmpdir);
	    break;
	default:
	    sudo_warnx(_("sesh: unknown error %d"), rc);
	    break;
	}
    }

    /* Restore saved command_details. */
    command_details->command = saved_command_details.command;
    command_details->flags = saved_command_details.flags;
    command_details->argv = saved_command_details.argv;

    debug_return_int(rval);
}
#endif /* HAVE_SELINUX */

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 * Returns 0 on success and 1 on failure.
 */
int
sudo_edit(struct command_details *command_details)
{
    struct command_details saved_command_details;
    char **nargv = NULL, **ap, **files = NULL;
    int errors, i, ac, nargc, rval;
    int editor_argc = 0, nfiles = 0;
    struct timespec times[2];
    struct tempfile *tf = NULL;
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)

    if (!set_tmpdir())
	goto cleanup;

    /*
     * Set real, effective and saved uids to root.
     * We will change the euid as needed below.
     */
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"setuid(%u)", ROOT_UID);
    if (setuid(ROOT_UID) != 0) {
	sudo_warn(U_("unable to change uid to root (%u)"), ROOT_UID);
	goto cleanup;
    }

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

    /* Copy editor files to temporaries. */
    tf = sudo_ecalloc(nfiles, sizeof(*tf));
#ifdef HAVE_SELINUX
    if (ISSET(command_details->flags, CD_RBAC_ENABLED))
	nfiles = selinux_edit_create_tfiles(command_details, tf, files, nfiles);
    else 
#endif
	nfiles = sudo_edit_create_tfiles(command_details, tf, files, nfiles);
    if (nfiles <= 0)
	goto cleanup;

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
    if (sudo_gettime_real(&times[0]) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto cleanup;
    }
    memcpy(&saved_command_details, command_details, sizeof(struct command_details));
    command_details->uid = user_details.uid;
    command_details->euid = user_details.uid;
    command_details->gid = user_details.gid;
    command_details->egid = user_details.gid;
    command_details->ngroups = user_details.ngroups;
    command_details->groups = user_details.groups;
    command_details->argv = nargv;
    rval = run_command(command_details);
    if (sudo_gettime_real(&times[1]) == -1) {
	sudo_warn(U_("unable to read the clock"));
	goto cleanup;
    }

    /* Restore saved command_details. */
    command_details->uid = saved_command_details.uid;
    command_details->euid = saved_command_details.euid;
    command_details->gid = saved_command_details.gid;
    command_details->egid = saved_command_details.egid;
    command_details->ngroups = saved_command_details.ngroups;
    command_details->groups = saved_command_details.groups;
    command_details->argv = saved_command_details.argv;

    /* Copy contents of temp files to real ones. */
#ifdef HAVE_SELINUX
    if (ISSET(command_details->flags, CD_RBAC_ENABLED))
	errors = selinux_edit_copy_tfiles(command_details, tf, nfiles, times);
    else
#endif
	errors = sudo_edit_copy_tfiles(command_details, tf, nfiles, times);

    sudo_efree(tf);
    sudo_efree(nargv);
    debug_return_int(errors ? 1 : rval);

cleanup:
    /* Clean up temp files and return. */
    if (tf != NULL) {
	for (i = 0; i < nfiles; i++) {
	    if (tf[i].tfile != NULL)
		unlink(tf[i].tfile);
	}
    }
    sudo_efree(tf);
    sudo_efree(nargv);
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
