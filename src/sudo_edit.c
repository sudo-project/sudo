/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2008, 2010-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <fcntl.h>

#include "sudo.h"
#include "sudo_edit.h"
#include "sudo_exec.h"

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)

/*
 * Editor temporary file name along with original name, mtime and size.
 */
struct tempfile {
    char *tfile;
    char *ofile;
    off_t osize;
    struct timespec omtim;
};

static char edit_tmpdir[MAX(sizeof(_PATH_VARTMP), sizeof(_PATH_TMP))];

/*
 * Find our temporary directory, one of /var/tmp, /usr/tmp, or /tmp
 * Returns true on success, else false;
 */
static bool
set_tmpdir(struct command_details *command_details)
{
    const char *tdir = NULL;
    const char *tmpdirs[] = {
	_PATH_VARTMP,
#ifdef _PATH_USRTMP
	_PATH_USRTMP,
#endif
	_PATH_TMP
    };
    unsigned int i;
    size_t len;
    int dfd;
    debug_decl(set_tmpdir, SUDO_DEBUG_EDIT)

    for (i = 0; tdir == NULL && i < nitems(tmpdirs); i++) {
	if ((dfd = open(tmpdirs[i], O_RDONLY)) != -1) {
	    if (dir_is_writable(dfd, &user_details, command_details) == true)
		tdir = tmpdirs[i];
	    close(dfd);
	}
    }
    if (tdir == NULL)
	sudo_fatalx(U_("no writable temporary directory found"));
   
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

/*
 * Construct a temporary file name for file and return an
 * open file descriptor.  The temporary file name is stored
 * in tfile which the caller is responsible for freeing.
 */
static int
sudo_edit_mktemp(const char *ofile, char **tfile)
{
    const char *cp, *suff;
    int len, tfd;
    debug_decl(sudo_edit_mktemp, SUDO_DEBUG_EDIT)

    if ((cp = strrchr(ofile, '/')) != NULL)
	cp++;
    else
	cp = ofile;
    suff = strrchr(cp, '.');
    if (suff != NULL) {
	len = asprintf(tfile, "%s/%.*sXXXXXXXX%s", edit_tmpdir,
	    (int)(size_t)(suff - cp), cp, suff);
    } else {
	len = asprintf(tfile, "%s/%s.XXXXXXXX", edit_tmpdir, cp);
    }
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
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
    struct tempfile *tf, char *files[], int nfiles)
{
    int i, j, tfd, ofd, rc;
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
	ofd = sudo_edit_open(files[i], O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, &user_details, command_details);
	if (ofd != -1 || errno == ENOENT) {
	    if (ofd == -1) {
		/*
		 * New file, verify parent dir exists unless in cwd.
		 * This fails early so the user knows ahead of time if the
		 * edit won't succeed.  Additional checks are performed
		 * when copying the temporary file back to the origin.
		 */
		char *slash = strrchr(files[i], '/');
		if (slash != NULL && slash != files[i]) {
		    const int sflags = command_details->flags;
		    const int serrno = errno;
		    int dfd;

		    /*
		     * The parent directory is allowed to be a symbolic
		     * link as long as *its* parent is not writable.
		     */
		    *slash = '\0';
		    SET(command_details->flags, CD_SUDOEDIT_FOLLOW);
		    dfd = sudo_edit_open(files[i], DIR_OPEN_FLAGS,
			S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, &user_details,
			command_details);
		    command_details->flags = sflags;
		    if (dfd != -1) {
			if (fstat(dfd, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			    memset(&sb, 0, sizeof(sb));
			    rc = 0;
			}
			close(dfd);
		    }
		    *slash = '/';
		    errno = serrno;
		} else {
		    memset(&sb, 0, sizeof(sb));
		    rc = 0;
		}
	    } else {
		rc = fstat(ofd, &sb);
	    }
	}
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (ofd != -1 && !S_ISREG(sb.st_mode)) {
	    sudo_warnx(U_("%s: not a regular file"), files[i]);
	    close(ofd);
	    continue;
	}
	if (rc == -1) {
	    /* open() or fstat() error. */
	    if (ofd == -1 && errno == ELOOP) {
		sudo_warnx(U_("%s: editing symbolic links is not permitted"),
		    files[i]);
	    } else if (ofd == -1 && errno == EISDIR) {
		sudo_warnx(U_("%s: editing files in a writable directory is not permitted"),
		    files[i]);
	    } else {
		sudo_warn("%s", files[i]);
	    }
	    if (ofd != -1)
		close(ofd);
	    continue;
	}
	tf[j].ofile = files[i];
	tf[j].osize = sb.st_size;
	mtim_get(&sb, tf[j].omtim);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", (unsigned int)user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%u)", (unsigned int)user_details.uid);
	tfd = sudo_edit_mktemp(tf[j].ofile, &tf[j].tfile);
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	if (tfd == -1) {
	    sudo_warn("mkstemps");
	    if (ofd != -1)
		close(ofd);
	    debug_return_int(-1);
	}
	if (ofd != -1) {
	    if (sudo_copy_file(tf[j].ofile, ofd, tf[j].osize, tf[j].tfile, tfd, -1) == -1) {
		close(ofd);
		close(tfd);
		debug_return_int(-1);
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
    int i, tfd, ofd, errors = 0;
    struct timespec ts;
    struct stat sb;
    mode_t oldmask;
    debug_decl(sudo_edit_copy_tfiles, SUDO_DEBUG_EDIT)

    /* Copy contents of temp files to real ones. */
    for (i = 0; i < nfiles; i++) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", (unsigned int)user_details.uid);
	if (seteuid(user_details.uid) != 0)
	    sudo_fatal("seteuid(%u)", (unsigned int)user_details.uid);
	tfd = sudo_edit_open(tf[i].tfile, O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, &user_details, NULL);
	if (seteuid(ROOT_UID) != 0)
	    sudo_fatal("seteuid(ROOT_UID)");
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "seteuid(%u)", ROOT_UID);
	if (tfd == -1 || !sudo_check_temp_file(tfd, tf[i].tfile, user_details.uid, &sb)) {
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
		continue;
	    }
	}
	switch_user(command_details->euid, command_details->egid,
	    command_details->ngroups, command_details->groups);
	oldmask = umask(command_details->umask);
	ofd = sudo_edit_open(tf[i].ofile, O_WRONLY|O_CREAT,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, &user_details, command_details);
	umask(oldmask);
	switch_user(ROOT_UID, user_details.egid,
	    user_details.ngroups, user_details.groups);
	if (ofd == -1) {
	    sudo_warn(U_("unable to write to %s"), tf[i].ofile);
	    goto bad;
	}

	/* Overwrite the old file with the new contents. */
	if (sudo_copy_file(tf[i].tfile, tfd, sb.st_size, tf[i].ofile, ofd,
		tf[i].osize) == 0) {
	    /* success, remove temporary file. */
	    unlink(tf[i].tfile);
	} else {
bad:
	    sudo_warnx(U_("contents of edit session left in %s"), tf[i].tfile);
	    errors++;
	}

	if (ofd != -1)
	    close(ofd);
	close(tfd);
    }
    debug_return_int(errors);
}

#ifdef HAVE_SELINUX
static int
selinux_run_helper(uid_t uid, gid_t gid, int ngroups, GETGROUPS_T *groups,
    char *const argv[], char *const envp[])
{
    int status, ret = SESH_ERR_FAILURE;
    const char *sesh;
    pid_t child, pid;
    debug_decl(selinux_run_helper, SUDO_DEBUG_EDIT);

    sesh = sudo_conf_sesh_path();
    if (sesh == NULL) {
	sudo_warnx("internal error: sesh path not set");
	debug_return_int(-1);
    }

    child = sudo_debug_fork();
    switch (child) {
    case -1:
	sudo_warn(U_("unable to fork"));
	break;
    case 0:
	/* child runs sesh in new context */
	if (selinux_setcon() == 0) {
	    switch_user(uid, gid, ngroups, groups);
	    execve(sesh, argv, envp);
	}
	_exit(SESH_ERR_FAILURE);
    default:
	/* parent waits */
	do {
	    pid = waitpid(child, &status, 0);
	} while (pid == -1 && errno == EINTR);

	ret = WIFSIGNALED(status) ? SESH_ERR_KILLED : WEXITSTATUS(status);
    }

    debug_return_int(ret);
}

static int
selinux_edit_create_tfiles(struct command_details *command_details,
    struct tempfile *tf, char *files[], int nfiles)
{
    char **sesh_args, **sesh_ap;
    int i, error, sesh_nargs, ret = -1;
    struct stat sb;
    debug_decl(selinux_edit_create_tfiles, SUDO_DEBUG_EDIT)
    
    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    sesh_nargs = 4 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = reallocarray(NULL, sesh_nargs, sizeof(char *));
    if (sesh_args == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    if (!ISSET(command_details->flags, CD_SUDOEDIT_FOLLOW))
	*sesh_ap++ = "-h";
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
	    free(tfile);
	    goto done;
	}
	/* Helper will re-create temp file with proper security context. */
	close(tfd);
	unlink(tfile);
	*sesh_ap++  = tfile;
	tf[i].tfile = tfile;
    }
    *sesh_ap = NULL;

    /* Run sesh -e [-h] 0 <o1> <t1> ... <on> <tn> */
    error = selinux_run_helper(command_details->uid, command_details->gid,
	command_details->ngroups, command_details->groups, sesh_args,
	command_details->envp);
    switch (error) {
    case SESH_SUCCESS:
	break;
    case SESH_ERR_BAD_PATHS:
	sudo_fatalx(U_("sesh: internal error: odd number of paths"));
    case SESH_ERR_NO_FILES:
	sudo_fatalx(U_("sesh: unable to create temporary files"));
    case SESH_ERR_KILLED:
	sudo_fatalx(U_("sesh: killed by a signal"));
    default:
	sudo_warnx(U_("sesh: unknown error %d"), error);
	goto done;
    }

    for (i = 0; i < nfiles; i++) {
	int tfd = open(tf[i].tfile, O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
	if (tfd == -1) {
	    sudo_warn(U_("unable to open %s"), tf[i].tfile);
	    goto done;
	}
	if (!sudo_check_temp_file(tfd, tf[i].tfile, command_details->uid, NULL)) {
	    close(tfd);
	    goto done;
	}
	if (fchown(tfd, user_details.uid, user_details.gid) != 0) {
	    sudo_warn("unable to chown(%s) to %d:%d for editing",
		tf[i].tfile, user_details.uid, user_details.gid);
	    close(tfd);
	    goto done;
	}
	close(tfd);
    }
    ret = nfiles;

done:
    /* Contents of tf will be freed by caller. */
    free(sesh_args);

    debug_return_int(ret);
}

static int
selinux_edit_copy_tfiles(struct command_details *command_details,
    struct tempfile *tf, int nfiles, struct timespec *times)
{
    char **sesh_args, **sesh_ap;
    int i, error, sesh_nargs, ret = 1;
    int tfd = -1;
    struct timespec ts;
    struct stat sb;
    debug_decl(selinux_edit_copy_tfiles, SUDO_DEBUG_EDIT)
    
    if (nfiles < 1)
	debug_return_int(0);

    /* Construct common args for sesh */
    sesh_nargs = 3 + (nfiles * 2) + 1;
    sesh_args = sesh_ap = reallocarray(NULL, sesh_nargs, sizeof(char *));
    if (sesh_args == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    *sesh_ap++ = "sesh";
    *sesh_ap++ = "-e";
    *sesh_ap++ = "1";

    /* Construct args for sesh -e 1 */
    for (i = 0; i < nfiles; i++) {
	if (tfd != -1)
	    close(tfd);
	if ((tfd = open(tf[i].tfile, O_RDONLY|O_NONBLOCK|O_NOFOLLOW)) == -1) {
	    sudo_warn(U_("unable to open %s"), tf[i].tfile);
	    continue;
	}
	if (!sudo_check_temp_file(tfd, tf[i].tfile, user_details.uid, &sb))
	    continue;
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
	*sesh_ap++ = tf[i].tfile;
	*sesh_ap++ = tf[i].ofile;
	if (fchown(tfd, command_details->uid, command_details->gid) != 0) {
	    sudo_warn("unable to chown(%s) back to %d:%d", tf[i].tfile,
		command_details->uid, command_details->gid);
	}
    }
    *sesh_ap = NULL;
    if (tfd != -1)
	close(tfd);

    if (sesh_ap - sesh_args > 3) {
	/* Run sesh -e 1 <t1> <o1> ... <tn> <on> */
	error = selinux_run_helper(command_details->uid, command_details->gid,
	    command_details->ngroups, command_details->groups, sesh_args,
	    command_details->envp);
	switch (error) {
	case SESH_SUCCESS:
	    ret = 0;
	    break;
	case SESH_ERR_NO_FILES:
	    sudo_warnx(U_("unable to copy temporary files back to their original location"));
	    break;
	case SESH_ERR_SOME_FILES:
	    sudo_warnx(U_("unable to copy some of the temporary files back to their original location"));
	    break;
	case SESH_ERR_KILLED:
	    sudo_warnx(U_("sesh: killed by a signal"));
	    break;
	default:
	    sudo_warnx(U_("sesh: unknown error %d"), error);
	    break;
	}
	if (ret != 0)
	    sudo_warnx(U_("contents of edit session left in %s"), edit_tmpdir);
    }
    free(sesh_args);

    debug_return_int(ret);
}
#endif /* HAVE_SELINUX */

/*
 * Wrapper to allow users to edit privileged files with their own uid.
 * Returns the wait status of the command on success and a wait status
 * of 1 on failure.
 */
int
sudo_edit(struct command_details *command_details)
{
    struct command_details saved_command_details;
    char **nargv = NULL, **ap, **files = NULL;
    int errors, i, ac, nargc, ret;
    int editor_argc = 0, nfiles = 0;
    struct timespec times[2];
    struct tempfile *tf = NULL;
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)

    if (!set_tmpdir(command_details))
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

#ifdef HAVE_SELINUX
    /* Compute new SELinux security context. */
    if (ISSET(command_details->flags, CD_RBAC_ENABLED)) {
	if (selinux_setup(command_details->selinux_role,
		command_details->selinux_type, NULL, -1, false) != 0)
	    goto cleanup;
    }
#endif

    /* Copy editor files to temporaries. */
    tf = calloc(nfiles, sizeof(*tf));
    if (tf == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }
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
    nargv = reallocarray(NULL, nargc + 1, sizeof(char *));
    if (nargv == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }
    for (ac = 0; ac < editor_argc; ac++)
	nargv[ac] = command_details->argv[ac];
    for (i = 0; i < nfiles && ac < nargc; )
	nargv[ac++] = tf[i++].tfile;
    nargv[ac] = NULL;

    /*
     * Run the editor with the invoking user's creds,
     * keeping track of the time spent in the editor.
     * XXX - should run editor with user's context
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
    ret = run_command(command_details);
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
    if (errors) {
	/* Preserve the edited temporary files. */
	ret = W_EXITCODE(1, 0);
    }

    for (i = 0; i < nfiles; i++)
	free(tf[i].tfile);
    free(tf);
    free(nargv);
    debug_return_int(ret);

cleanup:
    /* Clean up temp files and return. */
    if (tf != NULL) {
	for (i = 0; i < nfiles; i++) {
	    if (tf[i].tfile != NULL)
		unlink(tf[i].tfile);
	    free(tf[i].tfile);
	}
    }
    free(tf);
    free(nargv);
    debug_return_int(W_EXITCODE(1, 0));
}

#else /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */

/*
 * Must have the ability to change the effective uid to use sudoedit.
 */
int
sudo_edit(struct command_details *command_details)
{
    debug_decl(sudo_edit, SUDO_DEBUG_EDIT)
    debug_return_int(W_EXITCODE(1, 0));
}

#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */
