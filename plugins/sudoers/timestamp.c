/*
 * Copyright (c) 2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/time.h>
#include <sys/stat.h>
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
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_STRUCT_TIMESPEC
# include "compat/timespec.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "secure_path.h"
#include "check.h"

/* On Linux, CLOCK_MONOTONIC does not run while suspended. */
#if defined(CLOCK_BOOTTIME)
# define SUDO_CLOCK_MONOTONIC	CLOCK_BOOTTIME
#elif defined(CLOCK_MONOTONIC)
# define SUDO_CLOCK_MONOTONIC	CLOCK_MONOTONIC
#else
# define SUDO_CLOCK_MONOTONIC	CLOCK_REALTIME
#endif

static char timestamp_file[PATH_MAX];
static off_t timestamp_hint = (off_t)-1;
static struct timestamp_entry timestamp_key;

static bool
ts_match_record(struct timestamp_entry *key, struct timestamp_entry *entry)
{
    debug_decl(ts_match_record, SUDO_DEBUG_AUTH)

    if (entry->version != key->version)
	debug_return_bool(false);
    if (!ISSET(key->flags, TS_ANYUID) && entry->auth_uid != key->auth_uid)
	debug_return_bool(false);
    if (entry->type != key->type)
	debug_return_bool(false);
    switch (entry->type) {
    case TS_GLOBAL:
	/* no ppid or tty to match */
	break;
    case TS_PPID:
	/* verify parent pid */
	if (entry->u.ppid != key->u.ppid)
	    debug_return_bool(false);
	break;
    case TS_TTY:
	if (entry->u.ttydev != key->u.ttydev)
	    debug_return_bool(false);
	break;
    default:
	/* unknown record type, ignore it */
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
ts_find_record(int fd, struct timestamp_entry *key, struct timestamp_entry *entry)
{
    struct timestamp_entry cur;
    debug_decl(ts_find_record, SUDO_DEBUG_AUTH)

    /*
     * Look for a matching record.
     * We don't match on the sid or actual time stamp.
     */
    while (read(fd, &cur, sizeof(cur)) == sizeof(cur)) {
	if (cur.size != sizeof(cur)) {
	    /* wrong size, seek to next record */
	    lseek(fd, (off_t)cur.size - (off_t)sizeof(cur), SEEK_CUR);
	    continue;
	}
	if (ts_match_record(key, &cur)) {
	    memcpy(entry, &cur, sizeof(struct timestamp_entry));
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

/* Find matching record to update or append a new one. */
static bool
ts_update_record(int fd, struct timestamp_entry *entry, off_t timestamp_hint)
{
    struct timestamp_entry cur;
    ssize_t nwritten;
    off_t old_eof = (off_t)-1;
    debug_decl(ts_update_record, SUDO_DEBUG_AUTH)

    /* First try the hint if one is given. */
    if (timestamp_hint != (off_t)-1) {
	if (lseek(fd, timestamp_hint, SEEK_SET) != -1) {
	    if (read(fd, &cur, sizeof(cur)) == sizeof(cur)) {
		if (ts_match_record(entry, &cur)) {
		    goto found_it;
		}
	    }
	}
    }

    /* Search for matching record. */
    lseek(fd, (off_t)0, SEEK_SET);
    if (ts_find_record(fd, entry, &cur)) {
found_it:
	/* back up over old record */
	lseek(fd, (off_t)0 - (off_t)cur.size, SEEK_CUR);
    } else {
	old_eof = lseek(fd, (off_t)0, SEEK_CUR);
    }

    /* Overwrite existing record or append to end. */
    nwritten = write(fd, entry, sizeof(struct timestamp_entry));
    if ((size_t)nwritten == sizeof(struct timestamp_entry))
	debug_return_bool(true);

    /* Truncate on partial write to be safe. */
    if (nwritten > 0 && old_eof != (off_t)-1)
	ftruncate(fd, old_eof);

    debug_return_bool(false);
}

/* XXX - somewhat duplicated in io_mkdirs */
static bool
ts_mkdirs(char *path, mode_t mode)
{
    struct stat sb;
    gid_t parent_gid = 0;
    char *slash = path;
    bool rval = false;
    debug_decl(ts_mkdirs, SUDO_DEBUG_AUTH)

    while ((slash = strchr(slash + 1, '/')) != NULL) {
	*slash = '\0';
	if (stat(path, &sb) != 0) {
	    if (mkdir(path, mode) != 0) {
		warning(N_("unable to mkdir %s"), path);
		goto done;
	    }
	    ignore_result(chown(path, (uid_t)-1, parent_gid));
	} else if (!S_ISDIR(sb.st_mode)) {
	    warningx(N_("%s exists but is not a directory (0%o)"),
		path, (unsigned int) sb.st_mode);
	    goto done;
	} else {
	    /* Inherit gid of parent dir for ownership. */
	    parent_gid = sb.st_gid;
	}
	*slash = '/';
    }
    /* Create final path component. */
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
	warning(N_("unable to mkdir %s"), path);
	goto done;
    }
    ignore_result(chown(path, (uid_t)-1, parent_gid));
    rval = true;
done:
    debug_return_bool(rval);
}

static bool
ts_secure_dir(char *path, bool make_it)
{
    struct stat sb;
    bool rval = false;
    debug_decl(ts_secure_dir, SUDO_DEBUG_AUTH)

    switch (sudo_secure_dir(path, timestamp_uid, -1, &sb)) {
    case SUDO_PATH_SECURE:
	rval = true;
	break;
    case SUDO_PATH_MISSING:
	if (make_it) {
	    ts_mkdirs(path, 0700);
	    rval = true;
	}
	break;
    case SUDO_PATH_BAD_TYPE:
	errno = ENOTDIR;
	warning("%s", path);
	break;
    case SUDO_PATH_WRONG_OWNER:
	warningx(U_("%s is owned by uid %u, should be %u"),
	    path, (unsigned int) sb.st_uid,
	    (unsigned int) timestamp_uid);
	break;
    case SUDO_PATH_GROUP_WRITABLE:
	warningx(U_("%s is group writable"), path);
	break;
    }
    debug_return_bool(rval);
}

/*
 * Fills in timestamp_file[].
 */
int
build_timestamp(struct passwd *pw)
{
    int len;
    debug_decl(build_timestamp, SUDO_DEBUG_AUTH)

    len = snprintf(timestamp_file, sizeof(timestamp_file), "%s/%s",
	def_timestampdir, user_name);
    if (len <= 0 || (size_t)len >= sizeof(timestamp_file)) {
	log_fatal(0, N_("timestamp path too long: %s/%s"),
	    def_timestampdir, user_name);
    }

    debug_return_int(len);
}

/*
 * Update the time on the timestamp file/dir or create it if necessary.
 */
bool
update_timestamp(struct passwd *pw)
{
    struct timestamp_entry entry;
    bool rval = false;
    int fd;
    debug_decl(update_timestamp, SUDO_DEBUG_AUTH)

    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);

    /* Check/create parent directories as needed. */
    if (!ts_secure_dir(def_timestampdir, true))
	goto done;

    /* Fill in time stamp. */
    memcpy(&entry, &timestamp_key, sizeof(struct timestamp_entry));
    clock_gettime(SUDO_CLOCK_MONOTONIC, &entry.ts);

    /* Open time stamp file and lock it for exclusive access. */
    fd = open(timestamp_file, O_RDWR|O_CREAT, 0600);
    if (fd == -1) {
	log_warning(USE_ERRNO, N_("unable to open %s"), timestamp_file);
	goto done;
    }

    /* Update record or append a new one. */
    lock_file(fd, SUDO_LOCK);
    ts_update_record(fd, &entry, timestamp_hint);
    close(fd);

    rval = true;

done:
    if (timestamp_uid != 0)
	restore_perms();
    debug_return_bool(rval);
}

/*
 * Check the timestamp file and directory and return their status.
 */
int
timestamp_status(struct passwd *pw)
{
    struct timestamp_entry entry;
    struct timespec diff, timeout;
    int status = TS_ERROR;		/* assume the worst */
    int fd = -1;
    debug_decl(timestamp_status, SUDO_DEBUG_AUTH)

    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);

    /* Zero timeout means ignore time stamp files. */
    if (def_timestamp_timeout == 0) {
	status = TS_OLD;	/* XXX - could also be TS_MISSING */
	goto done;
    }

    /* Ignore time stamp files in an insecure directory. */
    if (!ts_secure_dir(def_timestampdir, false)) {
	status = TS_ERROR;
	goto done;
    }

    /*
     * Create a key used for matching entries in the time stamp file.
     * The actual time stamp in the key is used below as the time "now".
     */
    memset(&timestamp_key, 0, sizeof(timestamp_key));
    timestamp_key.version = TS_VERSION;
    timestamp_key.size = sizeof(timestamp_key);
    timestamp_key.type = TS_GLOBAL;	/* may be overriden below */
    if (pw != NULL) {
	timestamp_key.auth_uid = pw->pw_uid;
    } else {
	timestamp_key.flags = TS_ANYUID;
    }
    timestamp_key.sid = user_sid;
    if (def_timestampdir) {
	struct stat sb;
	if (user_ttypath != NULL && stat(user_ttypath, &sb) == 0) {
	    /* tty-based time stamp */
	    timestamp_key.type = TS_TTY;
	    timestamp_key.u.ttydev = sb.st_rdev;
	} else {
	    /* ppid-based time stamp */
	    timestamp_key.type = TS_PPID;
	    timestamp_key.u.ppid = getppid();
	}
    }
    clock_gettime(SUDO_CLOCK_MONOTONIC, &timestamp_key.ts);

    /* Open time stamp file and lock it for exclusive access. */
    fd = open(timestamp_file, O_RDONLY);
    if (fd == -1) {
	status = TS_MISSING;
	goto done;
    }

    /* Read existing record, if any. */
    lock_file(fd, SUDO_LOCK);
    if (!ts_find_record(fd, &timestamp_key, &entry)) {
	timestamp_hint = (off_t)-1;
	status = TS_MISSING;
	goto done;
    }

    /* Set record position hint for use by update_timestamp() */
    timestamp_hint = lseek(fd, (off_t)0, SEEK_CUR);
    if (timestamp_hint != (off_t)-1)
	timestamp_hint -= entry.size;

    if (ISSET(entry.flags, TS_DISABLED)) {
	status = TS_OLD;	/* disabled via sudo -k */
	goto done;
    }

    if (entry.type != TS_GLOBAL && entry.sid != timestamp_key.sid) {
	status = TS_OLD;	/* belongs to different session */
	goto done;
    }

    /* Negative timeouts only expire manually (sudo -k).  */
    if (def_timestamp_timeout < 0) {
	status = TS_CURRENT;
	goto done;
    }

    /* Compare stored time stamp with current time. */
    sudo_timespecsub(&timestamp_key.ts, &entry.ts, &diff);
    timeout.tv_sec = 60 * def_timestamp_timeout;
    timeout.tv_nsec =
	((60.0 * def_timestamp_timeout) - timeout.tv_sec) * 1000000000000000000;
    if (sudo_timespeccmp(&diff, &timeout, <)) {
	status = TS_CURRENT;
#ifdef CLOCK_MONOTONIC
	/* A monotonic clock should never run backwards. */
	if (diff.tv_sec < 0) {
	    log_warning(0, N_("ignoring time stamp from the future"));
	    status = TS_OLD;
	    SET(entry.flags, TS_DISABLED);
	    ts_update_record(fd, &entry, timestamp_hint);
	}
#else
	/* Check for bogus (future) time in the stampfile. */
	sudo_timespecsub(&entry.ts, &timestamp_key.ts, &diff);
	timeout.tv_sec *= 2;
	if (sudo_timespeccmp(&diff, &timeout, >)) {
	    time_t tv_sec = (time_t)entry.ts.tv_sec;
	    log_warning(0,
		N_("time stamp too far in the future: %20.20s"),
		4 + ctime(&tv_sec));
	    status = TS_OLD;
	    SET(entry.flags, TS_DISABLED);
	    ts_update_record(fd, &entry, timestamp_hint);
	}
#endif /* CLOCK_MONOTONIC */
    } else {
	status = TS_OLD;
    }

done:
    if (fd != -1)
	close(fd);
    if (timestamp_uid != 0)
	restore_perms();
    debug_return_int(status);
}

/*
 * Remove the timestamp entry or file.
 */
void
remove_timestamp(bool unlink_it)
{
    struct timestamp_entry entry;
    int fd = -1;
    debug_decl(remove_timestamp, SUDO_DEBUG_AUTH)

    if (build_timestamp(NULL) == -1)
	debug_return;

    /* For "sudo -K" simply unlink the time stamp file. */
    if (unlink_it) {
	(void) unlink(timestamp_file);
	debug_return;
    }

    /*
     * For "sudo -k" find matching entries and invalidate them.
     */
    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);

    /*
     * Create a key used for matching entries in the time stamp file.
     */
    memset(&timestamp_key, 0, sizeof(timestamp_key));
    timestamp_key.version = TS_VERSION;
    timestamp_key.size = sizeof(timestamp_key);
    timestamp_key.type = TS_GLOBAL;	/* may be overriden below */
    timestamp_key.flags = TS_ANYUID;
    if (def_timestampdir) {
	struct stat sb;
	if (user_ttypath != NULL && stat(user_ttypath, &sb) == 0) {
	    /* tty-based time stamp */
	    timestamp_key.type = TS_TTY;
	    timestamp_key.u.ttydev = sb.st_rdev;
	} else {
	    /* ppid-based time stamp */
	    timestamp_key.type = TS_PPID;
	    timestamp_key.u.ppid = getppid();
	}
    }

    /* Open time stamp file and lock it for exclusive access. */
    fd = open(timestamp_file, O_RDWR);
    if (fd == -1)
	goto done;
    lock_file(fd, SUDO_LOCK);

    while (ts_find_record(fd, &timestamp_key, &entry)) {
	/* Set record position hint for use by update_timestamp() */
	timestamp_hint = lseek(fd, (off_t)0, SEEK_CUR);
	if (timestamp_hint != (off_t)-1)
	    timestamp_hint -= (off_t)entry.size;
	/* Disable the entry. */
	SET(entry.flags, TS_DISABLED);
	ts_update_record(fd, &entry, timestamp_hint);
    }
    close(fd);

done:
    if (timestamp_uid != 0)
	restore_perms();

    debug_return;
}

/*
 * Returns true if the user has already been lectured.
 */
bool
already_lectured(int unused)
{
    char lecture_status[PATH_MAX];
    struct stat sb;
    int len;
    debug_decl(already_lectured, SUDO_DEBUG_AUTH)

    len = snprintf(lecture_status, sizeof(lecture_status), "%s/%s",
	def_lecture_status_dir, user_name);
    if (len <= 0 || (size_t)len >= sizeof(lecture_status)) {
	log_fatal(0, N_("lecture status path too long: %s/%s"),
	    def_lecture_status_dir, user_name);
    }

    debug_return_bool(ts_secure_dir(def_lecture_status_dir, false) &&
	stat(lecture_status, &sb) == 0);
}

/*
 * Create the lecture status file.
 */
bool
set_lectured(void)
{
    char lecture_status[PATH_MAX];
    int len, fd = -1;
    debug_decl(set_lectured, SUDO_DEBUG_AUTH)

    len = snprintf(lecture_status, sizeof(lecture_status), "%s/%s",
	def_lecture_status_dir, user_name);
    if (len <= 0 || (size_t)len >= sizeof(lecture_status)) {
	log_fatal(0, N_("lecture status path too long: %s/%s"),
	    def_lecture_status_dir, user_name);
    }

    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);

    /* Sanity check lecture dir and create if missing. */
    if (!ts_secure_dir(def_lecture_status_dir, true))
	goto done;

    /* Create lecture file. */
    fd = open(lecture_status, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd != -1)
	close(fd);

done:
    if (timestamp_uid != 0)
	restore_perms();

    debug_return_bool(fd != -1 ? true : false);
}
