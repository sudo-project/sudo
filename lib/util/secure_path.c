/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2012, 2014-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_debug.h"

/*
 * Verify that path is the right type and not writable by other users.
 */
static int
sudo_check_secure(struct stat *sb, unsigned int type, uid_t uid, gid_t gid)
{
    int ret = SUDO_PATH_SECURE;
    debug_decl(sudo_check_secure, SUDO_DEBUG_UTIL);

    if ((sb->st_mode & S_IFMT) != type) {
	ret = SUDO_PATH_BAD_TYPE;
    } else if (uid != (uid_t)-1 && sb->st_uid != uid) {
	ret = SUDO_PATH_WRONG_OWNER;
    } else if (sb->st_mode & S_IWOTH) {
	ret = SUDO_PATH_WORLD_WRITABLE;
    } else if (ISSET(sb->st_mode, S_IWGRP) &&
	(gid == (gid_t)-1 || sb->st_gid != gid)) {
	ret = SUDO_PATH_GROUP_WRITABLE;
    }

    debug_return_int(ret);
}

/*
 * Verify that path is the right type and not writable by other users.
 */
static int
sudo_secure_path(const char *path, unsigned int type, uid_t uid, gid_t gid,
     struct stat *sb)
{
    int ret = SUDO_PATH_MISSING;
    struct stat stat_buf;
    debug_decl(sudo_secure_path, SUDO_DEBUG_UTIL);

    if (sb == NULL)
	sb = &stat_buf;

    if (path != NULL && stat(path, sb) == 0)
	ret = sudo_check_secure(sb, type, uid, gid);

    debug_return_int(ret);
}

/*
 * Verify that path is a regular file and not writable by other users.
 * Not currently used.
 */
int
sudo_secure_file_v1(const char *path, uid_t uid, gid_t gid, struct stat *sb)
{
    return sudo_secure_path(path, S_IFREG, uid, gid, sb);
}

/*
 * Verify that path is a directory and not writable by other users.
 */
int
sudo_secure_dir_v1(const char *path, uid_t uid, gid_t gid, struct stat *sb)
{
    return sudo_secure_path(path, S_IFDIR, uid, gid, sb);
}

/*
 * Open path read-only as long as it is not writable by other users.
 * Returns an open file descriptor on success, else -1.
 * Sets error to SUDO_PATH_SECURE on success, and a value < 0 on failure.
 */
static int
sudo_secure_open(const char *path, int type, uid_t uid, gid_t gid,
    struct stat *sb, int *error)
{
    struct stat stat_buf;
    int fd;
    debug_decl(sudo_secure_open, SUDO_DEBUG_UTIL);

    if (sb == NULL)
	sb = &stat_buf;

    fd = open(path, O_RDONLY|O_NONBLOCK);
    if (fd == -1 || fstat(fd, sb) != 0) {
	if (fd != -1)
	    close(fd);
	*error = SUDO_PATH_MISSING;
	debug_return_int(-1);
    }

    *error = sudo_check_secure(sb, type, uid, gid);
    if (*error == SUDO_PATH_SECURE) {
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    } else {
	/* Not secure, caller can check error flag. */
	close(fd);
	fd = -1;
    }

    debug_return_int(fd);
}

int
sudo_secure_open_file_v1(const char *path, uid_t uid, gid_t gid,
    struct stat *sb, int *error)
{
    return sudo_secure_open(path, S_IFREG, uid, gid, sb, error);
}

int
sudo_secure_open_dir_v1(const char *path, uid_t uid, gid_t gid,
    struct stat *sb, int *error)
{
    return sudo_secure_open(path, S_IFDIR, uid, gid, sb, error);
}
