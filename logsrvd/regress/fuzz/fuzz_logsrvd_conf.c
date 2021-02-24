/*
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

#include "log_server.pb-c.h"
#include "logsrvd.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char tempfile[] = "/tmp/logsrvd_conf.XXXXXX";
    size_t nwritten;
    int fd;

    /* logsrvd_conf_read() uses a conf file path, not an open file. */
    fd = mkstemp(tempfile);
    if (fd == -1)
	return 0;
    nwritten = write(fd, data, size);
    if (nwritten != size) {
	close(fd);
	return 0;
    }
    close(fd);

    logsrvd_conf_read(tempfile);

    unlink(tempfile);

    return 0;
}

void
eventlog_set_type(int type)
{
    return;
}

void
eventlog_set_format(enum eventlog_format format)
{
    return;
}

void
eventlog_set_syslog_acceptpri(int pri)
{
    return;
}

void
eventlog_set_syslog_rejectpri(int pri)
{
    return;
}

void
eventlog_set_syslog_alertpri(int pri)
{
    return;
}

void
eventlog_set_syslog_maxlen(int len)
{
    return;
}

void
eventlog_set_file_maxlen(int len)
{
    return;
}

void
eventlog_set_mailuid(uid_t uid)
{
    return;
}

void
eventlog_set_omit_hostname(bool omit_hostname)
{
    return;
}

void
eventlog_set_logpath(const char *path)
{
    return;
}

void
eventlog_set_time_fmt(const char *fmt)
{
    return;
}

void
eventlog_set_mailerpath(const char *path)
{
    return;
}

void
eventlog_set_mailerflags(const char *mflags)
{
    return;
}

void
eventlog_set_mailfrom(const char *from_addr)
{
    return;
}

void
eventlog_set_mailto(const char *to_addr)
{
    return;
}

void
eventlog_set_mailsub(const char *subject)
{
    return;
}

void
eventlog_set_open_log(FILE *(*fn)(int type, const char *))
{
    return;
}

void
eventlog_set_close_log(void (*fn)(int type, FILE *))
{
    return;
}

void
iolog_set_defaults(void)
{
    return;
}

void
iolog_set_maxseq(unsigned int newval)
{
    return;
}

void
iolog_set_owner(uid_t uid, gid_t gid)
{
    return;
}

void
iolog_set_gid(gid_t gid)
{
    return;
}

void
iolog_set_mode(mode_t mode)
{
    return;
}

void
iolog_set_compress(bool newval)
{
    return;
}

void
iolog_set_flush(bool newval)
{
    return;
}
