/*
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef LOGSRVD_IOLOG_H
#define LOGSRVD_IOLOG_H

#include <zlib.h>

/*
 * I/O log event types as stored as the first field in the timing file.
 * Changing existing values will result in incompatible I/O log files.
 */
#define IO_EVENT_STDIN		0
#define IO_EVENT_STDOUT		1
#define IO_EVENT_STDERR		2
#define IO_EVENT_TTYIN		3
#define IO_EVENT_TTYOUT		4
#define IO_EVENT_WINSIZE	5
#define IO_EVENT_TTYOUT_1_8_7	6
#define IO_EVENT_SUSPEND	7
#define IO_EVENT_COUNT		8

/*
 * Contents of the sudo I/O info log
 */
struct log_info {
    char *command;
    char *cwd;
    char *iolog_dir;
    char *rungroup;
    char *runuser;
    char *submithost;
    char *submituser;
    char *ttyname;
    char **argv;
    time_t start_time;
    int argc;
    int lines;
    int columns;
};

#endif /* LOGSRVD_IOLOG_H */
