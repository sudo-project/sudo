/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDOERS_IOLOG_READER_H
#define SUDOERS_IOLOG_READER_H

#include "iolog.h"

/*
 * Info present in the I/O log file
 */
struct iolog_info {
    char *cwd;
    char *user;
    char *runas_user;
    char *runas_group;
    char *tty;
    char *cmd;
    time_t tstamp;
    int lines;
    int cols;
};

struct timing_closure {
    struct timespec delay;
    const char *decimal;
    union io_fd fd;
    int event;
    union {
	struct {
	    int lines;
	    int cols;
	} winsize;
	size_t nbytes; // XXX
	int signo;
    } u;
};

/* iolog_reader.c */
bool parse_timing(const char *line, struct timing_closure *timing);
char *parse_delay(const char *cp, struct timespec *delay, const char *decimal_point);
struct iolog_info *parse_logfile(const char *logfile);
void free_iolog_info(struct iolog_info *li);
void adjust_delay(struct timespec *delay, struct timespec *max_delay, double scale_factor);

#endif /* SUDOERS_IOLOG_READER_H */
