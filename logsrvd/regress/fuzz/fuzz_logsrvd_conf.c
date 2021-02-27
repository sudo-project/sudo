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

    if (logsrvd_conf_read(tempfile)) {
	/* public config getters */
	logsrvd_conf_iolog_mode();
	logsrvd_conf_iolog_dir();
	logsrvd_conf_iolog_file();
	logsrvd_conf_listen_address();
	logsrvd_conf_tcp_keepalive();
	logsrvd_conf_pid_file();
	logsrvd_conf_get_sock_timeout();
    }

    unlink(tempfile);

    return 0;
}
