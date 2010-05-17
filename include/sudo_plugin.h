/*
 * Copyright (c) 2009-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_PLUGIN_H
#define _SUDO_PLUGIN_H

/* API version major/minor */
#define SUDO_API_VERSION_MAJOR 1
#define SUDO_API_VERSION_MINOR 0
#define SUDO_API_VERSION ((SUDO_API_VERSION_MAJOR << 16) | SUDO_API_VERSION_MINOR)

/* Getters and setters for API version */
#define SUDO_API_VERSION_GET_MAJOR(v) ((v) >> 16)
#define SUDO_API_VERSION_GET_MINOR(v) ((v) & 0xffff)
#define SUDO_API_VERSION_SET_MAJOR(vp, n) do { \
    *(vp) = (*(vp) & 0x0000ffff) | ((n) << 16); \
} while(0)
#define SUDO_VERSION_SET_MINOR(vp, n) do { \
    *(vp) = (*(vp) & 0xffff0000) | (n); \
} while(0)

/* Conversation function types and defines */
struct sudo_conv_message {
#define SUDO_CONV_PROMPT_ECHO_OFF	1
#define SUDO_CONV_PROMPT_ECHO_ON	2
#define SUDO_CONV_ERROR_MSG		3
#define SUDO_CONV_INFO_MSG		4
    int msg_type;
    int timeout;
    const char *msg;
};

struct sudo_conv_reply {
    char *reply;
};

typedef int (*sudo_conv_t)(int num_msgs, const struct sudo_conv_message msgs[],
	struct sudo_conv_reply replies[]);
typedef int (*sudo_printf_t)(int msg_type, const char *fmt, ...);

/* Policy plugin type and defines */
struct policy_plugin {
#define SUDO_POLICY_PLUGIN     1
    unsigned int type; /* always SUDO_POLICY_PLUGIN */
    unsigned int version; /* always SUDO_API_VERSION */
    int (*open)(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char * const settings[],
	char * const user_info[], char * const user_env[]);
    void (*close)(int exit_status, int error); /* wait status or error */
    int (*show_version)(int verbose);
    int (*check_policy)(int argc, char * const argv[],
	char *env_add[], char **command_info[],
	char **argv_out[], char **user_env_out[]);
    int (*list)(int argc, char * const argv[], int verbose,
	const char *list_user);
    int (*validate)(void);
    void (*invalidate)(int remove);
};

/* I/O plugin type and defines */
struct io_plugin {
#define SUDO_IO_PLUGIN	    2
    unsigned int type; /* always SUDO_IO_PLUGIN */
    unsigned int version; /* always SUDO_API_VERSION */
    int (*open)(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char * const settings[],
	char * const user_info[], int argc, char * const argv[],
	char * const user_env[]);
    void (*close)(int exit_status, int error); /* wait status or error */
    int (*show_version)(int verbose);
    int (*log_ttyin)(const char *buf, unsigned int len);
    int (*log_ttyout)(const char *buf, unsigned int len);
    int (*log_stdin)(const char *buf, unsigned int len);
    int (*log_stdout)(const char *buf, unsigned int len);
    int (*log_stderr)(const char *buf, unsigned int len);
};

/* Internal use only */
struct generic_plugin {
    unsigned int type;
    unsigned int version;
    int (*open)(unsigned int version, sudo_conv_t conversation,
	char * const settings[], char * const user_info[],
	char * const user_env[]);
    void (*close)(int exit_status, int error); /* wait status or error */
    int (*show_version)(int verbose);
    /* the rest depends on the type... */
};

#endif /* _SUDO_PLUGIN_H */
