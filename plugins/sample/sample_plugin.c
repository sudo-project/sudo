/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <sys/wait.h>

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
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <fcntl.h>
#include <stdarg.h>

#include <sudo_plugin.h>

/*
 * Sample plugin module that allows any user who knows the password
 * ("test") to run any command as root.  Since there is no credential
 * caching the validate and invalidate functions are NULL.
 */

static struct plugin_state {
    char **envp;
    char * const *settings;
    char * const *user_info;
} plugin_state;
static sudo_conv_t sudo_conv;
static FILE *input, *output;

#undef TRUE
#define TRUE 1
#undef FALSE
#define FALSE 0
#undef ERROR
#define ERROR -1

/*
 * Allocate storage for a name=value string and return it.
 */
static char *
fmt_string(const char *var, const char *val)
{
    size_t var_len = strlen(var);
    size_t val_len = strlen(val);
    char *cp, *str;

    cp = str = malloc(var_len + 1 + val_len + 1);
    if (!str)
	return NULL;
    memcpy(cp, var, var_len);
    cp += var_len;
    *cp++ = '=';
    memcpy(cp, val, val_len);
    cp += val_len;
    *cp = '\0';

    return(str);
}

/*
 * Display warning via conversation function.
 */
static void
sudo_log(int type, const char *fmt, ...)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    va_list ap;
    char *str;
    int rc;

    va_start(ap, fmt);
    rc = vasprintf(&str, fmt, ap);
    va_end(ap);
    if (rc == -1)
	return;

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = type;
    msg.msg = str;
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl);
}

/*
 * Plugin policy open function.
 */
static int
policy_open(unsigned int version, sudo_conv_t conversation,
    char * const settings[], char * const user_info[],
    char * const user_env[])
{
    char * const *ui;
    const char *runas_user = NULL;

    sudo_conv = conversation;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
	sudo_log(SUDO_CONV_ERROR_MSG,
	    "the sample plugin requires API version %d.x",
	    SUDO_API_VERSION_MAJOR);
	return ERROR;
    }

    /* Only allow commands to be run as root. */
    for (ui = user_info; *ui != NULL; ui++) {
	if (strncmp(*ui, "runas_user=", sizeof("runas_user=") - 1) == 0) {
	    runas_user = *ui + sizeof("runas_user=") - 1;
	}
    }
    if (runas_user && strcmp(runas_user, "root") != 0) {
	sudo_log(SUDO_CONV_ERROR_MSG, "commands may only be run as root.");
	return 0;
    }

    /* Plugin state. */
    plugin_state.envp = (char **)user_env;
    plugin_state.settings = settings;
    plugin_state.user_info = user_info;

    return 1;
}

/*
 * Plugin policy check function.
 * Simple example that prompts for a password, hard-coded to "test".
 */
static int 
policy_check(int argc, char * const argv[],
    char *env_add[], char **command_info_out[],
    char **argv_out[], char **user_env_out[])
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    char **command_info;
    int i = 0;

    if (!argc || argv[0] == NULL) {
	sudo_log(SUDO_CONV_ERROR_MSG, "no command specified");
	return FALSE;
    }
    /* Only allow fully qualified paths to keep things simple. */
    if (argv[0][0] != '/') {
	sudo_log(SUDO_CONV_ERROR_MSG,
	    "only fully qualified pathnames may be specified");
	return FALSE;
    }

    /* Prompt user for password via conversation function. */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = SUDO_CONV_PROMPT_ECHO_OFF;
    msg.msg = "Password: ";
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl);
    if (strcmp(repl.reply, "test") != 0) {
	sudo_log(SUDO_CONV_ERROR_MSG, "incorrect password");
	return FALSE;
    }

    /* No changes to argv or envp */
    *argv_out = (char **)argv;
    *user_env_out = plugin_state.envp;

    /* Setup command info. */
    command_info = calloc(32, sizeof(char *));
    if (command_info == NULL) {
	sudo_log(SUDO_CONV_ERROR_MSG, "out of memory");
	return ERROR;
    }
    command_info[i++] = fmt_string("command", argv[0]);
    command_info[i++] = "runas_uid=0";
    command_info[i++] = "runas_euid=0";
    *command_info_out = command_info;

    return TRUE;
}

static int
policy_list(int argc, char * const argv[], int verbose, const char *list_user)
{
    /*
     * List user's capabilities.
     */
    sudo_log(SUDO_CONV_INFO_MSG, "Validated users may run any command");
    return TRUE;
}

static int
policy_version(int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "Sample policy plugin version %s", PACKAGE_VERSION);
    return TRUE;
}

static void
policy_close(int exit_status, int error)
{
    /*
     * The policy might log the command exit status here.
     * In this example, we just print a message.
     */
    if (error) {
	sudo_log(SUDO_CONV_ERROR_MSG, "Command error: %s", strerror(error));
    } else {
        if (WIFEXITED(exit_status)) {
	    sudo_log(SUDO_CONV_INFO_MSG, "Command exited with status %d",
		WEXITSTATUS(exit_status));
        } else if (WIFSIGNALED(exit_status)) {
	    sudo_log(SUDO_CONV_INFO_MSG, "Command killed by signal %d",
		WTERMSIG(exit_status));
	}
    }
}

static int
io_open(unsigned int version, sudo_conv_t conversation,
    char * const settings[], char * const user_info[],
    char * const user_env[])
{
    int fd;
    char path[PATH_MAX];

    /* Open input and output files. */
    snprintf(path, sizeof(path), "/var/tmp/sample-%u.output",
	(unsigned int)getpid());
    fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0644);
    if (fd == -1)
	return FALSE;
    output = fdopen(fd, "w");

    snprintf(path, sizeof(path), "/var/tmp/sample-%u.input",
	(unsigned int)getpid());
    fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0644);
    if (fd == -1)
	return FALSE;
    input = fdopen(fd, "w");

    return TRUE;
}

static void
io_close(int exit_status, int error)
{
    fclose(input);
    fclose(output);
}

static int
io_version(int verbose)
{
    sudo_log(SUDO_CONV_INFO_MSG, "Sample I/O plugin version %s", PACKAGE_VERSION);
    return TRUE;
}

static int
io_log_input(const char *buf, unsigned int len)
{
    fwrite(buf, len, 1, input);
    return TRUE;
}

static int
io_log_output(const char *buf, unsigned int len)
{
    fwrite(buf, len, 1, output);
    return TRUE;
}

struct policy_plugin sample_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    policy_open,
    policy_close,
    policy_version,
    policy_check,
    policy_list,
    NULL, /* validate */
    NULL /* invalidate */
};

struct io_plugin sample_io = {
    SUDO_IO_PLUGIN,
    SUDO_API_VERSION,
    io_open,
    io_close,
    io_version,
    io_log_input,
    io_log_output
};
