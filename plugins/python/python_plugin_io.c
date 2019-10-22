/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019 Robert Manner <robert.manner@oneidentity.com>
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

#include "python_plugin_common.h"


static struct PluginContext plugin_ctx;

extern struct io_plugin python_io;

#define PY_IO_PLUGIN_VERSION SUDO_API_MKVERSION(1, 0)

#define CALLBACK_PLUGINFUNC(func_name) python_io.func_name
#define CALLBACK_CFUNC(func_name) python_plugin_io_ ## func_name

// This also verifies compile time that the name matches the sudo plugin API.
#define CALLBACK_PYNAME(func_name) ((void)CALLBACK_PLUGINFUNC(func_name), #func_name)

#define MARK_CALLBACK_OPTIONAL(function_name) \
    do { \
        python_plugin_mark_callback_optional(&plugin_ctx, CALLBACK_PYNAME(function_name), \
            (void **)&CALLBACK_PLUGINFUNC(function_name)); \
    } while(0)


static int
_call_plugin_open(int argc, char * const argv[], char * const command_info[])
{
    debug_decl(_call_plugin_open, PYTHON_DEBUG_CALLBACKS);
    plugin_ctx.call_close = 1;

    if (!PyObject_HasAttrString(plugin_ctx.py_instance, CALLBACK_PYNAME(open))) {
        debug_return_int(SUDO_RC_OK);
    }

    int rc = SUDO_RC_ERROR;
    PyObject *py_argv = py_str_array_to_tuple_with_count(argc, argv);
    PyObject *py_command_info = py_str_array_to_tuple(command_info);

    if (py_argv != NULL && py_command_info != NULL) {
        rc = python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(open),
                                       Py_BuildValue("(OO)", py_argv, py_command_info));
    } else {
        rc = SUDO_RC_ERROR;
    }

    if (rc != SUDO_RC_OK)
        plugin_ctx.call_close = 0;

    Py_XDECREF(py_argv);
    Py_XDECREF(py_command_info);
    debug_return_int(rc);
}

int
python_plugin_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t sudo_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[],
    char * const plugin_options[])
{
    debug_decl(python_plugin_io_open, PYTHON_DEBUG_CALLBACKS);

    if (version < SUDO_API_MKVERSION(1, 2)) {
        sudo_printf(SUDO_CONV_ERROR_MSG,
                    "Error: Python IO plugin requires at least plugin API version 1.2\n");
        debug_return_int(SUDO_RC_ERROR);
    }

    int rc = python_plugin_register_logging(conversation, sudo_printf, settings);
    if (rc != SUDO_RC_OK)
        debug_return_int(rc);

    rc = python_plugin_init(&plugin_ctx, plugin_options);
    if (rc != SUDO_RC_OK)
        debug_return_int(rc);

    rc = python_plugin_construct(&plugin_ctx, PY_IO_PLUGIN_VERSION,
                                 settings, user_info, user_env, plugin_options);
    if (rc != SUDO_RC_OK)
        debug_return_int(rc);

    // skip plugin callbacks which are not mandatory
    MARK_CALLBACK_OPTIONAL(show_version);
    MARK_CALLBACK_OPTIONAL(log_ttyin);
    MARK_CALLBACK_OPTIONAL(log_ttyout);
    MARK_CALLBACK_OPTIONAL(log_stdin);
    MARK_CALLBACK_OPTIONAL(log_stdout);
    MARK_CALLBACK_OPTIONAL(log_stderr);
    MARK_CALLBACK_OPTIONAL(change_winsize);
    MARK_CALLBACK_OPTIONAL(log_suspend);
    // open and close are mandatory

    if (argc > 0)  // we only call open if there is request for running sg
        rc = _call_plugin_open(argc, argv, command_info);

    debug_return_int(rc);
}

void
python_plugin_io_close(int exit_status, int error)
{
    debug_decl(python_plugin_io_close, PYTHON_DEBUG_CALLBACKS);
    python_plugin_close(&plugin_ctx, CALLBACK_PYNAME(close), exit_status, error);
    debug_return;
}

int
python_plugin_io_show_version(int verbose)
{
    debug_decl(python_plugin_io_show_version, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_show_version(&plugin_ctx, CALLBACK_PYNAME(show_version), verbose));
}

int
python_plugin_io_log_ttyin(const char *buf, unsigned int len)
{
    debug_decl(python_plugin_io_log_ttyin, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_ttyin),
                                     Py_BuildValue("(s#)", buf, len)));
}

int
python_plugin_io_log_ttyout(const char *buf, unsigned int len)
{
    debug_decl(python_plugin_io_log_ttyout, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_ttyout),
                                     Py_BuildValue("(s#)", buf, len)));
}

int
python_plugin_io_log_stdin(const char *buf, unsigned int len)
{
    debug_decl(python_plugin_io_log_stdin, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_stdin),
                                               Py_BuildValue("(s#)", buf, len)));
}

int
python_plugin_io_log_stdout(const char *buf, unsigned int len)
{
    debug_decl(python_plugin_io_log_stdout, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_stdout),
                                               Py_BuildValue("(s#)", buf, len)));
}

int
python_plugin_io_log_stderr(const char *buf, unsigned int len)
{
    debug_decl(python_plugin_io_log_stderr, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_stderr),
                                               Py_BuildValue("(s#)", buf, len)));
}

int
python_plugin_io_change_winsize(unsigned int line, unsigned int cols)
{
    debug_decl(python_plugin_io_change_winsize, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(change_winsize),
                                               Py_BuildValue("(ii)", line, cols)));
}

int
python_plugin_io_log_suspend(int signo)
{
    debug_decl(python_plugin_io_log_suspend, PYTHON_DEBUG_CALLBACKS);
    debug_return_int(python_plugin_api_rc_call(&plugin_ctx, CALLBACK_PYNAME(log_suspend),
                                     Py_BuildValue("(i)", signo)));
}

__dso_public struct io_plugin python_io = {
    SUDO_IO_PLUGIN,
    SUDO_API_VERSION,
    CALLBACK_CFUNC(open),
    CALLBACK_CFUNC(close),
    CALLBACK_CFUNC(show_version),
    CALLBACK_CFUNC(log_ttyin),
    CALLBACK_CFUNC(log_ttyout),
    CALLBACK_CFUNC(log_stdin),
    CALLBACK_CFUNC(log_stdout),
    CALLBACK_CFUNC(log_stderr),
    NULL, // register_hooks,
    NULL, // deregister_hooks,
    CALLBACK_CFUNC(change_winsize),
    CALLBACK_CFUNC(log_suspend),
    NULL // event_alloc
};
