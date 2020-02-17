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
#include "sudo_python_module.h"

#include "sudo_queue.h"
#include "sudo_conf.h"

#include <limits.h>
#include <string.h>


const char *
_lookup_value(char * const keyvalues[], const char *key)
{
    debug_decl(_lookup_value, PYTHON_DEBUG_INTERNAL);
    if (keyvalues == NULL)
        debug_return_const_str(NULL);

    size_t keylen = strlen(key);
    for (; *keyvalues != NULL; ++keyvalues) {
        const char *keyvalue = *keyvalues;
        if (strncmp(keyvalue, key, keylen) == 0 && keyvalue[keylen] == '=')
            debug_return_const_str(keyvalue + keylen + 1);
    }
    debug_return_const_str(NULL);
}

CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION
int
_append_python_path(const char *module_dir)
{
    debug_decl(_py_debug_python_function, PYTHON_DEBUG_PLUGIN_LOAD);
    int rc = -1;
    PyObject *py_sys_path = PySys_GetObject("path");
    if (py_sys_path == NULL) {
        PyErr_Format(sudo_exc_SudoException, "Failed to get python 'path'");
        debug_return_int(rc);
    }

    sudo_debug_printf(SUDO_DEBUG_DIAG, "Extending python 'path' with '%s'\n", module_dir);

    PyObject *py_module_dir = PyUnicode_FromString(module_dir);
    if (py_module_dir == NULL || PyList_Append(py_sys_path, py_module_dir) != 0) {
        Py_XDECREF(py_module_dir);
        debug_return_int(rc);
    }
    Py_XDECREF(py_module_dir);

    if (sudo_debug_needed(SUDO_DEBUG_INFO)) {
        char *path = py_join_str_list(py_sys_path, ":");
        sudo_debug_printf(SUDO_DEBUG_INFO, "Python path became: %s\n", path);
        free(path);
    }

    rc = 0;
    debug_return_int(rc);
}

static PyObject *
_import_module(const char *path)
{
    debug_decl(_import_module, PYTHON_DEBUG_PLUGIN_LOAD);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "importing module: %s\n", path);

    char path_copy[PATH_MAX];
    if (strlcpy(path_copy, path, sizeof(path_copy)) >= sizeof(path_copy))
        debug_return_ptr(NULL);

    char *module_dir = path_copy;
    char *module_name = strrchr(path_copy, '/');
    if (module_name == NULL) {
        module_name = path_copy;
        module_dir = "";
    } else {
        *module_name++ = '\0';
    }

    size_t len = strlen(module_name);
    if (len >= 3 && strcmp(".py", module_name + len - 3) == 0)
        module_name[len - 3] = '\0';

    sudo_debug_printf(SUDO_DEBUG_INFO, "module_name: '%s', module_dir: '%s'\n", module_name, module_dir);

    if (_append_python_path(module_dir) < 0)
        debug_return_ptr(NULL);

    debug_return_ptr(PyImport_ImportModule(module_name));
}

void
python_plugin_handle_plugin_error_exception(PyObject **py_result, struct PluginContext *plugin_ctx)
{
    debug_decl(python_plugin_handle_plugin_error_exception, PYTHON_DEBUG_INTERNAL);

    free(plugin_ctx->callback_error);
    plugin_ctx->callback_error = NULL;

    if (PyErr_Occurred()) {
        int rc = SUDO_RC_ERROR;
        if (PyErr_ExceptionMatches(sudo_exc_PluginReject)) {
            rc = SUDO_RC_REJECT;
        } else if (!PyErr_ExceptionMatches(sudo_exc_PluginError)) {
            debug_return;
        }

        if (py_result != NULL) {
            Py_CLEAR(*py_result);
            *py_result = PyLong_FromLong(rc);
        }

        PyObject *py_type = NULL, *py_message = NULL, *py_traceback = NULL;
        PyErr_Fetch(&py_type, &py_message, &py_traceback);

        char *message = py_message ? py_create_string_rep(py_message) : NULL;
        sudo_debug_printf(SUDO_DEBUG_INFO, "received sudo.PluginError exception with message '%s'",
                          message == NULL ? "(null)" : message);

        plugin_ctx->callback_error = message;

        Py_CLEAR(py_type);
        Py_CLEAR(py_message);
        Py_CLEAR(py_traceback);
    }

    debug_return;
}

int
python_plugin_construct_custom(struct PluginContext *plugin_ctx, PyObject *py_kwargs)
{
    debug_decl(python_plugin_construct_custom, PYTHON_DEBUG_PLUGIN_LOAD);
    int rc = SUDO_RC_ERROR;
    PyObject *py_args = PyTuple_New(0);

    if (py_args == NULL)
        goto cleanup;

    py_debug_python_call(python_plugin_name(plugin_ctx), "__init__",
                         py_args, py_kwargs, PYTHON_DEBUG_PY_CALLS);

    plugin_ctx->py_instance = PyObject_Call(plugin_ctx->py_class, py_args, py_kwargs);
    python_plugin_handle_plugin_error_exception(NULL, plugin_ctx);

    py_debug_python_result(python_plugin_name(plugin_ctx), "__init__",
                           plugin_ctx->py_instance, PYTHON_DEBUG_PY_CALLS);

    if (plugin_ctx->py_instance)
        rc = SUDO_RC_OK;

cleanup:
    if (PyErr_Occurred()) {
        py_log_last_error("Failed to construct plugin instance");
        Py_CLEAR(plugin_ctx->py_instance);
        rc = SUDO_RC_ERROR;
    }

    Py_XDECREF(py_args);
    debug_return_int(rc);
}

PyObject *
python_plugin_construct_args(unsigned int version,
                        char *const settings[], char *const user_info[],
                        char *const user_env[], char *const plugin_options[])
{
    PyObject *py_settings = NULL;
    PyObject *py_user_info = NULL;
    PyObject *py_user_env = NULL;
    PyObject *py_plugin_options = NULL;
    PyObject *py_version = NULL;
    PyObject *py_kwargs = NULL;

    if ((py_settings = py_str_array_to_tuple(settings)) == NULL ||
        (py_user_info = py_str_array_to_tuple(user_info)) == NULL ||
        (py_user_env = py_str_array_to_tuple(user_env)) == NULL ||
        (py_plugin_options = py_str_array_to_tuple(plugin_options)) == NULL ||
        (py_version = py_create_version(version)) == NULL ||
        (py_kwargs = PyDict_New()) == NULL ||
        PyDict_SetItemString(py_kwargs, "version", py_version) != 0 ||
        PyDict_SetItemString(py_kwargs, "settings", py_settings) != 0 ||
        PyDict_SetItemString(py_kwargs, "user_env", py_user_env) != 0 ||
        PyDict_SetItemString(py_kwargs, "user_info", py_user_info) != 0 ||
        PyDict_SetItemString(py_kwargs, "plugin_options", py_plugin_options) != 0)
    {
        Py_CLEAR(py_kwargs);
    }

    Py_CLEAR(py_settings);
    Py_CLEAR(py_user_info);
    Py_CLEAR(py_user_env);
    Py_CLEAR(py_plugin_options);
    Py_CLEAR(py_version);
    return py_kwargs;
}

int
python_plugin_construct(struct PluginContext *plugin_ctx, unsigned int version,
                        char *const settings[], char *const user_info[],
                        char *const user_env[], char *const plugin_options[])
{
    debug_decl(python_plugin_construct, PYTHON_DEBUG_PLUGIN_LOAD);

    int rc = SUDO_RC_ERROR;
    PyObject *py_kwargs = python_plugin_construct_args(
        version, settings, user_info, user_env, plugin_options);

    if (py_kwargs == NULL) {
        py_log_last_error("Failed to construct plugin instance");
        rc = SUDO_RC_ERROR;
    } else {
        rc = python_plugin_construct_custom(plugin_ctx, py_kwargs);
    }

    Py_CLEAR(py_kwargs);

    debug_return_int(rc);
}

int
python_plugin_register_logging(sudo_conv_t conversation,
                               sudo_printf_t sudo_printf,
                               char * const settings[])
{
    debug_decl(python_plugin_register_logging, PYTHON_DEBUG_INTERNAL);

    int rc = SUDO_RC_ERROR;
    if (py_ctx.sudo_conv == NULL)
        py_ctx.sudo_conv = conversation;

    if (sudo_printf)
        py_ctx.sudo_log = sudo_printf;

    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudo_conf_debug_file_list *debug_files_ptr = &debug_files;

    const char *plugin_path = _lookup_value(settings, "plugin_path");
    if (plugin_path == NULL)
        plugin_path = "python_plugin.so";

    const char *debug_flags = _lookup_value(settings, "debug_flags");

    if (debug_flags == NULL) {  // the group plugin does not have this information, so try to look it up
        debug_files_ptr = sudo_conf_debug_files(plugin_path);
    } else {
        if (!python_debug_parse_flags(&debug_files, debug_flags))
            goto cleanup;
    }

    if (debug_files_ptr != NULL) {
        if (!python_debug_register(plugin_path, debug_files_ptr))
            goto cleanup;
    }

    rc = SUDO_RC_OK;

cleanup:
    debug_return_int(rc);
}

CPYCHECKER_NEGATIVE_RESULT_SETS_EXCEPTION
static int
_python_plugin_register_plugin_in_py_ctx(void)
{
    debug_decl(_python_plugin_register_plugin_in_py_ctx, PYTHON_DEBUG_PLUGIN_LOAD);

    if (!Py_IsInitialized()) {
        py_ctx.open_plugin_count = 0;

        // Disable environment variables effecting the python interpreter
        // This is important since we are running code here as root, the
        // user should not be able to alter what is running any how.
        Py_IgnoreEnvironmentFlag = 1;
        Py_IsolatedFlag = 1;
        Py_NoUserSiteDirectory = 1;

        PyImport_AppendInittab("sudo", sudo_module_init);
        Py_InitializeEx(0);
        py_ctx.py_main_interpreter = PyThreadState_Get();

        // This ensures we import "sudo" module in the main interpreter,
        // each subinterpreter will have a shallow copy.
        // (This makes the C sudo module able to eg. import other modules.)
        PyObject *py_sudo = NULL;
        if ((py_sudo = PyImport_ImportModule("sudo")) == NULL) {
            debug_return_int(SUDO_RC_ERROR);
        }
        Py_CLEAR(py_sudo);
    } else {
        PyThreadState_Swap(py_ctx.py_main_interpreter);
    }

    ++py_ctx.open_plugin_count;
    debug_return_int(SUDO_RC_OK);
}

int
python_plugin_init(struct PluginContext *plugin_ctx, char * const plugin_options[],
                   unsigned int version)
{
    debug_decl(python_plugin_init, PYTHON_DEBUG_PLUGIN_LOAD);

    int rc = SUDO_RC_ERROR;

    if (_python_plugin_register_plugin_in_py_ctx() != SUDO_RC_OK)
        goto cleanup;

    plugin_ctx->sudo_api_version = version;

    plugin_ctx->py_interpreter = Py_NewInterpreter();
    if (plugin_ctx->py_interpreter == NULL) {
        goto cleanup;
    }
    PyThreadState_Swap(plugin_ctx->py_interpreter);

    if (!sudo_conf_developer_mode() && sudo_module_register_importblocker() < 0) {
        py_log_last_error(NULL);
        debug_return_int(SUDO_RC_ERROR);
    }

    const char *module_path = _lookup_value(plugin_options, "ModulePath");
    if (module_path == NULL) {
        py_sudo_log(SUDO_CONV_ERROR_MSG, "No python module path is specified. "
                                         "Use 'ModulePath' plugin config option in 'sudo.conf'\n", module_path);
        goto cleanup;
    }

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "Loading python module from path '%s'", module_path);
    plugin_ctx->py_module = _import_module(module_path);
    if (plugin_ctx->py_module == NULL) {
        goto cleanup;
    }

    const char *plugin_class = _lookup_value(plugin_options, "ClassName");
    if (plugin_class == NULL) {
        py_sudo_log(SUDO_CONV_ERROR_MSG, "No plugin class is specified for python module '%s'. "
                    "Use 'ClassName' configuration option in 'sudo.conf'\n", module_path);
        goto cleanup;
    }

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "Using plugin class '%s'", plugin_class);
    plugin_ctx->py_class = PyObject_GetAttrString(plugin_ctx->py_module, plugin_class);
    if (plugin_ctx->py_class == NULL) {
        py_sudo_log(SUDO_CONV_ERROR_MSG, "Failed to find plugin class '%s'\n", plugin_class);
        goto cleanup;
    }

    if (!PyObject_IsSubclass(plugin_ctx->py_class, (PyObject *)sudo_type_Plugin)) {
        py_sudo_log(SUDO_CONV_ERROR_MSG, "Plugin class '%s' does not inherit from 'sudo.Plugin'\n", plugin_class);
        Py_CLEAR(plugin_ctx->py_class);
        goto cleanup;
    }

    rc = SUDO_RC_OK;

cleanup:
    if (plugin_ctx->py_class == NULL) {
        py_log_last_error("Failed during loading plugin class");
        rc = SUDO_RC_ERROR;
    }

    debug_return_int(rc);
}

void
python_plugin_deinit(struct PluginContext *plugin_ctx)
{
    debug_decl(python_plugin_deinit, PYTHON_DEBUG_PLUGIN_LOAD);
    --py_ctx.open_plugin_count;
    sudo_debug_printf(SUDO_DEBUG_DIAG, "Closing: %d python plugins left open\n", py_ctx.open_plugin_count);

    Py_CLEAR(plugin_ctx->py_instance);
    Py_CLEAR(plugin_ctx->py_class);
    Py_CLEAR(plugin_ctx->py_module);

    if (plugin_ctx->py_interpreter != NULL) {
        sudo_debug_printf(SUDO_DEBUG_TRACE, "deinit python interpreter for plugin\n");
        Py_EndInterpreter(plugin_ctx->py_interpreter);
    }

    free(plugin_ctx->callback_error);
    memset(plugin_ctx, 0, sizeof(*plugin_ctx));

    if (py_ctx.open_plugin_count <= 0) {
        if (Py_IsInitialized()) {
            sudo_debug_printf(SUDO_DEBUG_NOTICE, "Closing: deinit python interpreter\n");

            // we need to call finalize from the main interpreter
            PyThreadState_Swap(py_ctx.py_main_interpreter);

            Py_Finalize();
        }

        py_ctx_reset();
    }

    python_debug_deregister();

    debug_return;
}

PyObject *
python_plugin_api_call(struct PluginContext *plugin_ctx, const char *func_name, PyObject *py_args)
{
    debug_decl(python_plugin_api_call, PYTHON_DEBUG_PY_CALLS);

    // Note: call fails if py_args is an empty tuple. Passing no arguments works passing NULL
    // instead. So having such must be handled as valid. (See policy_plugin.validate())
    if (py_args == NULL && PyErr_Occurred()) {
        py_sudo_log(SUDO_CONV_ERROR_MSG, "Failed to build arguments for python plugin API call '%s'\n", func_name);
        py_log_last_error(NULL);
        debug_return_ptr(NULL);
    }

    PyObject *py_callable = NULL;
    py_callable = PyObject_GetAttrString(plugin_ctx->py_instance, func_name);

    if (py_callable == NULL) {
        Py_CLEAR(py_args);
        debug_return_ptr(NULL);
    }

    py_debug_python_call(python_plugin_name(plugin_ctx), func_name,
                         py_args, NULL, PYTHON_DEBUG_PY_CALLS);

    PyObject *py_result = PyObject_CallObject(py_callable, py_args);
    Py_CLEAR(py_args);
    Py_CLEAR(py_callable);

    py_debug_python_result(python_plugin_name(plugin_ctx), func_name,
                           py_result, PYTHON_DEBUG_PY_CALLS);

    python_plugin_handle_plugin_error_exception(&py_result, plugin_ctx);

    if (PyErr_Occurred()) {
        py_log_last_error(NULL);
    }

    debug_return_ptr(py_result);
}

int
python_plugin_rc_to_int(PyObject *py_result)
{
    debug_decl(python_plugin_rc_to_int, PYTHON_DEBUG_PY_CALLS);
    if (py_result == NULL)
        debug_return_int(SUDO_RC_ERROR);

    if (py_result == Py_None)
        debug_return_int(SUDO_RC_OK);

    debug_return_int((int)PyLong_AsLong(py_result));
}

int
python_plugin_api_rc_call(struct PluginContext *plugin_ctx, const char *func_name, PyObject *py_args)
{
    debug_decl(python_plugin_api_rc_call, PYTHON_DEBUG_PY_CALLS);

    PyObject *py_result = python_plugin_api_call(plugin_ctx, func_name, py_args);
    int rc = python_plugin_rc_to_int(py_result);
    Py_XDECREF(py_result);
    debug_return_int(rc);
}

int
python_plugin_show_version(struct PluginContext *plugin_ctx, const char *python_callback_name, int is_verbose)
{
    debug_decl(python_plugin_show_version, PYTHON_DEBUG_CALLBACKS);

    debug_return_int(python_plugin_api_rc_call(plugin_ctx, python_callback_name,
                                               Py_BuildValue("(i)", is_verbose)));
}

void
python_plugin_close(struct PluginContext *plugin_ctx, const char *callback_name,
                    PyObject *py_args)
{
    debug_decl(python_plugin_close, PYTHON_DEBUG_CALLBACKS);

    PyThreadState_Swap(plugin_ctx->py_interpreter);

    // Note, this should handle the case when init has failed
    if (plugin_ctx->py_instance != NULL) {
        if (!plugin_ctx->call_close) {
            sudo_debug_printf(SUDO_DEBUG_INFO, "Skipping close call, because there was no command run\n");

        } else if (!PyObject_HasAttrString(plugin_ctx->py_instance, callback_name)) {
            sudo_debug_printf(SUDO_DEBUG_INFO, "Python plugin function 'close' is skipped (not present)\n");
        } else {
            PyObject *py_result = python_plugin_api_call(plugin_ctx, callback_name, py_args);
            py_args = NULL;  // api call already freed it
            Py_XDECREF(py_result);
        }
    }

    Py_CLEAR(py_args);

    if (PyErr_Occurred()) {
        py_log_last_error(NULL);
    }

    python_plugin_deinit(plugin_ctx);

    debug_return;
}

void
python_plugin_mark_callback_optional(struct PluginContext *plugin_ctx,
                                     const char *function_name, void **function)
{
    if (!PyObject_HasAttrString(plugin_ctx->py_instance, function_name)) {
        debug_decl_vars(python_plugin_mark_callback_optional, PYTHON_DEBUG_PY_CALLS);
        sudo_debug_printf(SUDO_DEBUG_INFO, "%s function '%s' is not implemented\n",
                          Py_TYPENAME(plugin_ctx->py_instance), function_name);
        *function = NULL;
    }
}

const char *
python_plugin_name(struct PluginContext *plugin_ctx)
{
    debug_decl(python_plugin_name, PYTHON_DEBUG_INTERNAL);

    const char *name = "(NULL)";

    if (plugin_ctx == NULL || !PyType_Check(plugin_ctx->py_class))
        debug_return_const_str(name);

    debug_return_const_str(((PyTypeObject *)(plugin_ctx->py_class))->tp_name);
}
