/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2020 Robert Manner <robert.manner@oneidentity.com>
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

#include "sudo_python_module.h"

#include "sudo_util.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


static int
_verify_import(const char *file_path)
{
    debug_decl(_verify_import, PYTHON_DEBUG_INTERNAL);

    // Check mode and owner similar to what we do in open_sudoers().
    // This is to help avoid loading a potentially insecure module.
    struct stat sb;
    if (stat(file_path, &sb) != 0) {
        PyErr_Format(PyExc_ImportError, "Failed to stat file '%s'", file_path);
        debug_return_int(SUDO_RC_ERROR);
    }

    if (sb.st_uid != ROOT_UID) {
        PyErr_Format(PyExc_ImportError, "File '%s' must be owned by uid %d", file_path, ROOT_UID);
        debug_return_int(SUDO_RC_ERROR);
    }

    if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
        PyErr_Format(PyExc_ImportError, "File '%s' must be only be writable by owner", file_path);
        debug_return_int(SUDO_RC_ERROR);
    }

    debug_return_int(SUDO_RC_OK);
}

static PyObject *
_sudo_ImportBlocker__Init(PyObject *py_self, PyObject *py_args)
{
    debug_decl(_sudo_ImportBlocker__Init, PYTHON_DEBUG_C_CALLS);

    py_debug_python_call("ImportBlocker", "__init__", py_args, NULL, PYTHON_DEBUG_C_CALLS);

    PyObject *py_meta_path = NULL;
    if (!PyArg_UnpackTuple(py_args, "sudo.ImportBlocker.__init__", 2, 2, &py_self, &py_meta_path))
        goto cleanup;

    if (PyObject_SetAttrString(py_self, "meta_path", py_meta_path) != 0)
        goto cleanup;

cleanup:
    if (PyErr_Occurred())
        debug_return_ptr(NULL);

    debug_return_ptr_pynone;
}

static PyObject *
_sudo_ImportBlocker__find_module(PyObject *py_self, PyObject *py_args)
{
    debug_decl(_sudo_ImportBlocker__find_module, PYTHON_DEBUG_C_CALLS);

    PyObject *py_fullname = NULL, *py_path = NULL, *py_meta_path = NULL,
             *py_meta_path_iterator = NULL, *py_finder = NULL,
             *py_importer = NULL, *py_import_path = NULL;

    py_debug_python_call("ImportBlocker", "find_module", py_args, NULL, PYTHON_DEBUG_C_CALLS);

    if (!PyArg_UnpackTuple(py_args, "sudo.ImportBlocker.find_module", 2, 3, &py_self, &py_fullname, &py_path))
        goto cleanup;

    py_meta_path = PyObject_GetAttrString(py_self, "meta_path");
    if (py_meta_path == NULL)
        goto cleanup;

    py_meta_path_iterator = PyObject_GetIter(py_meta_path);
    if (py_meta_path_iterator == NULL)
        goto cleanup;

    while ((py_finder = PyIter_Next(py_meta_path_iterator)) != NULL) {
        py_importer = PyObject_CallMethod(py_finder, "find_module", "(OO)",
                                          py_fullname, py_path);
        if (py_importer == NULL) {
            goto cleanup;
        }

        if (py_importer != Py_None) { // the import could be resolved
            if (PyObject_HasAttrString(py_importer, "get_filename")) {
                // there is a file associated with the import (.py, .so, etc)
                py_import_path = PyObject_CallMethod(py_importer, "get_filename", "");
                const char *import_path = PyUnicode_AsUTF8(py_import_path);

                sudo_debug_printf(SUDO_DEBUG_DIAG, "ImportBlocker: verifying permissions "
                                                   "on file '%s'\n", import_path);
                if (_verify_import(import_path) != SUDO_RC_OK)
                    goto cleanup;

                Py_CLEAR(py_import_path);

            } else {
                sudo_debug_printf(SUDO_DEBUG_DIAG, "ImportBlocker: internal module import '%s'\n",
                                  PyUnicode_AsUTF8(py_fullname));
            }

            goto cleanup;
        }

        Py_CLEAR(py_importer);
        Py_CLEAR(py_finder);
    }

    Py_CLEAR(py_importer);
    py_importer = Py_None;
    Py_INCREF(py_importer);

cleanup:
    Py_CLEAR(py_meta_path_iterator);
    Py_CLEAR(py_meta_path);
    Py_CLEAR(py_finder);
    Py_CLEAR(py_import_path);

    if (PyErr_Occurred()) {
        Py_CLEAR(py_importer);
        debug_return_ptr(NULL);
    }

    debug_return_ptr(py_importer);
}

static PyMethodDef _sudo_ImportBlocker_class_methods[] =
{
    {"__init__", _sudo_ImportBlocker__Init, METH_VARARGS, ""},
    {"find_module", _sudo_ImportBlocker__find_module, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}
};

// This possibly can be replaced with PySys_AddAuditHook for python >= 3.8
//
// This function is equivalent of the python call:
// sys.meta_path = [sudo.ImportBlocker(sys.meta_path)]
int
sudo_module_register_importblocker(void)
{
    debug_decl(sudo_module_register_importblocker, PYTHON_DEBUG_C_CALLS);

    int rc = SUDO_RC_ERROR;

    PyObject *py_meta_path = NULL, *py_import_blocker_cls = NULL,
             *py_import_blocker = NULL;

    py_meta_path = PySys_GetObject("meta_path"); // note: borrowed reference
    if (py_meta_path == NULL) {
        PyErr_Format(sudo_exc_SudoException, "'sys.meta_path' is not available. "
                     "Unable to register import blocker hook which is meant to "
                     "verify that no such module get loaded by the sudo python plugins"
                     "which are writable by others than root.");
        goto cleanup;
    }
    Py_INCREF(py_meta_path);

    py_import_blocker_cls = sudo_module_create_class("sudo.ImportBlocker", _sudo_ImportBlocker_class_methods, NULL);
    if (py_import_blocker_cls == NULL)
        goto cleanup;

    // call the constructor
    py_import_blocker = PyObject_CallFunctionObjArgs(py_import_blocker_cls, py_meta_path, NULL);
    if (py_import_blocker == NULL)
        goto cleanup;

    Py_DECREF(py_meta_path);
    py_meta_path = PyList_New(1);
    if (py_meta_path == NULL)
        goto cleanup;

    if (PyList_SetItem(py_meta_path, 0, py_import_blocker) != 0)
        goto cleanup;
    py_import_blocker = NULL; // list has stolen it

    if (PySys_SetObject("meta_path", py_meta_path) != 0) {
        goto cleanup;
    }

    rc = SUDO_RC_OK;

cleanup:
    Py_CLEAR(py_meta_path);
    Py_CLEAR(py_import_blocker);
    Py_CLEAR(py_import_blocker_cls);

    debug_return_int(rc);
}
