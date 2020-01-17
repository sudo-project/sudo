/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Robert Manner <robert.manner@oneidentity.com>
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

#include "testhelpers.h"

#include "sudo_dso.h"

static struct io_plugin *python_io = NULL;
static struct policy_plugin *python_policy = NULL;
static struct sudoers_group_plugin *group_plugin = NULL;

static struct passwd example_pwd;

void
create_io_plugin_options(const char *log_path)
{
    static char logpath_keyvalue[PATH_MAX + 16];
    snprintf(logpath_keyvalue, sizeof(logpath_keyvalue), "LogPath=%s", log_path);

    free(data.plugin_options);
    data.plugin_options = create_str_array(
        4,
        "ModulePath=" SRC_DIR "/example_io_plugin.py",
        "ClassName=SudoIOPlugin",
        logpath_keyvalue,
        NULL
    );
}

void
create_group_plugin_options(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(
        3,
        "ModulePath=" SRC_DIR "/example_group_plugin.py",
        "ClassName=SudoGroupPlugin",
        NULL
    );
}

void
create_debugging_plugin_options(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(
        3,
        "ModulePath=" SRC_DIR "/example_debugging.py",
        "ClassName=DebugDemoPlugin",
        NULL
    );
}

void
create_conversation_plugin_options(void)
{
    static char logpath_keyvalue[PATH_MAX + 16];
    snprintf(logpath_keyvalue, sizeof(logpath_keyvalue), "LogPath=%s", data.tmp_dir);

    free(data.plugin_options);
    data.plugin_options = create_str_array(
        4,
        "ModulePath=" SRC_DIR "/example_conversation.py",
        "ClassName=ReasonLoggerIOPlugin",
        logpath_keyvalue,
        NULL
    );
}

void
create_policy_plugin_options(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(
        3,
        "ModulePath=" SRC_DIR "/example_policy_plugin.py",
        "ClassName=SudoPolicyPlugin",
        NULL
    );
}

int
init(void)
{
    // always start each test from clean state
    memset(&data, 0, sizeof(data));

    memset(&example_pwd, 0, sizeof(example_pwd));
    example_pwd.pw_name = "pw_name";
    example_pwd.pw_passwd = "pw_passwd";
    example_pwd.pw_gecos = "pw_gecos";
    example_pwd.pw_shell ="pw_shell";
    example_pwd.pw_dir = "pw_dir";
    example_pwd.pw_uid = (uid_t)1001;
    example_pwd.pw_gid = (gid_t)101;

    VERIFY_TRUE(asprintf(&data.tmp_dir, TEMP_PATH_TEMPLATE) >= 0);
    VERIFY_NOT_NULL(mkdtemp(data.tmp_dir));

    // by default we test in developer mode, so the python plugin can be loaded
    sudo_conf_clear_paths();
    VERIFY_INT(sudo_conf_read(sudo_conf_developer_mode, SUDO_CONF_ALL), true);
    VERIFY_TRUE(sudo_conf_developer_mode());

    // some default values for the plugin open:
    data.settings = create_str_array(1, NULL);
    data.user_info = create_str_array(1, NULL);
    data.command_info = create_str_array(1, NULL);
    data.command_info = create_str_array(1, NULL);
    data.plugin_argc = 0;
    data.plugin_argv = create_str_array(1, NULL);
    data.user_env = create_str_array(1, NULL);

    return true;
}

int
cleanup(int success)
{
    if (!success) {
        printf("\nThe output of the plugin:\n%s", data.stdout_str);
        printf("\nThe error output of the plugin:\n%s", data.stderr_str);
    }

    VERIFY_TRUE(rmdir_recursive(data.tmp_dir));

    free(data.settings);
    free(data.user_info);
    free(data.command_info);
    free(data.plugin_argv);
    free(data.user_env);
    free(data.plugin_options);

    VERIFY_FALSE(Py_IsInitialized());
    return true;
}

int
check_example_io_plugin_version_display(int is_verbose)
{
    create_io_plugin_options(data.tmp_dir);

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv, data.user_env,
                              data.plugin_options), SUDO_RC_OK);
    VERIFY_INT(python_io->show_version(is_verbose), SUDO_RC_OK);

    python_io->close(0, 0);  // this should not call the python plugin close as there was no command run invocation

    if (is_verbose) {
        // Note: the exact python version is environment dependant
        VERIFY_STR_CONTAINS(data.stdout_str, "Python interpreter version:");
        VERIFY_STR_CONTAINS(data.stdout_str, "Python io plugin API version");
    } else {
        VERIFY_STDOUT(expected_path("check_example_io_plugin_version_display.stdout"));
    }

    VERIFY_STDERR(expected_path("check_example_io_plugin_version_display.stderr"));
    VERIFY_FILE("sudo.log", expected_path("check_example_io_plugin_version_display.stored"));

    return true;
}

int
check_example_io_plugin_command_log(void)
{
    create_io_plugin_options(data.tmp_dir);

    free(data.plugin_argv);
    data.plugin_argc = 2;
    data.plugin_argv = create_str_array(3, "id", "--help", NULL);

    free(data.command_info);
    data.command_info = create_str_array(3, "command=/bin/id", "runas_uid=0", NULL);

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_OK);
    VERIFY_INT(python_io->log_stdin("some standard input", strlen("some standard input")), SUDO_RC_OK);
    VERIFY_INT(python_io->log_stdout("some standard output", strlen("some standard output")), SUDO_RC_OK);
    VERIFY_INT(python_io->log_stderr("some standard error", strlen("some standard error")), SUDO_RC_OK);
    VERIFY_INT(python_io->log_suspend(SIGTSTP), SUDO_RC_OK);
    VERIFY_INT(python_io->log_suspend(SIGCONT), SUDO_RC_OK);
    VERIFY_INT(python_io->change_winsize(200, 100), SUDO_RC_OK);
    VERIFY_INT(python_io->log_ttyin("some tty input", strlen("some tty input")), SUDO_RC_OK);
    VERIFY_INT(python_io->log_ttyout("some tty output", strlen("some tty output")), SUDO_RC_OK);

    python_io->close(1, 0);  // successful execution, command returned 1

    VERIFY_STDOUT(expected_path("check_example_io_plugin_command_log.stdout"));
    VERIFY_STDERR(expected_path("check_example_io_plugin_command_log.stderr"));
    VERIFY_FILE("sudo.log", expected_path("check_example_io_plugin_command_log.stored"));

    return true;
}

int
check_example_io_plugin_failed_to_start_command(void)
{
    create_io_plugin_options(data.tmp_dir);

    free(data.plugin_argv);
    data.plugin_argc = 1;
    data.plugin_argv = create_str_array(2, "cmd", NULL);

    free(data.command_info);
    data.command_info = create_str_array(3, "command=/usr/share/cmd", "runas_uid=0", NULL);

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_OK);

    python_io->close(0, EPERM);  // execve returned with error

    VERIFY_STDOUT(expected_path("check_example_io_plugin_failed_to_start_command.stdout"));
    VERIFY_STDERR(expected_path("check_example_io_plugin_failed_to_start_command.stderr"));
    VERIFY_FILE("sudo.log", expected_path("check_example_io_plugin_failed_to_start_command.stored"));

    return true;
}

int
check_example_io_plugin_fails_with_python_backtrace(void)
{
    create_io_plugin_options("/some/not/writable/directory");

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_ERROR);

    VERIFY_STDOUT(expected_path("check_example_io_plugin_fails_with_python_backtrace.stdout"));
    VERIFY_STDERR(expected_path("check_example_io_plugin_fails_with_python_backtrace.stderr"));

    python_io->close(0, 0);
    return true;
}

int
check_example_group_plugin(void)
{
    create_group_plugin_options();

    VERIFY_INT(group_plugin->init(GROUP_API_VERSION, fake_printf, data.plugin_options), SUDO_RC_OK);

    VERIFY_INT(group_plugin->query("test", "mygroup", NULL), SUDO_RC_OK);
    VERIFY_INT(group_plugin->query("testuser2", "testgroup", NULL), SUDO_RC_OK);
    VERIFY_INT(group_plugin->query("testuser2", "mygroup", NULL), SUDO_RC_REJECT);
    VERIFY_INT(group_plugin->query("test", "testgroup", NULL), SUDO_RC_REJECT);

    group_plugin->cleanup();
    VERIFY_STR(data.stderr_str, "");
    VERIFY_STR(data.stdout_str, "");
    return true;
}

const char *
create_debug_config(const char *debug_spec)
{
    char *result = NULL;

    static char config_path[PATH_MAX] = "/";
    snprintf(config_path, sizeof(config_path), "%s/sudo.conf", data.tmp_dir);

    char *content = NULL;
    if (asprintf(&content, "Set developer_mode true\n"
                           "Debug %s %s/debug.log %s\n",
                 "python_plugin.so", data.tmp_dir, debug_spec) < 0)
    {
        printf("Failed to allocate string\n");
        goto cleanup;
    }

    if (fwriteall(config_path, content) != true) {
        printf("Failed to write '%s'\n", config_path);
        goto cleanup;
    }

    result = config_path;

cleanup:
    free(content);

    return result;
}

int
check_example_group_plugin_is_able_to_debug(void)
{
    const char *config_path = create_debug_config("py_calls@diag");
    VERIFY_NOT_NULL(config_path);
    VERIFY_INT(sudo_conf_read(config_path, SUDO_CONF_ALL), true);

    create_group_plugin_options();

    group_plugin->init(GROUP_API_VERSION, fake_printf, data.plugin_options);

    group_plugin->query("user", "group", &example_pwd);

    group_plugin->cleanup();

    VERIFY_STR(data.stderr_str, "");
    VERIFY_STR(data.stdout_str, "");

    VERIFY_LOG_LINES(expected_path("check_example_group_plugin_is_able_to_debug.log"));

    return true;
}

int
check_example_debugging(const char *debug_spec)
{
    const char *config_path = create_debug_config(debug_spec);
    VERIFY_NOT_NULL(config_path);
    VERIFY_INT(sudo_conf_read(config_path, SUDO_CONF_ALL), true);

    create_debugging_plugin_options();

    free(data.settings);
    char *debug_flags_setting = NULL;
    VERIFY_TRUE(asprintf(&debug_flags_setting, "debug_flags=%s/debug.log %s", data.tmp_dir, debug_spec) >= 0);

    data.settings = create_str_array(3, debug_flags_setting, "plugin_path=python_plugin.so", NULL);

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_OK);
    python_io->close(0, 0);

    VERIFY_STR(data.stderr_str, "");
    VERIFY_STR(data.stdout_str, "");

    VERIFY_LOG_LINES(expected_path("check_example_debugging_%s.log", debug_spec));

    free(debug_flags_setting);
    return true;
}

int
check_loading_fails(const char *name)
{
    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_ERROR);
    python_io->close(0, 0);

    VERIFY_STDOUT(expected_path("check_loading_fails_%s.stdout", name));
    VERIFY_STDERR(expected_path("check_loading_fails_%s.stderr", name));

    return true;
}

int
check_loading_fails_with_missing_path(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(2, "ClassName=DebugDemoPlugin", NULL);
    return check_loading_fails("missing_path");
}

int
check_loading_fails_with_missing_classname(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(2, "ModulePath=" SRC_DIR "/example_debugging.py", NULL);
    return check_loading_fails("missing_classname");
}

int
check_loading_fails_with_wrong_classname(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(3, "ModulePath=" SRC_DIR "/example_debugging.py",
                                              "ClassName=MispelledPluginName", NULL);
    return check_loading_fails("wrong_classname");
}

int
check_loading_fails_with_wrong_path(void)
{
    free(data.plugin_options);
    data.plugin_options = create_str_array(3, "ModulePath=/wrong_path.py", "ClassName=PluginName", NULL);
    return check_loading_fails("wrong_path");
}

int
check_loading_fails_plugin_is_not_owned_by_root(void)
{
    sudo_conf_clear_paths();
    VERIFY_INT(sudo_conf_read(sudo_conf_normal_mode, SUDO_CONF_ALL), true);

    create_debugging_plugin_options();
    return check_loading_fails("not_owned_by_root");
}

int
check_example_conversation_plugin_reason_log(int simulate_suspend, const char *description)
{
    create_conversation_plugin_options();

    free(data.plugin_argv); // have a command run
    data.plugin_argc = 1;
    data.plugin_argv = create_str_array(2, "/bin/whoami", NULL);

    data.conv_replies[0] = "my fake reason";
    data.conv_replies[1] = "my real secret reason";

    sudo_conv_t conversation = simulate_suspend ? fake_conversation_with_suspend : fake_conversation;

    VERIFY_INT(python_io->open(SUDO_API_VERSION, conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_OK);
    python_io->close(0, 0);

    VERIFY_STDOUT(expected_path("check_example_conversation_plugin_reason_log_%s.stdout", description));
    VERIFY_STDERR(expected_path("check_example_conversation_plugin_reason_log_%s.stderr", description));
    VERIFY_CONV(expected_path("check_example_conversation_plugin_reason_log_%s.conversation", description));
    VERIFY_FILE("sudo_reasons.txt", expected_path("check_example_conversation_plugin_reason_log_%s.stored", description));
    return true;
}

int
check_example_conversation_plugin_user_interrupts(void)
{
    create_conversation_plugin_options();

    free(data.plugin_argv); // have a command run
    data.plugin_argc = 1;
    data.plugin_argv = create_str_array(2, "/bin/whoami", NULL);

    data.conv_replies[0] = NULL; // this simulates user interrupt for the first question

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_REJECT);
    python_io->close(0, 0);

    VERIFY_STDOUT(expected_path("check_example_conversation_plugin_user_interrupts.stdout"));
    VERIFY_STDERR(expected_path("check_example_conversation_plugin_user_interrupts.stderr"));
    VERIFY_CONV(expected_path("check_example_conversation_plugin_user_interrupts.conversation"));
    return true;
}

int
check_example_policy_plugin_version_display(int is_verbose)
{
    create_policy_plugin_options();

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);
    VERIFY_INT(python_policy->show_version(is_verbose), SUDO_RC_OK);

    python_policy->close(0, 0);  // this should not call the python plugin close as there was no command run invocation

    if (is_verbose) {
        // Note: the exact python version is environment dependant
        VERIFY_STR_CONTAINS(data.stdout_str, "Python interpreter version:");
        VERIFY_STR_CONTAINS(data.stdout_str, "Python policy plugin API version");
    } else {
        VERIFY_STDOUT(expected_path("check_example_policy_plugin_version_display.stdout"));
    }

    VERIFY_STDERR(expected_path("check_example_policy_plugin_version_display.stderr"));

    return true;
}

int
check_example_policy_plugin_accepted_execution(void)
{
    create_policy_plugin_options();

    data.plugin_argc = 2;
    data.plugin_argv = create_str_array(3, "/bin/whoami", "--help", NULL);

    free(data.user_env);
    data.user_env = create_str_array(3, "USER_ENV1=VALUE1", "USER_ENV2=value2", NULL);

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);

    char **env_add = create_str_array(3, "REQUESTED_ENV1=VALUE1", "REQUESTED_ENV2=value2", NULL);

    char **argv_out, **user_env_out, **command_info_out;  // free to contain garbage

    VERIFY_INT(python_policy->check_policy(data.plugin_argc, data.plugin_argv, env_add,
                                          &command_info_out, &argv_out, &user_env_out),
               SUDO_RC_ACCEPT);

    VERIFY_STR_SET(command_info_out, 4, "command=/bin/whoami", "runas_uid=0", "runas_gid=0", NULL);
    VERIFY_STR_SET(user_env_out, 5, "USER_ENV1=VALUE1", "USER_ENV2=value2",
                   "REQUESTED_ENV1=VALUE1", "REQUESTED_ENV2=value2", NULL);
    VERIFY_STR_SET(argv_out, 3, "/bin/whoami", "--help", NULL);

    VERIFY_INT(python_policy->init_session(&example_pwd, &user_env_out), SUDO_RC_ACCEPT);

    // init session is able to modify the user env:
    VERIFY_STR_SET(user_env_out, 6, "USER_ENV1=VALUE1", "USER_ENV2=value2",
                   "REQUESTED_ENV1=VALUE1", "REQUESTED_ENV2=value2", "PLUGIN_EXAMPLE_ENV=1", NULL);

    python_policy->close(3, 0);  // successful execution returned exit code 3

    VERIFY_STDOUT(expected_path("check_example_policy_plugin_accepted_execution.stdout"));
    VERIFY_STDERR(expected_path("check_example_policy_plugin_accepted_execution.stderr"));

    free(env_add);
    free(user_env_out);
    free(command_info_out);
    free(argv_out);
    return true;
}

int
check_example_policy_plugin_failed_execution(void)
{
    create_policy_plugin_options();

    data.plugin_argc = 2;
    data.plugin_argv = create_str_array(3, "/bin/id", "--help", NULL);

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);

    char **argv_out, **user_env_out, **command_info_out;  // free to contain garbage

    VERIFY_INT(python_policy->check_policy(data.plugin_argc, data.plugin_argv, NULL,
                                          &command_info_out, &argv_out, &user_env_out),
               SUDO_RC_ACCEPT);

    // pwd is unset (user is not part of /etc/passwd)
    VERIFY_INT(python_policy->init_session(NULL, &user_env_out), SUDO_RC_ACCEPT);

    python_policy->close(12345, ENOENT);  // failed to execute

    VERIFY_STDOUT(expected_path("check_example_policy_plugin_failed_execution.stdout"));
    VERIFY_STDERR(expected_path("check_example_policy_plugin_failed_execution.stderr"));

    free(user_env_out);
    free(command_info_out);
    free(argv_out);
    return true;
}

int
check_example_policy_plugin_denied_execution(void)
{
    create_policy_plugin_options();

    data.plugin_argc = 1;
    data.plugin_argv = create_str_array(2, "/bin/passwd", NULL);

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);

    char **argv_out, **user_env_out, **command_info_out;  // free to contain garbage

    VERIFY_INT(python_policy->check_policy(data.plugin_argc, data.plugin_argv, NULL,
                                          &command_info_out, &argv_out, &user_env_out),
               SUDO_RC_REJECT);

    VERIFY_PTR(command_info_out, NULL);
    VERIFY_PTR(argv_out, NULL);
    VERIFY_PTR(user_env_out, NULL);

    python_policy->close(0, 0);  // there was no execution

    VERIFY_STDOUT(expected_path("check_example_policy_plugin_denied_execution.stdout"));
    VERIFY_STDERR(expected_path("check_example_policy_plugin_denied_execution.stderr"));

    return true;
}

int
check_example_policy_plugin_list(void)
{
    create_policy_plugin_options();

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "-- minimal --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, false, NULL), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- minimal (verbose) --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, true, NULL), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with user --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, false, "testuser"), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with user (verbose) --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, true, "testuser"), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with allowed program --\n");
    free(data.plugin_argv);
    data.plugin_argc = 3;
    data.plugin_argv = create_str_array(4, "/bin/id", "some", "arguments", NULL);
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, false, NULL), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with allowed program (verbose) --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, true, NULL), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with denied program --\n");
    free(data.plugin_argv);
    data.plugin_argc = 1;
    data.plugin_argv = create_str_array(2, "/bin/passwd", NULL);
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, false, NULL), SUDO_RC_OK);

    snprintf_append(data.stdout_str, MAX_OUTPUT, "\n-- with denied program (verbose) --\n");
    VERIFY_INT(python_policy->list(data.plugin_argc, data.plugin_argv, true, NULL), SUDO_RC_OK);

    python_policy->close(0, 0);  // there was no execution

    VERIFY_STDOUT(expected_path("check_example_policy_plugin_list.stdout"));
    VERIFY_STDERR(expected_path("check_example_policy_plugin_list.stderr"));

    return true;
}

int
check_example_policy_plugin_validate_invalidate(void)
{
    // the plugin does not do any meaningful for these, so using log to validate instead
    const char *config_path = create_debug_config("py_calls@diag");
    VERIFY_NOT_NULL(config_path);
    VERIFY_INT(sudo_conf_read(config_path, SUDO_CONF_ALL), true);

    create_policy_plugin_options();

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);
    VERIFY_INT(python_policy->validate(), SUDO_RC_OK);
    python_policy->invalidate(true);
    python_policy->invalidate(false);

    python_policy->close(0, 0); // no command execution

    VERIFY_LOG_LINES(expected_path("check_example_policy_plugin_validate_invalidate.log"));
    VERIFY_STR(data.stderr_str, "");
    VERIFY_STR(data.stdout_str, "");
    return true;
}

int
check_policy_plugin_callbacks_are_optional(void)
{
    create_debugging_plugin_options();

    VERIFY_INT(python_policy->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                                  data.user_info, data.user_env, data.plugin_options),
               SUDO_RC_OK);

    VERIFY_PTR(python_policy->list, NULL);
    VERIFY_PTR(python_policy->validate, NULL);
    VERIFY_PTR(python_policy->invalidate, NULL);
    VERIFY_PTR_NE(python_policy->check_policy, NULL); // (not optional)
    VERIFY_PTR(python_policy->init_session, NULL);
    VERIFY_PTR(python_policy->show_version, NULL);

    python_io->close(0, 0);
    return true;
}

int
check_io_plugin_callbacks_are_optional(void)
{
    create_debugging_plugin_options();

    VERIFY_INT(python_io->open(SUDO_API_VERSION, fake_conversation, fake_printf, data.settings,
                              data.user_info, data.command_info, data.plugin_argc, data.plugin_argv,
                              data.user_env, data.plugin_options), SUDO_RC_OK);

    VERIFY_PTR(python_io->log_stdin, NULL);
    VERIFY_PTR(python_io->log_stdout, NULL);
    VERIFY_PTR(python_io->log_stderr, NULL);
    VERIFY_PTR(python_io->log_ttyin, NULL);
    VERIFY_PTR(python_io->log_ttyout, NULL);
    VERIFY_PTR(python_io->show_version, NULL);
    VERIFY_PTR(python_io->change_winsize, NULL);

    python_io->close(0, 0);
    return true;
}

int
check_python_plugin_can_be_loaded(const char *python_plugin_path)
{
    printf("Loading python plugin from '%s'\n", python_plugin_path);
    void *python_plugin_handle = sudo_dso_load(python_plugin_path, SUDO_DSO_LAZY|SUDO_DSO_GLOBAL);
    VERIFY_PTR_NE(python_plugin_handle, NULL);

    python_io = sudo_dso_findsym(python_plugin_handle, "python_io");
    VERIFY_PTR_NE(python_io, NULL);

    group_plugin = sudo_dso_findsym(python_plugin_handle, "group_plugin");
    VERIFY_PTR_NE(group_plugin, NULL);

    python_policy = sudo_dso_findsym(python_plugin_handle, "python_policy");
    VERIFY_PTR_NE(python_policy, NULL);
    return true;
}

int
main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Please specify the python_plugin.so as argument!\n");
        return EXIT_FAILURE;
    }
    const char *python_plugin_so_path = argv[1];

    RUN_TEST(check_python_plugin_can_be_loaded(python_plugin_so_path));
    RUN_TEST(check_example_io_plugin_version_display(true));
    RUN_TEST(check_example_io_plugin_version_display(false));
    RUN_TEST(check_example_io_plugin_command_log());
    RUN_TEST(check_example_io_plugin_failed_to_start_command());
    RUN_TEST(check_example_io_plugin_fails_with_python_backtrace());
    RUN_TEST(check_io_plugin_callbacks_are_optional());

    RUN_TEST(check_example_group_plugin());
    RUN_TEST(check_example_group_plugin_is_able_to_debug());

    RUN_TEST(check_loading_fails_with_missing_path());
    RUN_TEST(check_loading_fails_with_missing_classname());
    RUN_TEST(check_loading_fails_with_wrong_classname());
    RUN_TEST(check_loading_fails_with_wrong_path());
    RUN_TEST(check_loading_fails_plugin_is_not_owned_by_root());

    RUN_TEST(check_example_conversation_plugin_reason_log(false, "without_suspend"));
    RUN_TEST(check_example_conversation_plugin_reason_log(true, "with_suspend"));
    RUN_TEST(check_example_conversation_plugin_user_interrupts());

    RUN_TEST(check_example_policy_plugin_version_display(true));
    RUN_TEST(check_example_policy_plugin_version_display(false));
    RUN_TEST(check_example_policy_plugin_accepted_execution());
    RUN_TEST(check_example_policy_plugin_failed_execution());
    RUN_TEST(check_example_policy_plugin_denied_execution());
    RUN_TEST(check_example_policy_plugin_list());
    RUN_TEST(check_example_policy_plugin_validate_invalidate());
    RUN_TEST(check_policy_plugin_callbacks_are_optional());

    RUN_TEST(check_example_debugging("plugin@err"));
    RUN_TEST(check_example_debugging("plugin@info"));
    RUN_TEST(check_example_debugging("load@diag"));
    RUN_TEST(check_example_debugging("sudo_cb@info"));
    RUN_TEST(check_example_debugging("c_calls@diag"));
    RUN_TEST(check_example_debugging("c_calls@info"));
    RUN_TEST(check_example_debugging("py_calls@diag"));
    RUN_TEST(check_example_debugging("py_calls@info"));
    RUN_TEST(check_example_debugging("plugin@err"));

    return EXIT_SUCCESS;
}
