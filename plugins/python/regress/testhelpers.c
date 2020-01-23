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

const char *sudo_conf_developer_mode = TESTDATA_DIR "sudo.conf.developer_mode";
const char *sudo_conf_normal_mode = TESTDATA_DIR "sudo.conf.normal_mode";

struct TestData data;

static void
clean_output(char *output)
{
    // we replace some output which otherwise would be test run dependant
    str_replace_in_place(output, MAX_OUTPUT, data.tmp_dir, TEMP_PATH_TEMPLATE);

    if (data.tmp_dir2)
        str_replace_in_place(output, MAX_OUTPUT, data.tmp_dir2, TEMP_PATH_TEMPLATE "2");

    str_replace_in_place(output, MAX_OUTPUT, SRC_DIR, "SRC_DIR");
}

const char *
expected_path(const char *format, ...)
{
    static char expected_output_file[PATH_MAX];
    int count = snprintf(expected_output_file, PATH_MAX, TESTDATA_DIR);
    char *filename = expected_output_file + count;

    va_list args;
    va_start(args, format);
    vsprintf(filename, format, args);
    va_end(args);

    return expected_output_file;
}

char **
create_str_array(size_t count, ...)
{
    va_list args;

    va_start(args, count);

    char ** result = calloc(count, sizeof(char *));
    for (size_t i = 0; i < count; ++i) {
        result[i] = va_arg(args, char *);
    }

    va_end(args);
    return result;
}

int
is_update(void)
{
    static int result = -1;
    if (result < 0) {
        const char *update = getenv("UPDATE_TESTDATA");
        result = (update && strcmp(update, "1") == 0) ? 1 : 0;
    }
    return result;
}

int
verify_content(char *actual_content, const char *reference_path)
{
    clean_output(actual_content);

    if (is_update()) {
        VERIFY_TRUE(fwriteall(reference_path, actual_content));
    } else {
        char expected_output[MAX_OUTPUT] = "";
        if (!freadall(reference_path, expected_output, sizeof(expected_output))) {
            printf("Error: Missing test data at '%s'\n", reference_path);
            return false;
        }
        VERIFY_STR(actual_content, expected_output);
    }

    return true;
}

int
verify_file(const char *actual_dir, const char *actual_file_name, const char *reference_path)
{
    char actual_path[PATH_MAX];
    snprintf(actual_path, sizeof(actual_path), "%s/%s", actual_dir, actual_file_name);

    char actual_str[MAX_OUTPUT];
    if (!freadall(actual_path, actual_str, sizeof(actual_str))) {
        printf("Expected that file '%s' gets created, but it was not\n", actual_path);
        return false;
    }

    int rc = verify_content(actual_str, reference_path);
    return rc;
}

int
fake_conversation(int num_msgs, const struct sudo_conv_message msgs[],
                  struct sudo_conv_reply replies[], struct sudo_conv_callback *callback)
{
    (void) callback;
    snprintf_append(data.conv_str, MAX_OUTPUT, "Question count: %d\n", num_msgs);
    for (int i = 0; i < num_msgs; ++i) {
        const struct sudo_conv_message *msg = &msgs[i];
        snprintf_append(data.conv_str, MAX_OUTPUT, "Question %d: <<%s>> (timeout: %d, msg_type=%d)\n",
                      i, msg->msg, msg->timeout, msg->msg_type);

        if (data.conv_replies[i] == NULL)
            return 1; // simulates user interruption (conversation error)

        replies[i].reply = strdup(data.conv_replies[i]);
    }

    return 0; // simulate user answered just fine
}

int
fake_conversation_with_suspend(int num_msgs, const struct sudo_conv_message msgs[],
                               struct sudo_conv_reply replies[], struct sudo_conv_callback *callback)
{
    if (callback != NULL) {
        callback->on_suspend(SIGTSTP, callback->closure);
        callback->on_resume(SIGCONT, callback->closure);
    }

    return fake_conversation(num_msgs, msgs, replies, callback);
}

int
fake_printf(int msg_type, const char *fmt, ...)
{
    int rc = -1;
    va_list args;
    va_start(args, fmt);

    char *output = NULL;
    switch(msg_type) {
    case SUDO_CONV_INFO_MSG:
        output = data.stdout_str;
        break;
    case SUDO_CONV_ERROR_MSG:
        output = data.stderr_str;
        break;
    default:
        break;
    }

    if (output)
        rc = vsnprintf_append(output, MAX_OUTPUT, fmt, args);

    va_end(args);
    return rc;
}

int
verify_log_lines(const char *reference_path)
{
    char stored_path[PATH_MAX];
    snprintf(stored_path, sizeof(stored_path), "%s/%s", data.tmp_dir, "debug.log");

    FILE *file = fopen(stored_path, "rb");
    if (file == NULL) {
        printf("Failed to open file '%s'\n", stored_path);
        return false;
    }

    char line[1024] = "";
    char stored_str[MAX_OUTPUT] = "";
    while(fgets(line, sizeof(line), file) != NULL) {
        const char *line_data = strstr(line, "] "); // this skips the timestamp and pid at the beginning
        VERIFY_NOT_NULL(line_data); // malformed log line
        line_data += 2;

        char *line_end = strstr(line_data, " object at "); // this skips checking the pointer hex
        if (line_end)
            sprintf(line_end, " object>\n");

        VERIFY_TRUE(strlen(stored_str) + strlen(line_data) + 1 < sizeof(stored_str));  // we have enough space in buffer
        strcat(stored_str, line_data);
    }

    clean_output(stored_str);

    VERIFY_TRUE(verify_content(stored_str, reference_path));
    return true;
}

int
verify_str_set(char **actual_set, char **expected_set, const char *actual_variable_name)
{
    VERIFY_NOT_NULL(actual_set);
    VERIFY_NOT_NULL(expected_set);

    int actual_len = str_array_count(actual_set);
    int expected_len = str_array_count(expected_set);

    int matches = false;
    if (actual_len == expected_len) {
        int actual_pos = 0;
        for (; actual_pos < actual_len; ++actual_pos) {
            char *actual_item = actual_set[actual_pos];

            int expected_pos = 0;
            for (; expected_pos < expected_len; ++expected_pos) {
                if (strcmp(actual_item, expected_set[expected_pos]) == 0)
                    break;
            }

            if (expected_pos == expected_len) {
                // matching item was not found
                break;
            }
        }

        matches = (actual_pos == actual_len);
    }

    if (!matches) {
        char actual_set_str[MAX_OUTPUT] = "";
        char expected_set_str[MAX_OUTPUT] = "";
        str_array_snprint(actual_set_str, MAX_OUTPUT, actual_set, actual_len);
        str_array_snprint(expected_set_str, MAX_OUTPUT, expected_set, expected_len);

        VERIFY_PRINT_MSG("%s", actual_variable_name, actual_set_str, "expected",
                         expected_set_str, "expected to contain the same elements as");
        return false;
    }

    return true;
}
