/*
 * Growable, NUL-terminated C-string builder.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "string-builder.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Set EILSEQ for invalid input and report failure. */
static int string_builder_invalid(void)
{
    errno = EILSEQ;
    return -1;
}

/* Initialize storage and establish an empty, NUL-terminated builder. */
int string_builder_init(string_builder_t *builder, size_t initial_capacity)
{
    if (builder == NULL)
        return string_builder_invalid();
    if (initial_capacity == 0) {
        string_builder_destroy(builder);
        return 0;
    }
    if (string_builder_storage_init_with_capacity(&builder->storage,
                                                   initial_capacity) < 0)
        return -1;
    string_builder_data(builder)[0] = '\0';
    return 0;
}

/* Release storage and reset the logical length. */
void string_builder_destroy(string_builder_t *builder)
{
    if (builder == NULL)
        return;
    string_builder_storage_destroy(&builder->storage);
}

/* Reserve enough capacity for extra bytes after the current contents. */
int string_builder_reserve(string_builder_t *builder, size_t extra)
{
    if (builder == NULL)
        return string_builder_invalid();
    if (extra == 0 && string_builder_storage_count(&builder->storage) == 0 &&
        string_builder_capacity(builder) == 0)
        return 0;

    /* The dynamic array counts payload elements. Reserve one additional char
     * for the string builder's trailing NUL. */
    if (extra == SIZE_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    if (string_builder_storage_reserve(&builder->storage, extra + 1) < 0)
        return -1;
    string_builder_data(builder)[string_builder_storage_count(&builder->storage)] =
        '\0';
    return 0;
}

/* Locate a source span that aliases the builder allocation. The offset must be
 * captured before reserve because reserve may move the allocation. */
static int string_builder_source_offset(const string_builder_t *builder,
                                        const void *source, size_t length,
                                        size_t *offset)
{
    const char *base_ptr = string_builder_data_const(builder);
    size_t capacity = string_builder_capacity(builder);
    if (base_ptr == NULL || source == NULL)
        return 0;
    uintptr_t base = (uintptr_t) (const void *) base_ptr;
    uintptr_t address = (uintptr_t) source;
    if (address < base)
        return 0;
    uintptr_t delta = address - base;
    if (delta > (uintptr_t) SIZE_MAX)
        return 0;
    size_t start = (size_t) delta;
    if (start > capacity || length > capacity - start)
        return 0;
    *offset = start;
    return 1;
}

/* Commit string bytes through the generic array and restore the terminator. */
static int string_builder_commit_append(string_builder_t *builder,
                                        const char *data, size_t len)
{
    if (string_builder_storage_append_n(&builder->storage, data, len) < 0)
        return -1;
    string_builder_data(builder)[string_builder_storage_count(&builder->storage)] =
        '\0';
    return 0;
}

/* Append a C string and keep the builder NUL-terminated. */
int string_builder_append(string_builder_t *builder, const char *text)
{
    if (builder == NULL || text == NULL)
        return string_builder_invalid();

    size_t len = strlen(text);
    if (len == 0)
        return 0;

    size_t source_offset = 0;
    int aliases = string_builder_source_offset(builder, text, len,
                                               &source_offset);
    if (string_builder_reserve(builder, len) < 0)
        return -1;
    if (aliases)
        text = string_builder_data_const(builder) + source_offset;
    return string_builder_commit_append(builder, text, len);
}

/* Convert a formatting failure into the module's documented errno values. */
static int string_builder_format_failure(void)
{
    if (errno != EOVERFLOW && errno != EILSEQ)
        errno = EILSEQ;
    return -1;
}

/* Call vsnprintf with a copied argument list for the current sizing pass. */
static int string_builder_vsnprintf(char *destination, size_t available,
                                    const char *format, va_list arguments)
{
    va_list pass;
    va_copy(pass, arguments);
    errno = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    int result = vsnprintf(destination, available, format, pass);
#pragma clang diagnostic pop
    va_end(pass);
    return result;
}

typedef enum string_builder_format_status {
    STRING_BUILDER_FORMAT_ERROR = -1,
    STRING_BUILDER_FORMAT_FIT = 0,
    STRING_BUILDER_FORMAT_TRUNCATED = 1
} string_builder_format_status_t;

/* Ensure the builder has a writable tail and capture its current length. */
static int string_builder_prepare_appendf(string_builder_t *builder,
                                          size_t *old_len)
{
    if (string_builder_capacity(builder) == 0 &&
        string_builder_reserve(builder, 1) < 0)
        return -1;

    char *data = string_builder_data(builder);
    size_t capacity = string_builder_capacity(builder);
    *old_len = string_builder_storage_count(&builder->storage);
    if (data == NULL || *old_len >= capacity)
        return string_builder_invalid();
    return 0;
}

/* Format into the current tail and report whether the result was truncated. */
static string_builder_format_status_t
string_builder_try_format(string_builder_t *builder, size_t old_len,
                          const char *format, va_list arguments,
                          size_t *written)
{
    char *data = string_builder_data(builder);
    size_t available = string_builder_capacity(builder) - old_len;
    int formatted = string_builder_vsnprintf(data + old_len, available, format,
                                             arguments);
    if (formatted < 0)
        return STRING_BUILDER_FORMAT_ERROR;

    size_t visible = strlen(data + old_len);
    if ((size_t) formatted < available || visible < available - 1) {
        *written = visible;
        return STRING_BUILDER_FORMAT_FIT;
    }

    *written = (size_t) formatted;
    return STRING_BUILDER_FORMAT_TRUNCATED;
}

/* Restore the terminator after a failed formatting attempt. */
static void string_builder_rollback_appendf(string_builder_t *builder,
                                            size_t old_len)
{
    char *data = string_builder_data(builder);
    if (data != NULL && old_len < string_builder_capacity(builder))
        data[old_len] = '\0';
}

/* Append printf-formatted text, growing and retrying when the first pass is
 * truncated.
 */
int string_builder_appendf(string_builder_t *builder, const char *format, ...)
{
    int result = -1;
    int saved_errno;
    size_t old_len = 0;
    size_t written = 0;
    string_builder_format_status_t status;
    va_list arguments;

    if (builder == NULL || format == NULL)
        return string_builder_invalid();

    saved_errno = errno;
    va_start(arguments, format);

    if (string_builder_prepare_appendf(builder, &old_len) < 0)
        goto out;

    status = string_builder_try_format(builder, old_len, format, arguments,
                                       &written);
    if (status == STRING_BUILDER_FORMAT_ERROR) {
        string_builder_format_failure();
        goto rollback;
    }
    if (status == STRING_BUILDER_FORMAT_TRUNCATED) {
        if (string_builder_reserve(builder, written) < 0)
            goto rollback;

        status = string_builder_try_format(builder, old_len, format, arguments,
                                           &written);
        if (status == STRING_BUILDER_FORMAT_ERROR) {
            string_builder_format_failure();
            goto rollback;
        }
        if (status == STRING_BUILDER_FORMAT_TRUNCATED) {
            errno = EOVERFLOW;
            goto rollback;
        }
    }

    if (string_builder_commit_append(
            builder, string_builder_data(builder) + old_len, written) < 0)
        goto rollback;

    errno = saved_errno;
    result = 0;
    goto out;

rollback:
    string_builder_rollback_appendf(builder, old_len);

out:
    va_end(arguments);
    return result;
}

/* Return mutable storage for the builder, if it has been allocated. */
char *string_builder_data(string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_data(&builder->storage) : NULL;
}

/* Return const storage for the builder, if it has been allocated. */
const char *string_builder_data_const(const string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_data_const(&builder->storage)
                          : NULL;
}

/* Return the number of data bytes currently stored. */
size_t string_builder_length(const string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_count(&builder->storage) : 0;
}

/* Return allocated capacity in bytes, including the terminating NUL. */
size_t string_builder_capacity(const string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_capacity(&builder->storage) : 0;
}
