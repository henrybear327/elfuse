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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Set EILSEQ for invalid input and report failure. */
static int string_builder_invalid(void)
{
    errno = EILSEQ;
    return -1;
}

/* Initialize storage and establish an empty, NUL-terminated builder. This
 * fresh initializer is safe on an uninitialized automatic object; destroy an
 * existing builder before reinitializing it.
 */
int string_builder_init(string_builder_t *builder, size_t initial_capacity)
{
    if (builder == NULL)
        return string_builder_invalid();
    builder->storage = (string_builder_storage_t) {0};
    if (initial_capacity == 0) {
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
    string_builder_data(
        builder)[string_builder_storage_count(&builder->storage)] = '\0';
    return 0;
}

/* Locate a source span that aliases the builder allocation. The offset must be
 * captured before reserve because reserve may move the allocation. */
static int string_builder_source_offset(const string_builder_t *builder,
                                        const void *source,
                                        size_t length,
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
                                        const char *data,
                                        size_t len)
{
    if (string_builder_storage_append_n(&builder->storage, data, len) < 0)
        return -1;
    string_builder_data(
        builder)[string_builder_storage_count(&builder->storage)] = '\0';
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
    int aliases =
        string_builder_source_offset(builder, text, len, &source_offset);
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

/* Format into separate storage before touching the builder. Besides avoiding
 * writes through an aliased format string, this keeps %s arguments that point
 * into the builder valid even when appending the result grows the allocation.
 */
int string_builder_appendf(string_builder_t *builder, const char *format, ...)
{
    int saved_errno;
    int formatted_len;
    size_t visible_len;
    char *formatted = NULL;
    va_list arguments;
    va_list sizing;
    va_list rendering;

    if (builder == NULL || format == NULL)
        return string_builder_invalid();

    saved_errno = errno;
    va_start(arguments, format);

    va_copy(sizing, arguments);
    errno = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    formatted_len = vsnprintf(NULL, 0, format, sizing);
#pragma clang diagnostic pop
    va_end(sizing);
    if (formatted_len < 0) {
        string_builder_format_failure();
        goto out;
    }

    formatted = malloc((size_t) formatted_len + 1);
    if (formatted == NULL) {
        errno = ENOMEM;
        goto out;
    }

    va_copy(rendering, arguments);
    errno = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    int rendered_len =
        vsnprintf(formatted, (size_t) formatted_len + 1, format, rendering);
#pragma clang diagnostic pop
    va_end(rendering);
    if (rendered_len < 0 || rendered_len != formatted_len) {
        string_builder_format_failure();
        goto out;
    }

    /* Preserve the builder's C-string semantics for formatted NUL bytes. */
    visible_len = strlen(formatted);
    if (visible_len == 0) {
        errno = saved_errno;
        free(formatted);
        va_end(arguments);
        return 0;
    }
    if (string_builder_commit_append(builder, formatted, visible_len) < 0)
        goto out;

    errno = saved_errno;
    free(formatted);
    va_end(arguments);
    return 0;

out:
    free(formatted);
    va_end(arguments);
    return -1;
}

/* Return mutable storage for the builder, if it has been allocated. */
char *string_builder_data(string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_data(&builder->storage)
                           : NULL;
}

/* Return const storage for the builder, if it has been allocated. */
const char *string_builder_data_const(const string_builder_t *builder)
{
    return builder != NULL
               ? string_builder_storage_data_const(&builder->storage)
               : NULL;
}

/* Return the number of data bytes currently stored. */
size_t string_builder_length(const string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_count(&builder->storage)
                           : 0;
}

/* Return allocated capacity in bytes, including the terminating NUL. */
size_t string_builder_capacity(const string_builder_t *builder)
{
    return builder != NULL ? string_builder_storage_capacity(&builder->storage)
                           : 0;
}
