/*
 * Growable, NUL-terminated C-string builder.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>

#include "dynamic-array.h"

DYNAMIC_ARRAY_DEFINE(string_builder_storage, char)

/* The storage representation is an implementation detail; callers should use
 * the accessors below. The generated count is the string length; capacity is
 * measured in bytes and includes the trailing NUL slot.
 */
typedef struct string_builder {
    string_builder_storage_t storage;
} string_builder_t;

/* Initialize a builder, reserving initial_capacity bytes including the NUL.
 * A zero capacity leaves storage unallocated for lazy growth. This fresh
 * initializer is safe on an uninitialized automatic object; destroy an
 * existing builder before reinitializing it. Returns 0 on success or -1 with
 * errno set on invalid input or allocation failure.
 */
int string_builder_init(string_builder_t *builder, size_t initial_capacity);

/* Release the builder storage and reset its length. Safe to call with NULL. */
void string_builder_destroy(string_builder_t *builder);

/* Ensure room for extra string bytes plus the terminating NUL. */
int string_builder_reserve(string_builder_t *builder, size_t extra);

/* Append a C string, accepting aliases into the builder's storage. As with
 * standard C string functions, the first NUL terminates the input. A NULL
 * pointer is invalid. The resulting C string is always NUL-terminated.
 */
int string_builder_append(string_builder_t *builder, const char *text);

/* Append formatted text using printf-style arguments. A formatted NUL byte
 * terminates the appended C string prefix.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
int string_builder_appendf(string_builder_t *builder, const char *format, ...);

/* Return mutable builder data, or NULL when builder is NULL or unallocated.
 * Callers must preserve the no-embedded-NUL C-string invariant.
 */
char *string_builder_data(string_builder_t *builder);

/* Return read-only builder data, or NULL when builder is NULL or unallocated.
 */
const char *string_builder_data_const(const string_builder_t *builder);

/* Return the number of data bytes currently stored, excluding the NUL. */
size_t string_builder_length(const string_builder_t *builder);

/* Return allocated capacity in bytes, including space for the NUL. */
size_t string_builder_capacity(const string_builder_t *builder);
