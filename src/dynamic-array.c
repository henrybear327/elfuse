/*
 * Generic growable array of trivially-copyable elements.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dynamic-array.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DYNAMIC_ARRAY_INITIAL_CAPACITY ((size_t) 8)

/* Set errno for a bad argument and return a standard failure code. */
static int dynamic_array_invalid(void)
{
    errno = EINVAL;
    return -1;
}

/* Check that the array handle is non-null and has a non-zero element size. */
static int dynamic_array_validate(const dynamic_array_t *array)
{
    if (array == NULL || array->element_size == 0)
        return dynamic_array_invalid();
    return 0;
}

/* Return count + extra after guarding against size_t overflow. */
static int dynamic_array_count_plus(const dynamic_array_t *array,
                                    size_t extra,
                                    size_t *total)
{
    if (extra > SIZE_MAX - array->count) {
        errno = EOVERFLOW;
        return -1;
    }
    *total = array->count + extra;
    return 0;
}

/* Compute the byte size for a number of elements with overflow protection. */
static int dynamic_array_bytes(const dynamic_array_t *array,
                               size_t count,
                               size_t *bytes)
{
    if (count != 0 && array->element_size > SIZE_MAX / count) {
        errno = EOVERFLOW;
        return -1;
    }
    *bytes = count * array->element_size;
    return 0;
}

/* Return the offset of an in-array source span, including capacity bytes. */
static int dynamic_array_source_offset(const dynamic_array_t *array,
                                       const void *source,
                                       size_t bytes,
                                       size_t *offset)
{
    if (array->data == NULL || source == NULL)
        return 0;

    uintptr_t base = (uintptr_t) array->data;
    uintptr_t address = (uintptr_t) source;
    if (address < base)
        return 0;
    uintptr_t delta = address - base;
    if (delta > (uintptr_t) SIZE_MAX)
        return 0;
    size_t start = (size_t) delta;
    size_t allocation_bytes;
    if (dynamic_array_bytes(array, array->capacity, &allocation_bytes) < 0)
        return 0;
    if (start > allocation_bytes || bytes > allocation_bytes - start)
        return 0;
    *offset = start;
    return 1;
}

/* Initialize only metadata; allocate storage separately when requested.
 *
 * This is a fresh-initialization operation and deliberately does not inspect
 * prior object contents, so an automatic, uninitialized object is safe. Use
 * dynamic_array_destroy before reinitializing an array that already owns
 * storage; otherwise that allocation is intentionally abandoned.
 */
int dynamic_array_init(dynamic_array_t *array, size_t element_size)
{
    if (array == NULL || element_size == 0)
        return dynamic_array_invalid();

    *array = (dynamic_array_t) {
        .element_size = element_size,
    };
    return 0;
}

/* Initialize and reserve storage for an initial number of elements.
 *
 * Like dynamic_array_init, this is a fresh-initialization operation that does
 * not inspect prior object contents. In particular, do not free an
 * indeterminate pointer from an automatic object; destroy an existing array
 * before reinitializing it.
 */
int dynamic_array_init_with_capacity(dynamic_array_t *array,
                                     size_t element_size,
                                     size_t initial_capacity)
{
    if (array == NULL || element_size == 0)
        return dynamic_array_invalid();

    /* Establish a safe zero state before any fallible allocation. This is a
     * fresh initializer, so an existing allocation must have been destroyed
     * by the caller rather than silently leaked here. */
    *array = (dynamic_array_t) {0};

    size_t bytes;
    if (initial_capacity != 0 && element_size > SIZE_MAX / initial_capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    bytes = initial_capacity * element_size;
    void *storage = NULL;
    if (bytes != 0) {
        storage = malloc(bytes);
        if (storage == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }

    *array = (dynamic_array_t) {
        .data = storage,
        .capacity = initial_capacity,
        .element_size = element_size,
    };
    return 0;
}

/* Release backing storage and reset the array object to zero state. */
void dynamic_array_destroy(dynamic_array_t *array)
{
    if (array == NULL)
        return;
    free(array->data);
    *array = (dynamic_array_t) {0};
}

/* Ensure the array has capacity for at least extra additional elements. */
int dynamic_array_reserve(dynamic_array_t *array, size_t extra)
{
    if (dynamic_array_validate(array) < 0)
        return -1;

    size_t needed;
    if (dynamic_array_count_plus(array, extra, &needed) < 0)
        return -1;
    if (needed <= array->capacity)
        return 0;

    size_t new_capacity = array->capacity;
    if (new_capacity == 0)
        new_capacity = DYNAMIC_ARRAY_INITIAL_CAPACITY;
    while (new_capacity < needed) {
        if (new_capacity > SIZE_MAX / 2) {
            new_capacity = needed;
            break;
        }
        new_capacity *= 2;
    }

    size_t bytes;
    if (dynamic_array_bytes(array, new_capacity, &bytes) < 0)
        return -1;
    void *grown = realloc(array->data, bytes);
    if (grown == NULL && bytes != 0) {
        errno = ENOMEM;
        return -1;
    }
    array->data = grown;
    array->capacity = new_capacity;
    return 0;
}

/* Resize logical length; zero-initialize any newly visible elements. */
int dynamic_array_resize(dynamic_array_t *array, size_t count)
{
    if (dynamic_array_validate(array) < 0)
        return -1;
    if (count > array->capacity) {
        size_t extra = count - array->count;
        if (dynamic_array_reserve(array, extra) < 0)
            return -1;
    }
    if (count > array->count) {
        size_t old_bytes, new_bytes;
        if (dynamic_array_bytes(array, array->count, &old_bytes) < 0)
            return -1;
        if (dynamic_array_bytes(array, count, &new_bytes) < 0)
            return -1;
        memset((unsigned char *) array->data + old_bytes, 0,
               new_bytes - old_bytes);
    }
    array->count = count;
    return 0;
}

/* Append multiple elements from source memory to the end of the array. */
int dynamic_array_append_n(dynamic_array_t *array,
                           const void *data,
                           size_t count)
{
    if (dynamic_array_validate(array) < 0)
        return -1;
    if (count == 0)
        return 0;
    if (data == NULL)
        return dynamic_array_invalid();

    size_t total;
    if (dynamic_array_count_plus(array, count, &total) < 0)
        return -1;
    size_t bytes;
    if (dynamic_array_bytes(array, count, &bytes) < 0)
        return -1;
    size_t offset = 0;
    int aliases = dynamic_array_source_offset(array, data, bytes, &offset);

    if (dynamic_array_reserve(array, count) < 0)
        return -1;
    if (aliases)
        data = (const unsigned char *) array->data + offset;
    size_t old_bytes;
    if (dynamic_array_bytes(array, array->count, &old_bytes) < 0)
        return -1;
    memmove((unsigned char *) array->data + old_bytes, data, bytes);
    array->count = total;
    return 0;
}

/* Insert multiple elements at index while preserving existing elements. */
int dynamic_array_insert_n(dynamic_array_t *array,
                           size_t index,
                           const void *data,
                           size_t count)
{
    if (dynamic_array_validate(array) < 0)
        return -1;
    if (index > array->count)
        return dynamic_array_invalid();
    if (count == 0)
        return 0;
    if (data == NULL)
        return dynamic_array_invalid();

    size_t total;
    if (count > SIZE_MAX - array->count) {
        errno = EOVERFLOW;
        return -1;
    }
    total = array->count + count;
    size_t bytes, index_bytes, tail_bytes;
    if (dynamic_array_bytes(array, count, &bytes) < 0 ||
        dynamic_array_bytes(array, index, &index_bytes) < 0 ||
        dynamic_array_bytes(array, array->count - index, &tail_bytes) < 0)
        return -1;

    size_t source_offset = 0;
    int aliases =
        dynamic_array_source_offset(array, data, bytes, &source_offset);
    void *temporary = NULL;
    if (aliases) {
        temporary = malloc(bytes);
        if (temporary == NULL) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(temporary, (const unsigned char *) array->data + source_offset,
               bytes);
        data = temporary;
    }

    if (dynamic_array_reserve(array, count) < 0) {
        free(temporary);
        return -1;
    }
    unsigned char *base = array->data;
    memmove(base + index_bytes + bytes, base + index_bytes, tail_bytes);
    memcpy(base + index_bytes, data, bytes);
    array->count = total;
    free(temporary);
    return 0;
}

/* Append a single element by forwarding to append_n. */
int dynamic_array_append_one(dynamic_array_t *array, const void *data)
{
    return dynamic_array_append_n(array, data, 1);
}

/* Insert a single element by forwarding to insert_n. */
int dynamic_array_insert_one(dynamic_array_t *array,
                             size_t index,
                             const void *data)
{
    return dynamic_array_insert_n(array, index, data, 1);
}

/* Return a mutable pointer to the index-th element, or NULL when invalid. */
void *dynamic_array_at(dynamic_array_t *array, size_t index)
{
    if (dynamic_array_validate(array) < 0 || index >= array->count) {
        if (array != NULL && array->element_size != 0)
            errno = EINVAL;
        return NULL;
    }
    return (unsigned char *) array->data + index * array->element_size;
}

/* Return a read-only pointer to the index-th element, or NULL when invalid. */
const void *dynamic_array_at_const(const dynamic_array_t *array, size_t index)
{
    if (array == NULL || array->element_size == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (index >= array->count) {
        errno = EINVAL;
        return NULL;
    }
    return (const unsigned char *) array->data + index * array->element_size;
}
