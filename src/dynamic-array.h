/*
 * Generic growable array of trivially-copyable elements.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>

typedef struct dynamic_array {
    void *data;
    size_t count;
    size_t capacity;
    size_t element_size;
} dynamic_array_t;

#if defined(__GNUC__) || defined(__clang__)
#define DYNAMIC_ARRAY_INLINE static inline __attribute__((unused))
#else
#define DYNAMIC_ARRAY_INLINE static inline
#endif

/* Reset type metadata on a failed first-touch typed operation. */
static inline int dynamic_array_typed_result(dynamic_array_t *array,
                                             int was_uninitialized,
                                             int result)
{
    if (result < 0 && was_uninitialized && array != NULL &&
        array->data == NULL && array->count == 0 && array->capacity == 0)
        array->element_size = 0;
    return result;
}

/* Set the element size on the first typed operation and report that change. */
static inline int dynamic_array_typed_prepare(dynamic_array_t *array,
                                              size_t element_size)
{
    int was_uninitialized = array != NULL && array->element_size == 0;
    if (was_uninitialized)
        array->element_size = element_size;
    return was_uninitialized;
}

/* Initialize an array for elements of element_size bytes without allocation. */
int dynamic_array_init(dynamic_array_t *array, size_t element_size);

/* Initialize and reserve initial_capacity element slots. */
int dynamic_array_init_with_capacity(dynamic_array_t *array,
                                     size_t element_size,
                                     size_t initial_capacity);

/* Release storage and restore the all-zero state. */
void dynamic_array_destroy(dynamic_array_t *array);

/* Ensure room for extra elements beyond the current count. */
int dynamic_array_reserve(dynamic_array_t *array, size_t extra);

/* Set the logical element count. Newly exposed elements are zeroed. */
int dynamic_array_resize(dynamic_array_t *array, size_t count);

/* Append one element, or count elements when the three-argument form is
 * used. The macro keeps both forms available to callers. */
int dynamic_array_append_one(dynamic_array_t *array, const void *data);
int dynamic_array_append_n(dynamic_array_t *array, const void *data,
                           size_t count);
#define DYNAMIC_ARRAY_APPEND_PICK(_1, _2, _3, NAME, ...) NAME
#define dynamic_array_append(...)                                             \
    DYNAMIC_ARRAY_APPEND_PICK(__VA_ARGS__, dynamic_array_append_n,             \
                              dynamic_array_append_one, dynamic_array_append_dummy) \
        (__VA_ARGS__)

/* Insert one element, or count elements in the four-argument form. */
int dynamic_array_insert_one(dynamic_array_t *array, size_t index,
                             const void *data);
int dynamic_array_insert_n(dynamic_array_t *array, size_t index,
                           const void *data, size_t count);
#define DYNAMIC_ARRAY_INSERT_PICK(_1, _2, _3, _4, NAME, ...) NAME
#define dynamic_array_insert(...)                                             \
    DYNAMIC_ARRAY_INSERT_PICK(__VA_ARGS__, dynamic_array_insert_n,             \
                              dynamic_array_insert_one, dynamic_array_insert_dummy) \
        (__VA_ARGS__)

/* Return an element pointer, or NULL with errno=EINVAL for a bad index. */
void *dynamic_array_at(dynamic_array_t *array, size_t index);
const void *dynamic_array_at_const(const dynamic_array_t *array, size_t index);

/* Generate a small type-safe facade over the raw container. The facade owns
 * no additional state; all growth and copying remains in dynamic-array.c.
 */
#define DYNAMIC_ARRAY_DEFINE(name, type)                                       \
    typedef struct name {                                                      \
        dynamic_array_t raw;                                                   \
    } name##_t;                                                                \
                                                                               \
    /* Initialize the typed array with no preallocated storage. */             \
    DYNAMIC_ARRAY_INLINE int name##_init(name##_t *array)                      \
    {                                                                          \
        return dynamic_array_init(array != NULL ? &array->raw : NULL,          \
                                  sizeof(type));                               \
    }                                                                          \
    /* Initialize typed array and preallocate initial slots. */                \
    DYNAMIC_ARRAY_INLINE int name##_init_with_capacity(name##_t *array,        \
                                                size_t initial_capacity)       \
    {                                                                          \
        return dynamic_array_init_with_capacity(                               \
            array != NULL ? &array->raw : NULL, sizeof(type),                  \
            initial_capacity);                                                 \
    }                                                                          \
    /* Destroy the typed array and release backing storage. */                 \
    DYNAMIC_ARRAY_INLINE void name##_destroy(name##_t *array)                  \
    {                                                                          \
        if (array != NULL)                                                     \
            dynamic_array_destroy(&array->raw);                                \
    }                                                                          \
    /* Reserve extra slots in the typed array. */                              \
    DYNAMIC_ARRAY_INLINE int name##_reserve(name##_t *array, size_t extra)     \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_reserve(array != NULL ? &array->raw : NULL, extra)); \
    }                                                                          \
    /* Resize typed array, zero-filling newly visible elements. */             \
    DYNAMIC_ARRAY_INLINE int name##_resize(name##_t *array, size_t count)      \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_resize(array != NULL ? &array->raw : NULL, count));  \
    }                                                                          \
    /* Append one value through a typed pointer. */                            \
    DYNAMIC_ARRAY_INLINE int name##_append_ptr(name##_t *array,                \
                                               const type *value)              \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_append(array != NULL ? &array->raw : NULL, value,    \
                                 1));                                          \
    }                                                                          \
    /* Append one typed value by value. */                                     \
    DYNAMIC_ARRAY_INLINE int name##_append_value(name##_t *array, type value)  \
    {                                                                          \
        return name##_append_ptr(array, &value);                               \
    }                                                                          \
    /* Accept either a value or a pointer to a value while retaining compile-  \
     * time checking of the element type. */                                   \
    DYNAMIC_ARRAY_INLINE int name##_append(name##_t *array, const type *value) \
    {                                                                          \
        return name##_append_ptr(array, value);                                \
    }                                                                          \
    /* Append a typed range of values. */                                      \
    DYNAMIC_ARRAY_INLINE int name##_append_n(name##_t *array,                  \
                                      const type *values,                      \
                                      size_t count)                            \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_append(array != NULL ? &array->raw : NULL, values,   \
                                 count));                                      \
    }                                                                          \
    /* Insert one typed value through a pointer form. */                       \
    DYNAMIC_ARRAY_INLINE int name##_insert_ptr(name##_t *array,                \
                                               size_t index,                   \
                                    const type *value)                         \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_insert(array != NULL ? &array->raw : NULL, index,    \
                                 value, 1));                                   \
    }                                                                          \
    /* Insert one typed value by value. */                                     \
    DYNAMIC_ARRAY_INLINE int name##_insert_value(name##_t *array,              \
                                          size_t index,                        \
                                          type value)                          \
    {                                                                          \
        return name##_insert_ptr(array, index, &value);                        \
    }                                                                          \
    /* Insert one typed value from a pointer argument. */                      \
    DYNAMIC_ARRAY_INLINE int name##_insert(name##_t *array, size_t index,      \
                                    const type *value)                         \
    {                                                                          \
        return name##_insert_ptr(array, index, value);                         \
    }                                                                          \
    /* Insert a typed range of values at index. */                             \
    DYNAMIC_ARRAY_INLINE int name##_insert_n(name##_t *array,                  \
                                      size_t index, const type *values,        \
                                      size_t count)                            \
    {                                                                          \
        int was_uninitialized = dynamic_array_typed_prepare(                   \
            array != NULL ? &array->raw : NULL, sizeof(type));                 \
        return dynamic_array_typed_result(                                     \
            array != NULL ? &array->raw : NULL, was_uninitialized,             \
            dynamic_array_insert(array != NULL ? &array->raw : NULL, index,    \
                                 values, count));                              \
    }                                                                          \
    /* Return a typed pointer to the element at index. */                      \
    DYNAMIC_ARRAY_INLINE type *name##_at(name##_t *array, size_t index)        \
    {                                                                          \
        return (type *) dynamic_array_at(array != NULL ? &array->raw : NULL,   \
                                        index);                                \
    }                                                                          \
    /* Return a typed const pointer to the element at index. */                \
    DYNAMIC_ARRAY_INLINE const type *name##_at_const(const name##_t *array,    \
                                              size_t index)                    \
    {                                                                          \
        return (const type *) dynamic_array_at_const(                          \
            array != NULL ? &array->raw : NULL, index);                        \
    }                                                                          \
    /* Access the underlying typed data pointer. */                            \
    DYNAMIC_ARRAY_INLINE type *name##_data(name##_t *array)                    \
    {                                                                          \
        return array != NULL ? (type *) array->raw.data : NULL;                \
    }                                                                          \
    /* Access the underlying typed const data pointer. */                      \
    DYNAMIC_ARRAY_INLINE const type *name##_data_const(const name##_t *array)  \
    {                                                                          \
        return array != NULL ? (const type *) array->raw.data : NULL;          \
    }                                                                          \
    /* Query current number of elements in the typed array. */                 \
    DYNAMIC_ARRAY_INLINE size_t name##_count(const name##_t *array)            \
    {                                                                          \
        return array != NULL ? array->raw.count : 0;                           \
    }                                                                          \
    /* Query current allocated capacity. */                                    \
    DYNAMIC_ARRAY_INLINE size_t name##_capacity(const name##_t *array)         \
    {                                                                          \
        return array != NULL ? array->raw.capacity : 0;                        \
    }
