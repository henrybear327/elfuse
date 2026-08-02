/*
 * Native-host unit tests for the generic dynamic array.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dynamic-array.h"

typedef struct odd {
    unsigned char tag;
    uint32_t value;
} odd_t;

DYNAMIC_ARRAY_DEFINE(int_array, int)
DYNAMIC_ARRAY_DEFINE(odd_array, odd_t)

static void test_zero_and_init(void)
{
    int_array_t values = {0};
    int value = 7;
    assert(int_array_count(&values) == 0);
    assert(int_array_capacity(&values) == 0);
    assert(int_array_append(&values, &value) == 0);
    assert(int_array_count(&values) == 1);
    assert(*int_array_at(&values, 0) == 7);
    int_array_destroy(&values);
    assert(int_array_data(&values) == NULL);
    assert(int_array_count(&values) == 0);
    assert(int_array_capacity(&values) == 0);

    assert(int_array_init_with_capacity(&values, 4) == 0);
    assert(int_array_capacity(&values) >= 4);
    int_array_destroy(&values);
}

static void test_growth_insert_and_stride(void)
{
    odd_array_t values = {0};
    odd_t first = {1, 11};
    odd_t second = {2, 22};
    odd_t middle = {3, 33};
    assert(odd_array_append(&values, &first) == 0);
    assert(odd_array_append(&values, &second) == 0);
    assert(odd_array_insert(&values, 1, &middle) == 0);
    assert(odd_array_count(&values) == 3);
    assert(odd_array_at(&values, 1)->tag == 3);
    assert(odd_array_at(&values, 2)->value == 22);
    assert(odd_array_capacity(&values) >= 3);
    odd_array_destroy(&values);
}

static void test_alias_and_resize(void)
{
    int_array_t values = {0};
    int initial[] = {1, 2, 3, 4};
    assert(int_array_init_with_capacity(&values, 4) == 0);
    assert(int_array_append_n(&values, initial, 4) == 0);
    int *old_data = int_array_data(&values);
    int *alias = int_array_at(&values, 1);
    assert(int_array_append(&values, alias) == 0);
    assert(int_array_data(&values) != old_data ||
           int_array_capacity(&values) > 4);
    assert(int_array_count(&values) == 5);
    assert(*int_array_at(&values, 4) == 2);
    assert(int_array_resize(&values, 8) == 0);
    for (size_t i = 5; i < 8; i++)
        assert(*int_array_at(&values, i) == 0);
    assert(int_array_resize(&values, 2) == 0);
    int_array_destroy(&values);
}

static void test_invalid_and_overflow(void)
{
    int_array_t values = {0};
    int value = 9;
    errno = 0;
    assert(int_array_insert(&values, 1, &value) == -1);
    assert(errno == EINVAL);
    errno = 0;
    assert(int_array_append_n(&values, &value, SIZE_MAX) == -1);
    assert(errno == EOVERFLOW);

    dynamic_array_t raw = {0};
    errno = 0;
    assert(dynamic_array_init(&raw, 0) == -1);
    assert(errno == EINVAL);
    assert(dynamic_array_init(&raw, sizeof(uint64_t)) == 0);
    errno = 0;
    assert(dynamic_array_reserve(&raw, SIZE_MAX) == -1);
    assert(errno == EOVERFLOW);
    assert(raw.data == NULL && raw.count == 0 && raw.capacity == 0);
    dynamic_array_destroy(&raw);

    /* A malformed metadata state must not let failed byte-size calculations
     * feed uninitialized offsets into memory operations. */
    dynamic_array_t resize_overflow = {
        .data = NULL,
        .count = 0,
        .capacity = 2,
        .element_size = SIZE_MAX,
    };
    errno = 0;
    assert(dynamic_array_resize(&resize_overflow, 2) == -1);
    assert(errno == EOVERFLOW);
    assert(resize_overflow.count == 0);

    dynamic_array_t append_overflow = {
        .data = NULL,
        .count = SIZE_MAX / 2 + 1,
        .capacity = SIZE_MAX,
        .element_size = 2,
    };
    errno = 0;
    assert(dynamic_array_append(&append_overflow, &value) == -1);
    assert(errno == EOVERFLOW);
    assert(append_overflow.count == SIZE_MAX / 2 + 1);
}

int main(void)
{
    test_zero_and_init();
    test_growth_insert_and_stride();
    test_alias_and_resize();
    test_invalid_and_overflow();
    puts("test-dynamic-array-host: PASS");
    return 0;
}
