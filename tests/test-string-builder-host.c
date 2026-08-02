/*
 * Native-host unit tests for string_builder_t.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "string-builder.h"

static void expect_string(const string_builder_t *builder, const char *expected)
{
    size_t length = strlen(expected);
    assert(string_builder_length(builder) == length);
    assert(builder->storage.raw.count == length);
    if (string_builder_data_const(builder) != NULL) {
        assert(strcmp(string_builder_data_const(builder), expected) == 0);
        assert(string_builder_data_const(builder)[length] == '\0');
    } else {
        assert(length == 0);
    }
}

static void test_zero_and_initial_capacity(void)
{
    string_builder_t zero = {0};
    assert(string_builder_data(&zero) == NULL);
    assert(string_builder_length(&zero) == 0);
    assert(string_builder_capacity(&zero) == 0);
    /* The public API also accepts a plain {0} value without an init call. */
    assert(string_builder_append(&zero, "zero") == 0);
    expect_string(&zero, "zero");
    string_builder_destroy(&zero);

    string_builder_t lazy = {0};
    assert(string_builder_init(&lazy, 0) == 0);
    assert(string_builder_length(&lazy) == 0);
    assert(string_builder_capacity(&lazy) == 0);
    assert(string_builder_data(&lazy) == NULL);
    assert(string_builder_reserve(&lazy, 4) == 0);
    assert(string_builder_length(&lazy) == 0);
    assert(string_builder_data(&lazy)[0] == '\0');
    assert(string_builder_append(&lazy, "lazy") == 0);
    assert(string_builder_capacity(&lazy) >= string_builder_length(&lazy) + 1);
    expect_string(&lazy, "lazy");
    string_builder_destroy(&lazy);

    string_builder_t initial = {0};
    /* initial_capacity includes the trailing NUL byte. */
    assert(string_builder_init(&initial, 32) == 0);
    assert(string_builder_capacity(&initial) >= 32);
    assert(string_builder_data(&initial) != NULL);
    assert(string_builder_length(&initial) == 0);
    expect_string(&initial, "");
    string_builder_destroy(&initial);
}

static void test_text_and_formatted_append(void)
{
    string_builder_t builder = {0};
    assert(string_builder_init(&builder, 1) == 0);

    assert(string_builder_append(&builder, "prefix") == 0);

    assert(string_builder_appendf(&builder, ":%s:%d", "formatted", 42) == 0);
    expect_string(&builder, "prefix:formatted:42");

    /* An empty C string is a no-op. */
    size_t old_length = string_builder_length(&builder);
    assert(string_builder_append(&builder, "") == 0);
    assert(string_builder_length(&builder) == old_length);
    expect_string(&builder, "prefix:formatted:42");
    string_builder_destroy(&builder);
}

static void test_c_string_semantics(void)
{
    string_builder_t builder = {0};
    assert(string_builder_append(&builder, "prefix") == 0);

    const char embedded[] = {'a', '\0', 'b', '\0'};
    errno = 0;
    assert(string_builder_append(&builder, embedded) == 0);
    assert(errno == 0);
    expect_string(&builder, "prefixa");

    errno = 0;
    assert(string_builder_appendf(&builder, "x%c y", '\0') == 0);
    assert(errno == 0);
    expect_string(&builder, "prefixax");
    string_builder_destroy(&builder);

    /* A formatted NUL also terminates the appended C-string prefix when the
     * first sizing pass has room.
     */
    string_builder_t fit = {0};
    assert(string_builder_init(&fit, 16) == 0);
    errno = 0;
    assert(string_builder_appendf(&fit, "a%c%d", '\0', 1) == 0);
    assert(errno == 0);
    expect_string(&fit, "a");
    string_builder_destroy(&fit);
}

static void test_growth_preserves_content(void)
{
    enum { COUNT = 4096 };
    char expected[COUNT];
    string_builder_t builder = {0};
    assert(string_builder_init(&builder, 1) == 0);

    for (size_t i = 0; i < COUNT; i++) {
        expected[i] = (char) ('A' + (i % 26));
        char chunk[2] = {expected[i], '\0'};
        assert(string_builder_append(&builder, chunk) == 0);
    }
    assert(string_builder_length(&builder) == COUNT);
    assert(memcmp(string_builder_data_const(&builder), expected, COUNT) == 0);
    assert(string_builder_data_const(&builder)[COUNT] == '\0');
    assert(string_builder_capacity(&builder) >= COUNT + 1);
    string_builder_destroy(&builder);
}

static void test_alias_append(void)
{
    string_builder_t builder = {0};
    assert(string_builder_init(&builder, 4) == 0);
    assert(string_builder_append(&builder, "abc") == 0);
    const char *alias = string_builder_data_const(&builder) + 1;
    assert(string_builder_append(&builder, alias) == 0);
    const char expected[] = "abcbc";
    expect_string(&builder, expected);
    string_builder_destroy(&builder);
}

static void test_overflow_preserves_content(void)
{
    string_builder_t builder = {0};
    assert(string_builder_init(&builder, 0) == 0);
    assert(string_builder_appendf(&builder, "prefix:%d", 7) == 0);

    char snapshot[32];
    assert(string_builder_length(&builder) < sizeof(snapshot));
    memcpy(snapshot, string_builder_data_const(&builder),
           string_builder_length(&builder));
    size_t old_length = string_builder_length(&builder);
    size_t old_capacity = string_builder_capacity(&builder);

    errno = 0;
    assert(string_builder_reserve(&builder, SIZE_MAX) == -1);
    assert(errno == EOVERFLOW);
    assert(string_builder_length(&builder) == old_length);
    assert(string_builder_capacity(&builder) == old_capacity);
    assert(memcmp(string_builder_data_const(&builder), snapshot, old_length) ==
           0);
    assert(string_builder_data_const(&builder)[old_length] == '\0');

    errno = 0;
    assert(string_builder_append(&builder, NULL) == -1);
    assert(errno == EILSEQ);
    assert(string_builder_length(&builder) == old_length);
    assert(string_builder_capacity(&builder) == old_capacity);
    assert(memcmp(string_builder_data_const(&builder), snapshot, old_length) ==
           0);
    assert(string_builder_data_const(&builder)[old_length] == '\0');
    string_builder_destroy(&builder);
}

int main(void)
{
    test_zero_and_initial_capacity();
    test_text_and_formatted_append();
    test_c_string_semantics();
    test_growth_preserves_content();
    test_alias_append();
    test_overflow_preserves_content();
    puts("test-string-builder-host: PASS");
    return 0;
}
