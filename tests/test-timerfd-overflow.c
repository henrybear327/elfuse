/*
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>

#include "test-harness.h"

int main(void)
{
    int passes = 0, fails = 0;
    const struct {
        const char *name;
        int clockid, flags;
        int64_t seconds;
        bool interval;
    } cases[] = {
        {"relative nanosecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000000, false},
        {"relative microsecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000, false},
        {"relative maximum seconds", CLOCK_MONOTONIC, 0, INT64_MAX, false},
        {"interval nanosecond overflow", CLOCK_MONOTONIC, 0,
         INT64_MAX / 1000000000, true},
        {"absolute monotonic overflow", CLOCK_MONOTONIC, TFD_TIMER_ABSTIME,
         INT64_MAX / 1000000000, false},
        {"absolute realtime overflow", CLOCK_REALTIME, TFD_TIMER_ABSTIME,
         INT64_MAX / 1000000000, false},
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST(cases[i].name);
        int fd = timerfd_create(cases[i].clockid, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd < 0) {
            FAIL("timerfd_create");
            continue;
        }

        struct timespec large = {.tv_sec = cases[i].seconds,
                                 .tv_nsec = 999999999};
        struct itimerspec requested = {0};
        if (cases[i].interval) {
            requested.it_value.tv_sec = 60;
            requested.it_interval = large;
        } else {
            requested.it_value = large;
        }
        if (timerfd_settime(fd, cases[i].flags, &requested, NULL) < 0) {
            FAIL("timerfd_settime rejected a valid large timeout");
            close(fd);
            continue;
        }

        struct itimerspec current;
        if (timerfd_gettime(fd, &current) < 0) {
            FAIL("timerfd_gettime");
            close(fd);
            continue;
        }
        uint64_t count;
        errno = 0;
        ssize_t got = read(fd, &count, sizeof(count));
        int read_errno = errno;
        bool interval_ok =
            !cases[i].interval ||
            (current.it_interval.tv_sec == INT64_MAX / 1000000000 &&
             current.it_interval.tv_nsec == INT64_MAX % 1000000000);
        if (current.it_value.tv_sec > 30 && interval_ok && got == -1 &&
            read_errno == EAGAIN) {
            PASS();
        } else {
            FAIL("large timer expired or returned an invalid interval");
            printf("    remaining=%lld.%09ld interval=%lld.%09ld read=%ld\n",
                   (long long) current.it_value.tv_sec,
                   current.it_value.tv_nsec,
                   (long long) current.it_interval.tv_sec,
                   current.it_interval.tv_nsec, (long) got);
        }
        close(fd);
    }

    SUMMARY("test-timerfd-overflow");
    return fails > 0 ? 1 : 0;
}
