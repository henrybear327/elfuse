/*
 * inotify snapshot when the sidecar index stops being readable
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A directory watch recovers the child name kqueue omits by diffing a snapshot
 * of the directory against a baseline. Inside a casefold sysroot that snapshot
 * reverse-maps token children through the directory's index, so if the index
 * becomes unreadable between the baseline and the next snapshot, every mapped
 * child would be missing from the new listing and the diff would report each
 * one as deleted. The snapshot must fail instead, leaving the baseline in
 * place, so no event is emitted for a file that still exists.
 *
 * The failure has to begin after the baseline is taken, which needs the host:
 *   guest  creates the tree, arms the watch, prints WATCH_READY, waits for /go
 *   recipe sees WATCH_READY, chmods the index unreadable, touches a new file in
 *          the watched directory to provoke the next snapshot, creates /go
 *   guest  reads events and reports whether any child was announced as deleted
 *
 * /go is created by the recipe, so it is host-staged and keeps its real
 * spelling; a guest-created sentinel would be stored under a sidecar token and
 * the recipe could not name it. The guest needs no index access after the
 * chmod, so making the index unreadable cannot break the guest's own side of
 * this.
 *
 * Run under --sysroot on a case-insensitive volume, so the sidecar is active.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

/* No TEST()/SUMMARY output here: the verdict has to reach the host, because the
 * recipe is what perturbs the index and therefore what decides pass or fail.
 */
#include "test-util.h"

#define WATCH_DIR "/Watch.Dir"
#define GO_PATH "/go"

static const char *const kids[] = {"Ch.One", "Ch.Two", "Ch.Three"};
#define N_KIDS ((int) (sizeof(kids) / sizeof(kids[0])))

/* Poll for the recipe's host-staged sentinel under a wall-clock bound rather
 * than a fixed retry count, so a loaded machine cannot fail this spuriously.
 */
static bool wait_for_go(void)
{
    for (int waited_ms = 0; waited_ms < 20000; waited_ms += 50) {
        if (access(GO_PATH, F_OK) == 0)
            return true;
        usleep(50000);
    }
    return false;
}

int main(void)
{
    if (mkdir(WATCH_DIR, 0755) != 0 && errno != EEXIST) {
        printf("test-inotify-index-fail: mkdir %s failed (errno=%d)\n",
               WATCH_DIR, errno);
        return 1;
    }
    for (int i = 0; i < N_KIDS; i++) {
        char p[256];
        snprintf(p, sizeof(p), "%s/%s", WATCH_DIR, kids[i]);
        if (write_file(p, "k\n") != 0) {
            printf("test-inotify-index-fail: create %s failed (errno=%d)\n", p,
                   errno);
            return 1;
        }
    }

    int ifd = inotify_init1(IN_NONBLOCK);
    if (ifd < 0) {
        printf("test-inotify-index-fail: inotify_init1 failed (errno=%d)\n",
               errno);
        return 1;
    }
    /* Arming the watch captures the baseline, with all three children mapped.
     */
    int wd = inotify_add_watch(ifd, WATCH_DIR, IN_CREATE | IN_DELETE);
    if (wd < 0) {
        printf("test-inotify-index-fail: add_watch failed (errno=%d)\n", errno);
        close(ifd);
        return 1;
    }

    printf("WATCH_READY\n");
    fflush(stdout);

    if (!wait_for_go()) {
        printf("INDEX_FAIL=no-go\n");
        close(ifd);
        return 1;
    }

    /* Drain whatever the provoked snapshot produced. Any IN_DELETE naming a
     * child is the failure: those files were never removed.
     */
    bool phantom_delete = false;
    char seen[256] = {0};
    for (int round = 0; round < 20; round++) {
        char buf[4096];
        ssize_t n = read(ifd, buf, sizeof(buf));
        for (ssize_t off = 0;
             off + (ssize_t) sizeof(struct inotify_event) <= n;) {
            struct inotify_event *ev = (struct inotify_event *) (buf + off);
            if (ev->len && (ev->mask & IN_DELETE)) {
                for (int i = 0; i < N_KIDS; i++)
                    if (!strcmp(ev->name, kids[i])) {
                        phantom_delete = true;
                        snprintf(seen, sizeof(seen), "%s", ev->name);
                    }
            }
            off += (ssize_t) sizeof(*ev) + ev->len;
        }
        usleep(100000);
    }
    close(ifd);

    if (phantom_delete) {
        printf("INDEX_FAIL=deleted:%s\n", seen);
        return 1;
    }
    printf("INDEX_FAIL=ok\n");
    return 0;
}
