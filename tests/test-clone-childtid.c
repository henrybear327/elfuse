/* Test CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID on the fork (posix_spawn) path
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Issue #99: glibc's fork wrapper clones with CLONE_CHILD_SETTID |
 * CLONE_CHILD_CLEARTID | SIGCHLD. The child's TID must be written into the
 * ctid address so glibc's TCB caches the right value. This calls clone()
 * directly with those exact flags (no CLONE_VM/THREAD/VFORK, so elfuse takes
 * the fork helper-process path) and checks the child observes its own TID at
 * the ctid slot -- glibc-version-independent, unlike the canary symptom.
 *
 * Raw syscall throughout: glibc's own clone wrapper does not expose the ctid
 * arg, and we want to exercise elfuse's handling rather than libc's.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/sched.h>

#ifndef CLONE_CHILD_CLEARTID
#define CLONE_CHILD_CLEARTID 0x00200000
#endif
#ifndef CLONE_CHILD_SETTID
#define CLONE_CHILD_SETTID 0x01000000
#endif

static volatile int child_tid_slot;

int main(void)
{
    /* aarch64 clone(2): clone(flags, stack, parent_tid, tls, child_tid). */
    unsigned long flags = CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD;
    long rc = syscall(SYS_clone, flags, (void *) 0, (void *) 0, (void *) 0,
                      (void *) &child_tid_slot);
    if (rc < 0) {
        printf("test-clone-childtid: clone failed -- FAIL\n");
        return 1;
    }

    if (rc == 0) {
        /* Child: the kernel (here, elfuse) must have written our TID into the
         * ctid slot before we resumed.
         */
        pid_t tid = (pid_t) syscall(SYS_gettid);
        if (child_tid_slot != tid) {
            /* Cannot printf reliably from a possibly-confused child; encode the
             * result in the exit status instead.
             */
            _exit(child_tid_slot == 0 ? 2 : 3);
        }

        /* Nested clone: the child forks a grandchild with the same flags. This
         * exercises the child-side CoW shm retention (issue #99 part 2): the
         * child must be able to clone its own memory again, and the grandchild
         * must likewise see a fresh TID at its ctid slot.
         */
        static volatile int grand_tid_slot;
        long grc = syscall(SYS_clone, flags, (void *) 0, (void *) 0, (void *) 0,
                           (void *) &grand_tid_slot);
        if (grc < 0)
            _exit(4);
        if (grc == 0) {
            pid_t gtid = (pid_t) syscall(SYS_gettid);
            _exit(grand_tid_slot == gtid ? 0 : 5);
        }
        int gstatus;
        if (waitpid((pid_t) grc, &gstatus, 0) < 0)
            _exit(6);
        if (!WIFEXITED(gstatus) || WEXITSTATUS(gstatus) != 0)
            _exit(7);
        _exit(0);
    }

    int status;
    if (waitpid((pid_t) rc, &status, 0) < 0) {
        printf("test-clone-childtid: waitpid failed -- FAIL\n");
        return 1;
    }
    if (!WIFEXITED(status)) {
        printf(
            "test-clone-childtid: child did not exit cleanly (0x%x) -- FAIL\n",
            status);
        return 1;
    }
    switch (WEXITSTATUS(status)) {
    case 0:
        printf("test-clone-childtid: child saw its TID at ctid -- PASS\n");
        return 0;
    case 2:
        printf(
            "test-clone-childtid: ctid slot still 0 (SETTID ignored) -- "
            "FAIL\n");
        return 1;
    case 3:
        printf("test-clone-childtid: ctid slot holds wrong TID -- FAIL\n");
        return 1;
    default:
        printf("test-clone-childtid: unexpected child exit %d -- FAIL\n",
               WEXITSTATUS(status));
        return 1;
    }
}
