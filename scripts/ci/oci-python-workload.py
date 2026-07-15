#!/usr/bin/env python3
"""Non-trivial guest workload for the elfuse-oci OCI lifecycle CI.

Exercises more of a real dynamically-linked glibc guest than a one-line print:
concurrent SQLite writers (fcntl locking, fsync, and, when the guest FS
supports it, WAL mmap), plus a filesystem fan-out whose written content is
read back and checksummed. On full success it prints a single sentinel token
the workflow asserts on; any failure exits non-zero with a diagnostic.

Self-contained (stdlib only) so it runs under the image's bundled Python with
no network or extra packages, and is passed to the guest via `python3 -c`.
"""

import hashlib
import os
import sqlite3
import sys
import threading

DB = "/tmp/elfuse-workload.db"
TREE = "/tmp/elfuse-workload-tree"
THREADS = 8
PER_THREAD = 1000
FANOUT = 8


def setup_db():
    con = sqlite3.connect(DB)
    try:
        # WAL exercises the guest FS's shared-memory index (mmap) and is the
        # more demanding path; if the FS cannot back it, SQLite reports a
        # different mode and the concurrent-writer count check below still
        # validates fcntl locking and durable commits under rollback journal.
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "tid INTEGER NOT NULL, n INTEGER NOT NULL)"
        )
        con.commit()
    finally:
        con.close()


def worker(tid):
    con = sqlite3.connect(DB, timeout=60)
    try:
        con.execute("PRAGMA busy_timeout=60000")
        for n in range(PER_THREAD):
            con.execute("INSERT INTO t (tid, n) VALUES (?, ?)", (tid, n))
        con.commit()
    finally:
        con.close()


def db_count():
    con = sqlite3.connect(DB, timeout=60)
    try:
        (count,) = con.execute("SELECT COUNT(*) FROM t").fetchone()
        return count
    finally:
        con.close()


def content(i, j):
    return "elfuse-workload-%d-%d\n" % (i, j)


def fs_fanout_ok():
    for i in range(FANOUT):
        for j in range(FANOUT):
            d = os.path.join(TREE, str(i), str(j))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "f"), "w") as fh:
                fh.write(content(i, j))
                fh.flush()
                os.fsync(fh.fileno())
    read_back = []
    for i in range(FANOUT):
        for j in range(FANOUT):
            with open(os.path.join(TREE, str(i), str(j), "f")) as fh:
                read_back.append(fh.read())
    expected = [content(i, j) for i in range(FANOUT) for j in range(FANOUT)]
    got = hashlib.sha256()
    for p in sorted(read_back):
        got.update(p.encode())
    want = hashlib.sha256()
    for p in sorted(expected):
        want.update(p.encode())
    return got.hexdigest() == want.hexdigest()


def main():
    setup_db()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    count = db_count()
    if count != THREADS * PER_THREAD:
        print(
            "sqlite row count %d != %d (concurrent writers lost rows)"
            % (count, THREADS * PER_THREAD),
            file=sys.stderr,
        )
        sys.exit(1)

    if not fs_fanout_ok():
        print("filesystem fan-out checksum mismatch", file=sys.stderr)
        sys.exit(1)

    print("elfuse-oci-python-workload-ok")


if __name__ == "__main__":
    main()
