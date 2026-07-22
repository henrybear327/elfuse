#!/usr/bin/env python3
"""Non-trivial guest workload for the elfuse-oci python image CI.

Mirrors the profiled python workload: JSON/regex churn, a concurrent
SQLite writer set (fcntl locking, fsync, and WAL mmap where the guest FS
supports it), a few hundred small-file writes read back and checksummed,
an os.walk over the bundled standard library, and a batch of interpreter
subprocesses. On full success it prints a single sentinel token the workflow
asserts on; any failure exits non-zero with a diagnostic.

Self-contained (stdlib only) so it runs under the image's bundled Python with
no network or extra packages, and is passed to the guest via `python3 -c`.
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
import threading

DB = "/tmp/elfuse-workload.db"
TREE = "/tmp/elfuse-workload-tree"
THREADS = 8
PER_THREAD = 2500  # 8 * 2500 = 20k inserts, matching the profiled workload
FANOUT = 20  # 20 * 20 = 400 small files, matching the profiled workload
SUBPROCS = 10


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


def db_query_ok():
    # A GROUP BY aggregate over the 20k rows. Every thread inserts exactly
    # range(PER_THREAD), so the aggregates have exact expected values;
    # counting rows alone would accept duplicated or corrupted n values.
    con = sqlite3.connect(DB, timeout=60)
    try:
        rows = con.execute(
            "SELECT tid, COUNT(*), MIN(n), MAX(n), SUM(n) FROM t"
            " GROUP BY tid ORDER BY tid"
        ).fetchall()
    finally:
        con.close()
    want_sum = PER_THREAD * (PER_THREAD - 1) // 2
    return rows == [
        (tid, PER_THREAD, 0, PER_THREAD - 1, want_sum) for tid in range(THREADS)
    ]


def json_regex_churn():
    # Serialize and reparse a structured document many times, then pull every
    # embedded token back out with a regex and confirm the round-trip is exact.
    word = re.compile(r"tok-(\d+)")
    for r in range(2000):
        doc = {"round": r, "items": [{"k": i, "v": "tok-%d" % i} for i in range(16)]}
        blob = json.dumps(doc)
        back = json.loads(blob)
        got = [int(m) for m in word.findall(blob)]
        # doc holds only str keys and int/str values, so the parsed value
        # must equal it exactly; checking one field would let dropped or
        # reordered items pass.
        if got != list(range(16)) or back != doc:
            return False
    return True


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
    # Both lists are built in the same (i, j) path order, so plain equality
    # is the whole check; hashing sorted copies would let two files with
    # swapped contents pass as an equal multiset.
    return read_back == expected


def walk_stdlib_ok():
    # os.walk the bundled standard library and count .py modules. This exercises
    # getdents/newfstatat over a deep real tree; the exact count varies by
    # patch release, so only assert it is unmistakably a full stdlib.
    root = os.path.dirname(os.__file__)
    n = 0
    for _, _, files in os.walk(root):
        n += sum(1 for f in files if f.endswith(".py"))
    return n > 200


def subprocesses_ok():
    # Fork/exec the interpreter repeatedly; each child echoes a token this
    # parent verifies, exercising execve of a dynamically-linked glibc binary.
    for i in range(SUBPROCS):
        code = "print('child-%d')" % i
        # timeout bounds a hung child the same way the sqlite calls bound
        # theirs; TimeoutExpired propagates as a prompt non-zero failure
        # naming the child instead of idling to the job's timeout-minutes.
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        if out != "child-%d" % i:
            return False
    return True


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

    if not db_query_ok():
        print("sqlite per-thread aggregate mismatch", file=sys.stderr)
        sys.exit(1)

    if not json_regex_churn():
        print("json/regex round-trip mismatch", file=sys.stderr)
        sys.exit(1)

    if not fs_fanout_ok():
        print("filesystem fan-out checksum mismatch", file=sys.stderr)
        sys.exit(1)

    if not walk_stdlib_ok():
        print("stdlib walk found too few modules", file=sys.stderr)
        sys.exit(1)

    if not subprocesses_ok():
        print("subprocess output mismatch", file=sys.stderr)
        sys.exit(1)

    print("elfuse-oci-python-workload-ok")


if __name__ == "__main__":
    main()
