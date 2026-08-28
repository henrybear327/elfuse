"""Guest workload for the elfuse-oci python image CI, passed via python3 -c.

Stdlib only, so it runs under the image's bundled Python; on success it prints
one sentinel token, and any failure exits non-zero with a diagnostic.
"""

import json
import os
import re
import shutil
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
        # WAL exercises the guest FS's mmap-backed shared-memory index; if
        # the FS cannot back it, SQLite reports a different mode and the
        # checks below still validate fcntl locking under rollback journal.
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
        # timeout bounds a hung child; TimeoutExpired propagates as a prompt
        # non-zero failure naming the child instead of idling to the job's
        # timeout-minutes.
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
    # A reused plain rootfs keeps the previous run's files.
    if os.path.exists(DB):
        os.remove(DB)
    shutil.rmtree(TREE, ignore_errors=True)
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
        print("filesystem fan-out content mismatch", file=sys.stderr)
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
