#!/usr/bin/env python3
"""Guest workload for the elfuse-oci python image CI.

A deliberately single-threaded exercise of a dynamically-linked glibc python
guest: a small SQLite insert plus an aggregate query, a few dozen files written,
read back, and checksummed, and a JSON round-trip. On full success it prints a
single sentinel token the workflow asserts on; any failure exits non-zero with a
diagnostic. The concurrent/subprocess-heavy stress variant lives on the
oci/workload-stress branch.

Self-contained (stdlib only) so it runs under the image's bundled Python with no
network or extra packages, and is passed to the guest via `python3 -c`.
"""

import hashlib
import json
import os
import sqlite3
import sys

DB = "/tmp/elfuse-workload.db"
TREE = "/tmp/elfuse-workload-tree"
ROWS = 1000
FILES = 50


def db_ok():
    con = sqlite3.connect(DB)
    try:
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")
        for n in range(ROWS):
            con.execute("INSERT INTO t (n) VALUES (?)", (n,))
        con.commit()
        (count,) = con.execute("SELECT COUNT(*) FROM t").fetchone()
        (total,) = con.execute("SELECT SUM(n) FROM t").fetchone()
    finally:
        con.close()
    return count == ROWS and total == sum(range(ROWS))


def fs_ok():
    os.makedirs(TREE, exist_ok=True)
    for i in range(FILES):
        with open(os.path.join(TREE, "f%d" % i), "w") as fh:
            fh.write("elfuse-%d\n" % i)
            fh.flush()
            os.fsync(fh.fileno())
    got = hashlib.sha256()
    want = hashlib.sha256()
    for i in range(FILES):
        with open(os.path.join(TREE, "f%d" % i)) as fh:
            got.update(fh.read().encode())
        want.update(("elfuse-%d\n" % i).encode())
    return got.hexdigest() == want.hexdigest()


def json_ok():
    doc = {"items": [{"k": i, "v": "tok-%d" % i} for i in range(64)]}
    back = json.loads(json.dumps(doc))
    return len(back["items"]) == 64 and back["items"][63]["v"] == "tok-63"


def main():
    if not db_ok():
        print("sqlite insert/aggregate check failed", file=sys.stderr)
        sys.exit(1)
    if not fs_ok():
        print("filesystem write/read checksum mismatch", file=sys.stderr)
        sys.exit(1)
    if not json_ok():
        print("json round-trip mismatch", file=sys.stderr)
        sys.exit(1)

    print("elfuse-oci-python-workload-ok")


if __name__ == "__main__":
    main()
