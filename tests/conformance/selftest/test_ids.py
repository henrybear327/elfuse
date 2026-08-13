"""Selftests for canonical test-id handling.

Ids are the join key between discovery, expectations, and reports, so the
grammar is pinned exactly: gvisor ids carry the binary because two
binaries can define the same gtest suite name, ltp ids are bare runtest
tags, and globs are matcher syntax, never id syntax. Slugs name per-case
artifact directories, and a naive character mapping collides on real
gtest names, so assert_unique_slugs guards a whole run. Code under
test: tests/conformance/ids.py.
"""

from __future__ import annotations

import unittest

from conformance import ids


class ValidationTest(unittest.TestCase):
    def test_gvisor_simple(self):
        ids.validate("gvisor:epoll_test/EpollTest.AllWritable")

    def test_gvisor_parameterized(self):
        ids.validate(
            "gvisor:socket_test/AllTCPSockets/AllSocketPairTest.BasicSendmmsg/0")

    def test_ltp_plain(self):
        ids.validate("ltp:chmod09")

    def test_ltp_hyphen_and_underscore(self):
        ids.validate("ltp:cve-2015-7550")
        ids.validate("ltp:fcntl24_64")

    def assert_invalid(self, test_id):
        with self.assertRaises(ids.IdError):
            ids.validate(test_id)

    def test_missing_suite_prefix(self):
        self.assert_invalid("EpollTest.AllWritable")

    def test_unknown_suite(self):
        self.assert_invalid("kselftest:timers_posix_timers")

    def test_empty_name(self):
        self.assert_invalid("ltp:")
        self.assert_invalid("gvisor:")

    def test_gvisor_needs_binary_and_case(self):
        self.assert_invalid("gvisor:epoll_test")

    def test_glob_chars_are_not_id_syntax(self):
        self.assert_invalid("ltp:nanosleep*")
        self.assert_invalid("gvisor:epoll_test/EpollTest.*")

    def test_whitespace_rejected(self):
        self.assert_invalid("ltp:chmod 09")
        self.assert_invalid(" ltp:chmod09")


class ParseTest(unittest.TestCase):
    def test_parse_gvisor(self):
        self.assertEqual(
            ids.parse("gvisor:epoll_test/EpollTest.AllWritable"),
            ("gvisor", "epoll_test/EpollTest.AllWritable"))

    def test_parse_ltp(self):
        self.assertEqual(ids.parse("ltp:chmod09"), ("ltp", "chmod09"))


class SlugTest(unittest.TestCase):
    def test_deterministic(self):
        a = ids.slug("gvisor:epoll_test/EpollTest.AllWritable")
        self.assertEqual(a, ids.slug("gvisor:epoll_test/EpollTest.AllWritable"))

    def test_filesystem_safe(self):
        s = ids.slug(
            "gvisor:socket_test/AllTCPSockets/AllSocketPairTest.BasicSendmmsg/0")
        self.assertNotIn("/", s)
        self.assertNotIn(":", s)

    def test_unique_slugs_pass(self):
        ids.assert_unique_slugs(["ltp:chmod09", "ltp:chmod09_16"])

    def test_colliding_slugs_rejected(self):
        # Both ids map to gvisor_a_b_C.d under bare character replacement;
        # the digest suffix must keep them apart, and a genuine duplicate
        # id must still be reported as a collision.
        ids.assert_unique_slugs(["gvisor:a_b/C.d", "gvisor:a/b_C.d"])
        with self.assertRaises(ids.IdError):
            ids.assert_unique_slugs(["ltp:chmod09", "ltp:chmod09"])


if __name__ == "__main__":
    unittest.main()
