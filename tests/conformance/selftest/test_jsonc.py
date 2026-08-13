"""Selftests for the JSONC reader.

The expectation files are JSON plus // and /* */ comments plus trailing
commas, nothing more. These tests pin the subset from both sides: comment
markers and commas inside string literals survive untouched, stripping
preserves source positions so a JSON error names the original line, and
JSON5 constructs outside the subset (unquoted keys, single quotes) are
rejected rather than half-accepted. Code under test:
tests/conformance/jsonc.py.
"""

from __future__ import annotations

import unittest

from conformance import jsonc


class LoadsTest(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(jsonc.loads('{"a": [1, 2]}'), {"a": [1, 2]})

    def test_line_comment(self):
        self.assertEqual(jsonc.loads('{\n// note\n"a": 1\n}'), {"a": 1})

    def test_line_comment_after_value(self):
        self.assertEqual(jsonc.loads('{"a": 1 // note\n}'), {"a": 1})

    def test_block_comment(self):
        self.assertEqual(jsonc.loads('{"a": /* note */ 1}'), {"a": 1})

    def test_block_comment_multiline(self):
        self.assertEqual(jsonc.loads('{"a": /* one\ntwo\n*/ 1}'), {"a": 1})

    def test_line_comment_marker_inside_string(self):
        self.assertEqual(jsonc.loads('{"a": "x//y"}'), {"a": "x//y"})

    def test_block_open_marker_inside_string(self):
        self.assertEqual(jsonc.loads('{"a": "x/*y"}'), {"a": "x/*y"})

    def test_block_close_marker_inside_string(self):
        self.assertEqual(jsonc.loads('{"a": "x*/y"}'), {"a": "x*/y"})

    def test_escaped_quote_before_marker(self):
        self.assertEqual(jsonc.loads('{"a": "x\\"//y"}'), {"a": 'x"//y'})

    def test_escaped_backslash_then_quote_ends_string(self):
        self.assertEqual(jsonc.loads('{"a": "x\\\\", "b": 1 // c\n}'),
                         {"a": "x\\", "b": 1})

    def test_trailing_comma_object(self):
        self.assertEqual(jsonc.loads('{"a": 1,}'), {"a": 1})

    def test_trailing_comma_array(self):
        self.assertEqual(jsonc.loads('[1, 2,]'), [1, 2])

    def test_trailing_comma_before_comment(self):
        self.assertEqual(jsonc.loads('[1, // last\n]'), [1])

    def test_comma_inside_string_untouched(self):
        self.assertEqual(jsonc.loads('{"a": "1,]"}'), {"a": "1,]"})

    def test_nested_with_comments_everywhere(self):
        text = """
        // header
        {
          "actions": [ /* inline */
            { "type": "expect_pass", "matchers": ["*",], }, // row
          ],
        }
        """
        self.assertEqual(
            jsonc.loads(text),
            {"actions": [{"type": "expect_pass", "matchers": ["*"]}]})


class RejectionTest(unittest.TestCase):
    def assert_error(self, text, fragment):
        with self.assertRaises(jsonc.JsoncError) as ctx:
            jsonc.loads(text, filename="f.jsonc")
        self.assertIn("f.jsonc", str(ctx.exception))
        self.assertIn(fragment, str(ctx.exception))

    def test_unterminated_block_comment(self):
        self.assert_error('{"a": 1} /* open', "unterminated")

    def test_unterminated_string(self):
        self.assert_error('{"a: 1}', "unterminated")

    def test_unquoted_keys_rejected(self):
        self.assert_error('{a: 1}', "line 1")

    def test_single_quotes_rejected(self):
        self.assert_error("{'a': 1}", "line 1")

    def test_empty_input_rejected(self):
        self.assert_error('', "line 1")

    def test_comment_only_input_rejected(self):
        self.assert_error('// nothing here\n', "line")

    def test_error_reports_original_line(self):
        # The syntax error sits on line 4 of the source; stripping the
        # comments above it must not shift the reported position.
        self.assert_error('{\n// one\n/* two */\n"a" 1\n}', "line 4")


if __name__ == "__main__":
    unittest.main()
