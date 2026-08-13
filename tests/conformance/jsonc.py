"""Reader for the JSONC subset the expectation files are written in.

The subset is JSON plus // and /* */ comments plus trailing commas, and
nothing else: full JSON5 would need a vendored parser or a dependency for
constructs (unquoted keys, single quotes) the expectation files never use.
Stripping replaces comment and trailing-comma bytes with spaces instead of
deleting them, so positions in json.loads errors name the original source
line. Anything load-bearing (reasons, bug links) lives in structured
fields, never in the stripped comment text.
"""

from __future__ import annotations

import json


class JsoncError(ValueError):
    """A file is outside the JSONC subset or not valid JSON after strip."""


def strip(text: str, *, filename: str = "<jsonc>") -> str:
    out = list(text)
    i = 0
    n = len(text)
    # Stack of indices of commas that are candidates for trailing-comma
    # removal: a comma is trailing exactly when the next non-stripped,
    # non-whitespace character is a closing bracket.
    pending_comma = -1

    def blank(start: int, end: int) -> None:
        for j in range(start, end):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        ch = text[i]
        if ch == '"':
            start = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            if i >= n:
                raise JsoncError(
                    "%s: unterminated string literal starting at offset %d"
                    % (filename, start))
            i += 1
            pending_comma = -1
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                raise JsoncError(
                    "%s: unterminated block comment starting at offset %d"
                    % (filename, i))
            blank(i, j + 2)
            i = j + 2
        elif ch == ",":
            pending_comma = i
            i += 1
        elif ch in "]}":
            if pending_comma != -1:
                out[pending_comma] = " "
            pending_comma = -1
            i += 1
        elif ch in " \t\r\n":
            i += 1
        else:
            pending_comma = -1
            i += 1
    return "".join(out)


def loads(text: str, *, filename: str = "<jsonc>"):
    stripped = strip(text, filename=filename)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise JsoncError(
            "%s: %s: line %d column %d"
            % (filename, exc.msg, exc.lineno, exc.colno)) from exc


def load_path(path, *, filename: str | None = None):
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read(), filename=filename or str(path))
