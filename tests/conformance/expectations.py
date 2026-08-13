"""Ordered-actions expectations: load, resolve, and hygiene checks.

The model is Fuchsia's: a leaf file per (suite, backend) flattens its
includes into one ordered action list and the last matching action wins.
The loader appends flaky.jsonc as a final implicit layer, so a leaf cannot
forget the quarantine and quarantine always flags a case whatever the
underlying expectation says. Validation runs at load, so a malformed
file fails every loader, never only a booted lane. reason is mandatory
on every non-pass action; bug is optional because divergences are
recorded before a tracker issue exists, but a present bug must be a
URL or #N so it resolves.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import pathlib

from conformance import jsonc

ACTION_TYPES = ("expect_pass", "expect_failure", "expect_skip",
                "expect_conf", "skip", "quarantine")
FLAKY_FILE = "flaky.jsonc"
_ACTION_KEYS = {"type", "matchers", "reason", "bug"}
_MAX_INCLUDE_DEPTH = 10


class ExpectationError(ValueError):
    """An expectations file is malformed or violates a hygiene rule."""


@dataclasses.dataclass
class Action:
    type: str
    matchers: list
    reason: str | None
    bug: str | None
    file: str


@dataclasses.dataclass
class Resolution:
    type: str
    file: str
    matcher: str
    reason: str | None
    bug: str | None
    quarantined: bool


class Expectations:
    def __init__(self, suite: str, actions: list, quarantine: list):
        self.suite = suite
        self.actions = actions
        self.quarantine = quarantine

    def resolve(self, test_id: str) -> Resolution:
        quarantined = any(
            fnmatch.fnmatchcase(test_id, m)
            for action in self.quarantine for m in action.matchers)
        for action in reversed(self.actions):
            for matcher in action.matchers:
                if fnmatch.fnmatchcase(test_id, matcher):
                    return Resolution(
                        type=action.type, file=action.file, matcher=matcher,
                        reason=action.reason, bug=action.bug,
                        quarantined=quarantined)
        raise ExpectationError(
            "no action matches %r; the enforced expect_pass \"*\" baseline "
            "makes this unreachable for a loaded leaf" % test_id)

    def check_stale(self, listing) -> list:
        """One error per matcher naming no discovered id (baseline exempt).

        flaky.jsonc spans both suites, so a matcher whose suite prefix is
        not this lane's is invisible to this listing and never stale here.
        """
        listing = list(listing)
        errors = []
        for action in self.actions + self.quarantine:
            for matcher in action.matchers:
                if matcher == "*" or \
                        not matcher.startswith(self.suite + ":"):
                    continue
                if not any(fnmatch.fnmatchcase(t, matcher) for t in listing):
                    errors.append(
                        "%s: matcher %r (%s) matches no discovered test"
                        % (action.file, matcher, action.type))
        return errors


def _check_text(path: pathlib.Path, text: str) -> None:
    if "\u2014" in text:
        line = text[:text.index("\u2014")].count("\n") + 1
        raise ExpectationError(
            "%s:%d: U+2014 is banned on every surface of this repo"
            % (path.name, line))


def _parse_action(raw: dict, path: pathlib.Path) -> Action:
    unknown = set(raw) - _ACTION_KEYS
    if unknown:
        raise ExpectationError(
            "%s: unknown action key(s): %s"
            % (path.name, ", ".join(sorted(unknown))))
    action_type = raw.get("type")
    if action_type not in ACTION_TYPES:
        raise ExpectationError(
            "%s: unknown action type %r" % (path.name, action_type))
    matchers = raw.get("matchers")
    if not isinstance(matchers, list) or \
            not all(isinstance(m, str) for m in matchers):
        raise ExpectationError(
            "%s: %s action needs a list of string matchers"
            % (path.name, action_type))
    for matcher in matchers:
        if matcher != "*" and not matcher.startswith(("gvisor:", "ltp:")):
            raise ExpectationError(
                "%s: matcher %r is not suite-namespaced"
                % (path.name, matcher))
    if matchers != sorted(matchers):
        raise ExpectationError(
            "%s: matchers of the %s action are not sorted"
            % (path.name, action_type))
    reason = raw.get("reason")
    if action_type != "expect_pass" and not reason:
        raise ExpectationError(
            "%s: %s action needs a non-empty reason"
            % (path.name, action_type))
    bug = raw.get("bug")
    if bug is not None and not (
            bug.startswith("http://") or bug.startswith("https://")
            or (bug.startswith("#") and bug[1:].isdigit())):
        raise ExpectationError(
            "%s: bug %r is neither a URL nor #N" % (path.name, bug))
    return Action(type=action_type, matchers=list(matchers), reason=reason,
                  bug=bug, file=path.name)


def _load_file(path: pathlib.Path, stack: tuple) -> list:
    if not path.is_file():
        raise ExpectationError("expectations file %s does not exist"
                               % path.name)
    resolved = path.resolve()
    if resolved in stack:
        raise ExpectationError(
            "include cycle: %s" % " -> ".join(p.name for p in stack))
    if len(stack) >= _MAX_INCLUDE_DEPTH:
        raise ExpectationError("include depth over %d at %s"
                               % (_MAX_INCLUDE_DEPTH, path.name))
    text = path.read_text(encoding="utf-8")
    _check_text(path, text)
    try:
        doc = jsonc.loads(text, filename=path.name)
    except jsonc.JsoncError as exc:
        raise ExpectationError(str(exc)) from exc
    if not isinstance(doc, dict) or set(doc) != {"actions"} or \
            not isinstance(doc["actions"], list):
        raise ExpectationError(
            '%s: top level must be {"actions": [...]}' % path.name)
    actions = []
    for raw in doc["actions"]:
        if not isinstance(raw, dict):
            raise ExpectationError("%s: action is not an object" % path.name)
        if set(raw) == {"include"}:
            actions.extend(_load_file(path.parent / raw["include"],
                                      stack + (resolved,)))
        else:
            actions.append(_parse_action(raw, path))
    return actions


def load(suite: str, backend: str, root) -> Expectations:
    root = pathlib.Path(root)
    leaf = _load_file(root / ("%s_%s.jsonc" % (suite, backend)), ())
    if not leaf or leaf[0].type != "expect_pass" or leaf[0].matchers != ["*"]:
        raise ExpectationError(
            '%s_%s.jsonc: the first effective action must be the '
            'expect_pass "*" baseline' % (suite, backend))
    for action in leaf:
        if action.type == "quarantine":
            raise ExpectationError(
                "%s: quarantine is legal only in %s"
                % (action.file, FLAKY_FILE))
    flaky = _load_file(root / FLAKY_FILE, ())
    for action in flaky:
        if action.type != "quarantine":
            raise ExpectationError(
                "%s: only quarantine actions are legal here" % FLAKY_FILE)
    return Expectations(suite=suite, actions=leaf, quarantine=flaky)
