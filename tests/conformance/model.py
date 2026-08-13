"""Result model: statuses, verdicts, and the per-case record.

Status is what a backend observed for one case; Verdict is that status
judged against the expectation. The sets are closed on purpose: every
consumer (ratchet, report, JUnit) branches over them exhaustively, and an
unknown value must fail loudly at the boundary instead of flowing through
as a string. CaseResult keeps every attempt, so first-attempt and final
outcomes of a quarantined test are both in the record.
"""

from __future__ import annotations

import dataclasses
import enum


class Status(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    CONF = "CONF"
    WARN = "WARN"
    BROK = "BROK"
    TIMEOUT = "TIMEOUT"
    CRASH = "CRASH"
    INCONSISTENT = "INCONSISTENT"
    ERROR = "ERROR"


class Verdict(str, enum.Enum):
    AS_EXPECTED = "as_expected"
    UNEXPECTED_FAILURE = "unexpected_failure"
    UNEXPECTED_PASS = "unexpected_pass"
    FLAKED = "flaked"
    FILTERED = "filtered"
    ERROR = "error"

    @property
    def is_red(self) -> bool:
        return self in (Verdict.UNEXPECTED_FAILURE, Verdict.UNEXPECTED_PASS,
                        Verdict.ERROR)


EXECUTIONS = ("normal", "timeout", "signal", "transport")


@dataclasses.dataclass
class Attempt:
    status: Status
    exit_code: int
    wall_us: int
    execution: str
    detail: str

    def __post_init__(self):
        self.status = Status(self.status)
        if self.execution not in EXECUTIONS:
            raise ValueError("unknown execution kind: %r" % self.execution)

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "wall_us": self.wall_us,
            "execution": self.execution,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Attempt":
        return cls(status=Status(data["status"]),
                   exit_code=data["exit_code"],
                   wall_us=data["wall_us"],
                   execution=data["execution"],
                   detail=data["detail"])


@dataclasses.dataclass
class CaseResult:
    id: str
    suite: str
    backend: str
    status: Status
    verdict: Verdict
    expectation: dict
    attempts: list
    detail: str
    artifacts: str

    def __post_init__(self):
        self.status = Status(self.status)
        self.verdict = Verdict(self.verdict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "suite": self.suite,
            "backend": self.backend,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "expectation": self.expectation,
            "attempts": [a.to_dict() for a in self.attempts],
            "detail": self.detail,
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CaseResult":
        return cls(id=data["id"],
                   suite=data["suite"],
                   backend=data["backend"],
                   status=Status(data["status"]),
                   verdict=Verdict(data["verdict"]),
                   expectation=data["expectation"],
                   attempts=[Attempt.from_dict(a) for a in data["attempts"]],
                   detail=data["detail"],
                   artifacts=data["artifacts"])
