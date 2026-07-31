"""Pass-rate aggregation over one backend's observed results.

Pure functions over the digested per-test statuses (baseline.py) and
the reference map (cli.py), so the math is hermetically testable. Three
rates cover the questions the lane answers:

- pass rate: PASS over all selected tests, the headline number;
- pass rate excluding skips: PASS over tests that actually ran, since
  a TCONF-heavy selection would otherwise flatter nobody;
- conformance rate: PASS on elfuse among tests the QEMU reference
  passes, the fraction of attestable Linux behavior elfuse reproduces.

The per-group breakdown aggregates by the manifest's group field (the
test's source directory) so the worst syscall families surface first.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ltp_harness.baseline import STATUSES

# Groups with many failures list only this many ids in the markdown
# table; the JSON artifact always carries the full list.
_FAILING_IDS_SHOWN = 10


def _rate(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def compute(
    observed: Dict[str, Any],
    reference: Optional[Dict[str, Any]],
    tests_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Aggregate observed statuses into totals, rates, and groups.

    @reference is the per-test attestation map for the elfuse backend,
    None for the qemu backend (the reference does not attest itself).
    """
    totals = {status: 0 for status in STATUSES}
    groups: Dict[str, Dict[str, Any]] = {}

    for test_id, entry in sorted(observed.items()):
        status = entry["status"]
        totals[status] += 1

        test = tests_by_id.get(test_id)
        group_name = test["group"] if test else "(unknown)"
        group = groups.setdefault(
            group_name,
            {status_name: 0 for status_name in STATUSES}
            | {"total": 0, "non_attesting": 0, "failing": []},
        )
        group[status] += 1
        group["total"] += 1
        if status in ("FAIL", "BROKEN"):
            group["failing"].append(test_id)
        if reference is not None and not reference.get(test_id, {}).get(
            "attesting"
        ):
            group["non_attesting"] += 1

    total = sum(totals.values())
    ran = total - totals["SKIP"]
    for group in groups.values():
        group["pass_rate"] = _rate(group["PASS"], group["total"])

    conformance = None
    reference_summary = None
    if reference is not None:
        attesting = [
            test_id
            for test_id, entry in reference.items()
            if entry["attesting"]
        ]
        conforming = sum(
            1
            for test_id in attesting
            if observed.get(test_id, {}).get("status") == "PASS"
        )
        conformance = _rate(conforming, len(attesting))
        reference_summary = {
            "attesting": len(attesting),
            "non_pass": sum(
                1
                for entry in reference.values()
                if not entry["attesting"] and entry["status"] != "UNRECORDED"
            ),
            "unrecorded": sum(
                1
                for entry in reference.values()
                if entry["status"] == "UNRECORDED"
            ),
        }

    return {
        "totals": totals | {"total": total},
        "rates": {
            "pass": _rate(totals["PASS"], total),
            "pass_excl_skip": _rate(totals["PASS"], ran),
            "conformance": conformance,
        },
        "reference": reference_summary,
        "groups": groups,
    }


def _percent(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def worst_groups(data: Dict[str, Any], count: int = 3) -> List[str]:
    """The lowest-pass-rate groups as "name PASS/total" fragments,
    skipping groups that are fully green."""
    candidates = [
        (name, group)
        for name, group in data["groups"].items()
        if group["pass_rate"] is not None and group["PASS"] < group["total"]
    ]
    candidates.sort(key=lambda item: (item[1]["pass_rate"], item[0]))
    return [
        f"{name} {group['PASS']}/{group['total']}"
        for name, group in candidates[:count]
    ]


def summary_line(data: Dict[str, Any], backend: str, tier: str) -> str:
    totals = data["totals"]
    rates = data["rates"]
    parts = [
        f"LTP {backend} tier={tier} pass-rate: "
        f"{_percent(rates['pass'])} ({totals['PASS']}/{totals['total']}, "
        f"{_percent(rates['pass_excl_skip'])} excl SKIP)"
    ]
    if data["reference"] is not None:
        parts.append(
            f"conformance {_percent(rates['conformance'])} of "
            f"{data['reference']['attesting']} attesting"
        )
    worst = worst_groups(data)
    if worst:
        parts.append("worst: " + ", ".join(worst))
    return "; ".join(parts)


def render_markdown(data: Dict[str, Any], backend: str, tier: str) -> str:
    totals = data["totals"]
    rates = data["rates"]
    lines = [
        f"# LTP pass rate: {backend} tier={tier}",
        "",
        f"- pass rate: {_percent(rates['pass'])} "
        f"({totals['PASS']}/{totals['total']})",
        f"- excluding skips: {_percent(rates['pass_excl_skip'])}",
    ]
    if data["reference"] is not None:
        reference = data["reference"]
        lines.append(
            f"- conformance: {_percent(rates['conformance'])} of "
            f"{reference['attesting']} attesting tests "
            f"({reference['non_pass']} reference non-PASS, "
            f"{reference['unrecorded']} unrecorded)"
        )
    lines.extend(
        [
            "",
            "| group | pass/total | rate | non-attesting | failing |",
            "|---|---|---|---|---|",
        ]
    )

    ordered = sorted(
        data["groups"].items(),
        key=lambda item: (
            item[1]["pass_rate"] if item[1]["pass_rate"] is not None else 2.0,
            item[0],
        ),
    )
    for name, group in ordered:
        failing = group["failing"][:_FAILING_IDS_SHOWN]
        overflow = len(group["failing"]) - len(failing)
        failing_text = ", ".join(failing)
        if overflow:
            failing_text += f", +{overflow} more"
        lines.append(
            f"| {name} | {group['PASS']}/{group['total']} "
            f"| {_percent(group['pass_rate'])} "
            f"| {group['non_attesting']} | {failing_text} |"
        )

    return "\n".join(lines) + "\n"
