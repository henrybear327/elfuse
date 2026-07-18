#!/usr/bin/env python3
"""Focused self-tests for gVisor conformance result handling."""

# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

MODULE_PATH = Path(__file__).parent / "lib" / "gvisor_conformance.py"
SPEC = importlib.util.spec_from_file_location("gvisor_conformance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gc = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gc
SPEC.loader.exec_module(gc)


TEST = "ReadvTest.BadIovecsPointer_File"
PARAMETERIZED = "SharedPrivate/PrivateAndSharedFutexTest.Wait_WrongVal/0"


def testcase_xml(entries: str) -> str:
    return f"<testsuites><testsuite>{entries}</testsuite></testsuites>"


def entry(
    classname: str = "ReadvTest",
    name: str = "BadIovecsPointer_File",
    body: str = "",
    status: str = "run",
    result: str = "completed",
    time: str = "0.25",
) -> str:
    return (
        f'<testcase classname="{classname}" name="{name}" status="{status}" '
        f'result="{result}" time="{time}">{body}</testcase>'
    )


class ListingTests(unittest.TestCase):
    def test_list_includes_parameterized_names(self) -> None:
        listing = (
            "ReadvTest.\n"
            "  BadIovecsPointer_File\n"
            "SharedPrivate/PrivateAndSharedFutexTest.\n"
            "  Wait_WrongVal/0  # GetParam() = false\n"
        )
        self.assertEqual(gc.parse_gtest_list(listing), [TEST, PARAMETERIZED])

    def test_list_rejects_orphans_and_duplicates(self) -> None:
        for listing, message in (
            ("  Orphan\n", "before a suite"),
            ("Suite.\n  Case\n  Case\n", "duplicate"),
        ):
            with self.subTest(listing=listing):
                with self.assertRaisesRegex(gc.ValidationError, message):
                    gc.parse_gtest_list(listing)

    def test_disabled_detection(self) -> None:
        self.assertTrue(gc.is_disabled("DISABLED_Suite.Case"))
        self.assertTrue(gc.is_disabled("Suite.DISABLED_Case"))
        self.assertTrue(gc.is_disabled("Prefix/DISABLED_Suite.Case/0"))
        self.assertFalse(gc.is_disabled(TEST))
        self.assertFalse(gc.is_disabled(PARAMETERIZED))


def write_temp(case: unittest.TestCase, contents: str) -> Path:
    handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
    case.addCleanup(Path(handle.name).unlink, missing_ok=True)
    with handle:
        handle.write(contents)
    return Path(handle.name)


class SuiteXmlTests(unittest.TestCase):
    def test_multi_case_suite(self) -> None:
        path = write_temp(
            self,
            testcase_xml(
                entry()
                + entry(
                    name="OffsetIncremented",
                    body='<failure message="offset"/>',
                    time="1.5",
                )
                + entry(
                    name="Skipped",
                    body='<skipped message="unsupported"/>',
                    result="skipped",
                    time="0",
                )
            )
        )
        cases = gc.parse_gtest_suite_xml(path)
        self.assertEqual(
            [(case.test, case.state, case.duration_ms) for case in cases],
            [
                (TEST, "PASS", 250),
                ("ReadvTest.OffsetIncremented", "FAIL", 1500),
                ("ReadvTest.Skipped", "SKIP", 0),
            ],
        )
        self.assertEqual(cases[1].detail, "offset")
        self.assertEqual(cases[2].detail, "unsupported")

    def test_rejects_duplicates_and_unexecuted(self) -> None:
        with self.assertRaisesRegex(gc.ValidationError, "duplicate"):
            gc.parse_gtest_suite_xml(write_temp(self, testcase_xml(entry() + entry())))
        with self.assertRaisesRegex(gc.ValidationError, "not run"):
            gc.parse_gtest_suite_xml(
                write_temp(self, testcase_xml(entry(status="notrun", result="suppressed")))
            )

    def test_ignores_disabled_notrun(self) -> None:
        path = write_temp(
            self,
            testcase_xml(
                entry()
                + entry(name="DISABLED_Case", status="notrun", result="suppressed")
            ),
        )
        self.assertEqual([case.test for case in gc.parse_gtest_suite_xml(path)], [TEST])

    def test_rejects_skipped_and_failed(self) -> None:
        body = '<skipped message="s"/><failure message="f"/>'
        with self.assertRaisesRegex(gc.ValidationError, "both skipped and failed"):
            gc.parse_gtest_suite_xml(
                write_temp(self, testcase_xml(entry(body=body, result="skipped")))
            )


class ClassificationTests(unittest.TestCase):
    def test_single_case_classification(self) -> None:
        passing = write_temp(self, testcase_xml(entry()))
        failing = write_temp(self, testcase_xml(entry(body='<failure message="bad"/>')))
        self.assertEqual(gc.classify_gtest_case(passing, TEST, 0).final, "PASS")
        self.assertEqual(gc.classify_gtest_case(failing, TEST, 1).final, "FAIL")
        self.assertEqual(gc.classify_gtest_case(passing, TEST, 1).final, "BROKEN")
        self.assertEqual(gc.classify_gtest_case(passing, "S.Other", 0).final, "BROKEN")
        self.assertEqual(gc.classify_gtest_case(Path("missing.xml"), TEST, 0).final, "BROKEN")
        self.assertEqual(
            gc.classify_gtest_case(Path("missing.xml"), TEST, 124, "timeout").final,
            "TIMEOUT",
        )
        self.assertEqual(
            gc.classify_gtest_case(Path("missing.xml"), TEST, 192, "signal").final,
            "SIGNAL",
        )
        self.assertEqual(gc.classify_gtest_case(passing, TEST, 143).final, "SIGNAL")

    def test_apply_expectation(self) -> None:
        passing = gc.Classification("PASS", "PASS", False, "")
        failing = gc.Classification("FAIL", "FAIL", True, "assertion")
        skipping = gc.Classification("SKIP", "SKIP", False, "unsupported")
        broken = gc.Classification("BROKEN", "BROKEN", True, "missing XML")

        self.assertEqual(gc.apply_expectation(passing, "PASS").fatal, False)
        mismatch = gc.apply_expectation(failing, "PASS")
        self.assertEqual((mismatch.final, mismatch.fatal), ("FAIL", True))
        self.assertIn("assertion", mismatch.detail)
        xfail = gc.apply_expectation(failing, "XFAIL")
        self.assertEqual((xfail.final, xfail.fatal), ("XFAIL", False))
        xpass = gc.apply_expectation(passing, "XFAIL")
        self.assertEqual((xpass.final, xpass.fatal), ("XPASS", True))
        skipped_xfail = gc.apply_expectation(skipping, "XFAIL")
        self.assertEqual((skipped_xfail.final, skipped_xfail.fatal), ("SKIP", True))
        self.assertEqual(gc.apply_expectation(skipping, "SKIP").fatal, False)
        self.assertEqual(gc.apply_expectation(passing, "SKIP").fatal, True)
        self.assertEqual(gc.apply_expectation(broken, "XFAIL").final, "BROKEN")


class ExpectationManifestTests(unittest.TestCase):
    def write_manifest(self, root: Path, rows: list[str]) -> Path:
        path = root / "expectations.tsv"
        path.write_text("test\tbackend\texpected\treason\tissue\n" + "\n".join(rows) + "\n")
        return path

    def valid_rows(self) -> list[str]:
        return [f"{TEST}\t{backend}\tPASS\t-\t-" for backend in gc.BACKENDS]

    def test_valid_manifest_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            entries = gc.load_expectations(
                self.write_manifest(Path(tmp), self.valid_rows()), [TEST]
            )
            self.assertEqual(entries[(TEST, "qemu-aarch64")].expected, "PASS")

    def test_manifest_rejects_invalid_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            variants = [
                self.valid_rows() + [self.valid_rows()[0]],
                [f"ReadvTest.*\t{backend}\tPASS\t-\t-" for backend in gc.BACKENDS],
                [f"Unknown.Case\t{backend}\tPASS\t-\t-" for backend in gc.BACKENDS],
                self.valid_rows()[:1],
                [f"{TEST}\t{backend}\tXFAIL\treason\t-" for backend in gc.BACKENDS],
                [f"{TEST}\t{backend}\tSKIP\t-\t-" for backend in gc.BACKENDS],
                [f"{TEST}\t{backend}\tEXCLUDE\t-\t-" for backend in gc.BACKENDS],
            ]
            for index, rows in enumerate(variants):
                with self.subTest(index=index):
                    with self.assertRaises(gc.ValidationError):
                        gc.load_expectations(self.write_manifest(root, rows), [TEST])


class PlanAndSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_plan_bootstrap_and_manifest(self) -> None:
        listing = self.write("all.list", f"{TEST}\nReadvTest.DISABLED_Gone\n")
        plan = self.root / "plan.tsv"
        self.assertEqual(
            gc.main(
                [
                    "plan",
                    "--input",
                    str(listing),
                    "--backend",
                    "qemu-aarch64",
                    "--bootstrap",
                    "--output",
                    str(plan),
                ]
            ),
            0,
        )
        self.assertEqual(plan.read_text(), f"{TEST}\tPASS\t-\t-\n")
        manifest = self.write(
            "expectations.tsv",
            "test\tbackend\texpected\treason\tissue\n"
            + "".join(f"{TEST}\t{backend}\tPASS\t-\t-\n" for backend in gc.BACKENDS),
        )
        self.assertEqual(
            gc.main(
                [
                    "plan",
                    "--input",
                    str(listing),
                    "--backend",
                    "qemu-aarch64",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(plan),
                ]
            ),
            0,
        )
        self.assertEqual(plan.read_text(), f"{TEST}\tPASS\t-\t-\n")

    def test_plan_rejects_slug_collisions(self) -> None:
        listing = self.write("all.list", "Suite/Sub.Case\nSuite_Sub.Case\n")
        args = gc.build_parser().parse_args(
            [
                "plan",
                "--input",
                str(listing),
                "--backend",
                "qemu-aarch64",
                "--bootstrap",
                "--output",
                str(self.root / "plan.tsv"),
            ]
        )
        with self.assertRaisesRegex(gc.ValidationError, "slug collision"):
            gc.command_plan(args)

    def test_plan_drops_excluded_tests(self) -> None:
        second = "ReadvTest.OffsetIncremented"
        listing = self.write("all.list", f"{TEST}\n{second}\n")
        manifest = self.write(
            "expectations.tsv",
            "test\tbackend\texpected\treason\tissue\n"
            + "".join(f"{TEST}\t{backend}\tPASS\t-\t-\n" for backend in gc.BACKENDS)
            + "".join(
                f"{second}\t{backend}\tEXCLUDE\tcrashes the reference kernel\t-\n"
                for backend in gc.BACKENDS
            ),
        )
        plan = self.root / "plan.tsv"
        self.assertEqual(
            gc.main(
                [
                    "plan",
                    "--input",
                    str(listing),
                    "--backend",
                    "qemu-aarch64",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(plan),
                ]
            ),
            0,
        )
        self.assertEqual(plan.read_text(), f"{TEST}\tPASS\t-\t-\n")

    def run_record_suite(self, xml_body: str, exit_code: int, execution: str) -> Path:
        tests = self.write("tests.list", f"{TEST}\nReadvTest.OffsetIncremented\n")
        plan = self.write(
            "plan.tsv",
            f"{TEST}\tPASS\t-\t-\nReadvTest.OffsetIncremented\tPASS\t-\t-\n",
        )
        xml = self.root / "result.xml"
        if xml_body:
            xml.write_text(xml_body, encoding="utf-8")
        stdout = self.write("stdout.log", "suite stdout\n")
        stderr = self.write("stderr.log", "")
        log = self.write("complete.log", "suite log\n")
        cases = self.root / "cases"
        code = gc.main(
            [
                "record-suite",
                "--xml",
                str(xml),
                "--tests",
                str(tests),
                "--plan",
                str(plan),
                "--backend",
                "qemu-aarch64",
                "--exit-code",
                str(exit_code),
                "--execution",
                execution,
                "--stdout",
                str(stdout),
                "--stderr",
                str(stderr),
                "--log",
                str(log),
                "--output-dir",
                str(cases),
                "--rerun-list",
                str(self.root / "rerun.tsv"),
                "--summary",
                str(self.root / "summary.tsv"),
            ]
        )
        self.assertEqual(code, 0)
        return cases

    def test_record_suite_marks_missing_tests_for_rerun(self) -> None:
        cases = self.run_record_suite(testcase_xml(entry()), 0, "normal")
        passing = json.loads((cases / gc.test_slug(TEST) / "result.json").read_text())
        self.assertEqual((passing["final"], passing["fatal"]), ("PASS", False))
        self.assertEqual(passing["duration_ms"], 250)
        missing = json.loads(
            (cases / gc.test_slug("ReadvTest.OffsetIncremented") / "result.json").read_text()
        )
        self.assertEqual((missing["final"], missing["fatal"]), ("BROKEN", True))
        self.assertEqual(
            (self.root / "rerun.tsv").read_text(),
            "ReadvTest.OffsetIncremented\tReadvTest.OffsetIncremented\tPASS\t-\t-\n",
        )

    def test_record_suite_abnormal_reruns_everything(self) -> None:
        self.run_record_suite("", 137, "timeout")
        rerun = (self.root / "rerun.tsv").read_text().splitlines()
        self.assertEqual(len(rerun), 2)

    def test_record_suite_exit_mismatch_reruns_everything(self) -> None:
        self.run_record_suite(
            testcase_xml(entry() + entry(name="OffsetIncremented")), 1, "normal"
        )
        rerun = (self.root / "rerun.tsv").read_text().splitlines()
        self.assertEqual(len(rerun), 2)


class ExpectationsInitTests(unittest.TestCase):
    def test_draft_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for test, actual, detail in (
                (TEST, "PASS", ""),
                ("ReadvTest.OffsetIncremented", "FAIL", "offset mismatch"),
                ("ReadvTest.Skipped", "SKIP", "unsupported"),
                ("ReadvTest.Crashes", "SIGNAL", "terminated by signal 11"),
            ):
                case_dir = root / "qemu-aarch64" / "cases" / gc.test_slug(test)
                case_dir.mkdir(parents=True)
                (case_dir / "result.json").write_text(
                    json.dumps(
                        {
                            "test": test,
                            "backend": "qemu-aarch64",
                            "actual": actual,
                            "final": actual,
                            "detail": detail,
                        }
                    )
                )
            draft = root / "draft.tsv"
            self.assertEqual(
                gc.main(
                    ["expectations-init", "--root", str(root), "--output", str(draft)]
                ),
                0,
            )
            text = draft.read_text()
            self.assertIn(f"{TEST}\telfuse-aarch64\tPASS\t-\t-", text)
            self.assertIn("REVIEW", text)
            entries = gc.load_expectations(
                draft,
                [TEST, "ReadvTest.OffsetIncremented", "ReadvTest.Skipped",
                 "ReadvTest.Crashes"],
            )
            self.assertEqual(
                entries[("ReadvTest.OffsetIncremented", "elfuse-aarch64")].expected,
                "XFAIL",
            )
            self.assertEqual(entries[("ReadvTest.Skipped", "qemu-aarch64")].expected, "SKIP")
            self.assertEqual(entries[("ReadvTest.Crashes", "qemu-aarch64")].expected, "EXCLUDE")


class ArtifactTests(unittest.TestCase):
    def test_json_escaping_and_junit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            stdout.write_text('quote " and newline\n')
            stderr.write_text("diagnostic\n")
            result = {
                "test": TEST,
                "backend": "elfuse-aarch64",
                "final": "PASS",
                "fatal": False,
                "detail": 'quote " and newline\nnext',
                "stdout": str(stdout),
                "stderr": str(stderr),
                "duration_ms": 1,
            }
            aggregate = gc.aggregate_results([result])
            json_path = root / "results.json"
            junit_path = root / "results.xml"
            gc.write_json(json_path, aggregate)
            gc.write_junit(junit_path, [result])
            self.assertEqual(
                json.loads(json_path.read_text())["results"][0]["detail"], result["detail"]
            )
            self.assertEqual(ET.parse(junit_path).getroot().attrib["tests"], "1")

    def test_result_discovery_ignores_aggregate_results_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_dir = root / "backend" / "cases" / "one"
            case_dir.mkdir(parents=True)
            (case_dir / "result.json").write_text(
                json.dumps({"test": TEST, "final": "PASS"})
            )
            (root / "backend" / "results.json").write_text(
                json.dumps({"results": [{"test": TEST, "final": "PASS"}]})
            )
            self.assertEqual(len(gc.load_results(root)), 1)

    def test_aggregate_rejects_unknown_state(self) -> None:
        with self.assertRaisesRegex(gc.ValidationError, "unknown final result state"):
            gc.aggregate_results([{"test": TEST, "final": "MAYBE"}])

    def test_aggregate_empty_result_set_is_fatal(self) -> None:
        aggregate = gc.aggregate_results([])
        self.assertEqual((aggregate["total"], aggregate["fatal"]), (0, 1))

    def test_junit_fatal_skip_counts_as_failure_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            junit = Path(tmp) / "results.xml"
            gc.write_junit(
                junit,
                [
                    {
                        "test": TEST,
                        "backend": "elfuse-aarch64",
                        "final": "SKIP",
                        "fatal": True,
                        "detail": "expected XFAIL, got SKIP",
                    }
                ],
            )
            suite = ET.parse(junit).getroot()
            self.assertEqual(
                (suite.attrib["tests"], suite.attrib["failures"], suite.attrib["skipped"]),
                ("1", "1", "0"),
            )
            self.assertIsNotNone(suite.find(".//failure"))
            self.assertIsNone(suite.find(".//skipped"))

    def test_junit_embeds_logs_only_for_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = root / "stdout.log"
            stdout.write_text("shared suite log\n")
            passing = {
                "test": TEST,
                "backend": "elfuse-aarch64",
                "final": "PASS",
                "fatal": False,
                "stdout": str(stdout),
            }
            junit = root / "results.xml"
            gc.write_junit(junit, [passing])
            self.assertIsNone(ET.parse(junit).getroot().find(".//system-out"))

    def test_junit_preserves_malformed_logs_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            stdout.write_bytes(b"bad utf-8: \xff\ncontrol: \x01\n")
            stderr.write_bytes(b"ok\n")
            result = {
                "test": TEST,
                "backend": "elfuse-aarch64",
                "final": "BROKEN",
                "fatal": True,
                "stdout": str(stdout),
                "stderr": str(stderr),
            }
            junit = root / "results.xml"
            gc.write_junit(junit, [result])
            parsed = ET.parse(junit).getroot()
            output = parsed.findtext(".//system-out")
            self.assertIsNotNone(output)
            self.assertIn("�", output)


if __name__ == "__main__":
    unittest.main()
