"""Selftests for the pure-Python ELF payload validation.

The payload must be fully static AArch64 ELFs: ELF64 little-endian,
EM_AARCH64, at least one PT_LOAD, no PT_INTERP, and no DT_NEEDED in
PT_DYNAMIC (static-pie carries PT_DYNAMIC without DT_NEEDED, so the
dynamic segment alone is not a defect). The fixtures are hand-built
headers, one per rejection reason, so each check is exercised in
isolation. Code under test: tests/conformance/payload/elfcheck.py.
"""

from __future__ import annotations

import pathlib
import struct
import tempfile
import unittest

from conformance.payload import elfcheck

EM_AARCH64 = 183
EM_X86_64 = 62
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED = 0, 1
EHSIZE, PHENTSIZE = 64, 56


def build_elf(machine=EM_AARCH64, ei_class=2, ei_data=1, phdrs=(),
              dynamic=()):
    """Assemble headers, program headers, then any dynamic entries."""
    phoff = EHSIZE
    dyn_off = phoff + PHENTSIZE * len(phdrs)
    dyn_blob = b"".join(struct.pack("<qQ", tag, val) for tag, val in dynamic)
    header = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF", ei_class, ei_data, 1, 0, 0,
        2, machine, 1,
        0x400000, phoff, 0,
        0, EHSIZE, PHENTSIZE, len(phdrs), 0, 0, 0)
    body = b""
    for p_type in phdrs:
        offset = dyn_off if p_type == PT_DYNAMIC else 0
        filesz = len(dyn_blob) if p_type == PT_DYNAMIC else 0
        body += struct.pack("<IIQQQQQQ", p_type, 5, offset, 0, 0,
                            filesz, filesz, 0x1000)
    return header + body + dyn_blob


class ElfCheckTest(unittest.TestCase):
    def check(self, blob):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
        path = pathlib.Path(fh.name)
        self.addCleanup(path.unlink)
        elfcheck.validate_static_aarch64(path)

    def assert_rejected(self, blob, fragment):
        with self.assertRaises(elfcheck.ElfCheckError) as ctx:
            self.check(blob)
        self.assertIn(fragment, str(ctx.exception))

    def test_static_binary_accepted(self):
        self.check(build_elf(phdrs=(PT_LOAD,)))

    def test_static_pie_accepted(self):
        # PT_DYNAMIC without DT_NEEDED is static-pie, not a dynamic link.
        self.check(build_elf(phdrs=(PT_LOAD, PT_DYNAMIC),
                             dynamic=((DT_NULL, 0),)))

    def test_not_elf(self):
        self.assert_rejected(b"#!/bin/sh\n", "ELF magic")

    def test_truncated_header(self):
        self.assert_rejected(build_elf(phdrs=(PT_LOAD,))[:40], "truncated")

    def test_elf32_rejected(self):
        self.assert_rejected(build_elf(ei_class=1, phdrs=(PT_LOAD,)), "ELF64")

    def test_big_endian_rejected(self):
        self.assert_rejected(build_elf(ei_data=2, phdrs=(PT_LOAD,)),
                             "little-endian")

    def test_wrong_machine_rejected(self):
        self.assert_rejected(build_elf(machine=EM_X86_64, phdrs=(PT_LOAD,)),
                             "AArch64")

    def test_no_load_segment_rejected(self):
        self.assert_rejected(build_elf(phdrs=()), "PT_LOAD")

    def test_interp_rejected(self):
        self.assert_rejected(build_elf(phdrs=(PT_LOAD, PT_INTERP)),
                             "PT_INTERP")

    def test_dt_needed_rejected(self):
        self.assert_rejected(
            build_elf(phdrs=(PT_LOAD, PT_DYNAMIC),
                      dynamic=((DT_NEEDED, 1), (DT_NULL, 0))),
            "DT_NEEDED")


if __name__ == "__main__":
    unittest.main()
