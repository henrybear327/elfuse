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
              dynamic=(), interp=None, strtab=b""):
    """Assemble headers, program headers, then dynamic entries and blobs.

    The whole file is described by one PT_LOAD at vaddr 0 mapping offset
    0, so dynamic-section vaddrs (DT_STRTAB) equal file offsets.
    """
    phdrs = list(phdrs)
    if interp is not None and PT_INTERP not in phdrs:
        phdrs.append(PT_INTERP)
    phoff = EHSIZE
    dyn_off = phoff + PHENTSIZE * len(phdrs)
    interp_off = dyn_off + 16 * len(dynamic)
    interp_blob = (interp + b"\0") if interp else b""
    strtab_off = interp_off + len(interp_blob)
    # A "strtab" sentinel value resolves to the table's file offset; byte
    # patching after assembly is unsound because a PT_LOAD header's
    # p_flags=5 plus zero offset matches the same 16-byte pattern.
    dyn_blob = b"".join(
        struct.pack("<qQ", tag, strtab_off if val == "strtab" else val)
        for tag, val in dynamic)
    header = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF", ei_class, ei_data, 1, 0, 0,
        2, machine, 1,
        0x400000, phoff, 0,
        0, EHSIZE, PHENTSIZE, len(phdrs), 0, 0, 0)
    body = b""
    for p_type in phdrs:
        if p_type == PT_DYNAMIC:
            offset, filesz = dyn_off, len(dyn_blob)
        elif p_type == PT_INTERP:
            offset, filesz = interp_off, len(interp_blob)
        elif p_type == PT_LOAD:
            offset, filesz = 0, strtab_off + len(strtab)
        else:
            offset, filesz = 0, 0
        body += struct.pack("<IIQQQQQQ", p_type, 5, offset, offset, offset,
                            filesz, filesz, 0x1000)
    return header + body + dyn_blob + interp_blob + strtab


def strtab_and_offsets(names):
    """A dynamic string table plus the offset of each name inside it."""
    table = b"\0"
    offsets = []
    for name in names:
        offsets.append(len(table))
        table += name + b"\0"
    return table, offsets


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


DT_STRTAB, DT_STRSZ = 5, 10


class ReadDynamicTest(unittest.TestCase):
    """read_dynamic() feeds the LTP rootfs library-closure staging."""

    def read(self, blob):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
        path = pathlib.Path(fh.name)
        self.addCleanup(path.unlink)
        return elfcheck.read_dynamic(path)

    def test_static_binary(self):
        info = self.read(build_elf(phdrs=(PT_LOAD,)))
        self.assertIsNone(info.interp)
        self.assertEqual(info.needed, [])
        self.assertEqual(info.machine, EM_AARCH64)

    def test_dynamic_binary(self):
        strtab, (libc_off, libm_off) = strtab_and_offsets(
            [b"libc.so.6", b"libm.so.6"])
        blob = build_elf(
            phdrs=(PT_LOAD, PT_DYNAMIC),
            interp=b"/lib/ld-linux-aarch64.so.1",
            strtab=strtab,
            dynamic=((DT_NEEDED, libc_off), (DT_NEEDED, libm_off),
                     (DT_STRTAB, "strtab"), (DT_STRSZ, len(strtab)),
                     (DT_NULL, 0)))
        info = self.read(blob)
        self.assertEqual(info.interp, "/lib/ld-linux-aarch64.so.1")
        self.assertEqual(info.needed, ["libc.so.6", "libm.so.6"])

    def test_non_elf_rejected(self):
        with self.assertRaises(elfcheck.ElfCheckError):
            self.read(b"not an elf")


if __name__ == "__main__":
    unittest.main()
