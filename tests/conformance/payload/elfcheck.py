"""Validate that a payload binary is a fully static AArch64 ELF.

Parses the ELF64 header and program headers directly (Elf64_Ehdr and
Elf64_Phdr layouts per elf(5)) rather than shelling out to readelf, so
the checks behave identically on any host: ELF64, EM_AARCH64, at least
one PT_LOAD, no PT_INTERP, no DT_NEEDED. PT_DYNAMIC without DT_NEEDED
is static-pie and is accepted.
"""

from __future__ import annotations

import struct

EM_AARCH64 = 183
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED = 0, 1
_EHDR = struct.Struct("<4sBBBBB7xHHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")
_DYN = struct.Struct("<qQ")


class ElfCheckError(ValueError):
    """The file is not a fully static AArch64 ELF64 binary."""


def _parse(path):
    """Return (blob, machine, [(p_type, p_offset, p_vaddr, p_filesz)])."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"\x7fELF":
        raise ElfCheckError("%s: no ELF magic" % path)
    if len(blob) < _EHDR.size:
        raise ElfCheckError("%s: truncated ELF header" % path)
    (_, ei_class, ei_data, _, _, _, _, machine, _, _, phoff, _, _,
     _, phentsize, phnum, _, _, _) = _EHDR.unpack_from(blob)
    if ei_class != 2:
        raise ElfCheckError("%s: not ELF64" % path)
    if ei_data != 1:
        raise ElfCheckError("%s: not little-endian" % path)
    if phentsize != _PHDR.size or phoff + phnum * phentsize > len(blob):
        raise ElfCheckError("%s: truncated program headers" % path)
    phdrs = []
    for index in range(phnum):
        (p_type, _, p_offset, p_vaddr, _, p_filesz, _, _) = \
            _PHDR.unpack_from(blob, phoff + index * phentsize)
        phdrs.append((p_type, p_offset, p_vaddr, p_filesz))
    return blob, machine, phdrs


def validate_static_aarch64(path) -> None:
    blob, machine, phdrs = _parse(path)
    if machine != EM_AARCH64:
        raise ElfCheckError("%s: machine %d is not AArch64" % (path, machine))
    loads = 0
    dynamic = None
    for p_type, p_offset, _, p_filesz in phdrs:
        if p_type == PT_LOAD:
            loads += 1
        elif p_type == PT_INTERP:
            raise ElfCheckError(
                "%s: PT_INTERP present, not a static binary" % path)
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)
    if not loads:
        raise ElfCheckError("%s: no PT_LOAD segment" % path)
    if dynamic:
        offset, size = dynamic
        if offset + size > len(blob):
            raise ElfCheckError("%s: truncated PT_DYNAMIC" % path)
        for pos in range(offset, offset + size, _DYN.size):
            tag, _ = _DYN.unpack_from(blob, pos)
            if tag == DT_NULL:
                break
            if tag == DT_NEEDED:
                raise ElfCheckError(
                    "%s: DT_NEEDED present, not a static binary" % path)
