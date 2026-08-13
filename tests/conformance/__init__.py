"""Shared conformance harness for the gVisor syscall and LTP suites.

One engine runs both upstream suites on both backends (elfuse and the QEMU
Linux reference) and gates every case against ordered-actions expectation
files: an unexpected failure and an unexpected pass are both red, so the
checked-in expectations always describe the current behavior exactly.
"""
