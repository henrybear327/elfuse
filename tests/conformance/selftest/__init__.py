"""Hermetic selftests for the conformance harness.

Every module here runs without payloads, network, or a VM, so the whole
directory is cheap enough for the make check lane. Run with:
    python3 -m unittest discover -s tests/conformance/selftest -t tests
"""
