"""Payload acquisition and builds for the conformance suites.

Payloads are fixtures, not build products: they install under
externals/payloads/, survive make clean, and their freshness is a content
fingerprint (never an mtime) that doubles as the CI cache key.
"""
