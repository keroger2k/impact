"""
Shared pytest configuration.

The env vars below MUST be set at module-import time of conftest.py — that's
before pytest collects any test file. dev.DEV_MODE and aci_registry's fabric
list are both captured at first module import; setting these via fixtures
(monkeypatch.setenv) is too late, because the modules will already have read
their env values.

Tests that need to override these (e.g. test_security_remediation flips
DEV_MODE off via re-import) can still do so on a per-test basis.
"""
import os

os.environ.setdefault("DEV_MODE", "true")
os.environ.setdefault("AD_LDAP_URL", "ldaps://localhost")
os.environ.setdefault("ACI_FABRICS", "dc1")
os.environ.setdefault("ACI_DC1_URL", "http://aci-dc1.local")
os.environ.setdefault("ACI_DC1_LABEL", "DC1")
