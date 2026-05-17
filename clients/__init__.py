# clients/__init__.py
#
# Infrastructure clients hit self-signed endpoints by default (override with
# IMPACT_VERIFY_SSL=true). Suppress urllib3's InsecureRequestWarning once here
# so individual clients don't each need to.
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def verify_ssl() -> bool:
    """Whether to verify TLS certs when talking to infrastructure endpoints.

    Defaults to False because the platform uses self-signed certificates.
    Override with IMPACT_VERIFY_SSL=true.
    """
    return os.getenv("IMPACT_VERIFY_SSL", "false").lower() == "true"
