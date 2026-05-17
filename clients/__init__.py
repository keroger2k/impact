# clients/__init__.py
#
# Infrastructure clients hit self-signed endpoints by default (override with
# IMPACT_VERIFY_SSL=true). Suppress urllib3's InsecureRequestWarning once here
# so individual clients don't each need to.
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
