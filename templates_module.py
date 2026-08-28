from fastapi.templating import Jinja2Templates
from jinja2 import Undefined

from utils.site_code import (
    site_code as _site_code,
    site_code_from_hostname as _site_code_from_hostname,
    site_code_strict as _site_code_strict,
)
from utils.ipv6_assembler import (
    site_vvvv_mask as _site_vvvv_mask,
    site_vvvv_fixed_value as _site_vvvv_fixed_value,
)
from utils.nxos_interface import format_bytes as _shared_format_bytes

templates = Jinja2Templates(directory="templates")

# Available as `{{ value|site_code }}` in any template.
templates.env.filters["site_code"] = _site_code
# Hostname-aware variant — uppercases input and prefix-matches (use this on
# device hostnames; `site_code` requires word boundaries and won't match
# patterns inside undelimited hostnames like `k024fwl006`).
templates.env.filters["site_code_from_hostname"] = _site_code_from_hostname
# Strict KXXX / SXXX / TXXX / IXXX 4-char shape; works on hostnames AND site
# paths in one shot. Use this for prefilling forms where false positives like
# "ROUT" from "ROUTER-K024" must be avoided.
templates.env.filters["site_code_strict"] = _site_code_strict


# IPv6 vvvv helpers — used by the allocation modal to expose each site's
# fixed-bits + mask as data attributes the JS reads on selection.
def _vvvv_fixed_hex(site: dict) -> str:
    length = int(site.get("prefix_length", 48))
    return f"{_site_vvvv_fixed_value(site['prefix'], length):04x}"


def _vvvv_mask_hex(site: dict) -> str:
    length = int(site.get("prefix_length", 48))
    return f"{_site_vvvv_mask(length):04x}"


templates.env.filters["vvvv_fixed_hex"] = _vvvv_fixed_hex
templates.env.filters["vvvv_mask_hex"] = _vvvv_mask_hex


# Human-readable byte counter, e.g. for Nexus interface RX/TX totals.
# Formatting itself lives in utils.nxos_interface (shared with the CLI health
# report); this wrapper only adds the Jinja concern: `dict.attr` on a dict
# lacking that key — a cache entry written before the field existed — resolves
# to Undefined, not None, and float(Undefined) raises UndefinedError.
def _format_bytes(value) -> str:
    if isinstance(value, Undefined):
        return "N/A"
    return _shared_format_bytes(value)


templates.env.filters["format_bytes"] = _format_bytes
