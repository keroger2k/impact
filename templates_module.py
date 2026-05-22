from fastapi.templating import Jinja2Templates

from utils.site_code import site_code as _site_code, site_code_from_hostname as _site_code_from_hostname

templates = Jinja2Templates(directory="templates")

# Available as `{{ value|site_code }}` in any template.
templates.env.filters["site_code"] = _site_code
# Hostname-aware variant — uppercases input and prefix-matches (use this on
# device hostnames; `site_code` requires word boundaries and won't match
# patterns inside undelimited hostnames like `k024fwl006`).
templates.env.filters["site_code_from_hostname"] = _site_code_from_hostname
