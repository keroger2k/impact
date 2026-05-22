from fastapi.templating import Jinja2Templates

from utils.site_code import site_code as _site_code

templates = Jinja2Templates(directory="templates")

# Available as `{{ value|site_code }}` in any template.
templates.env.filters["site_code"] = _site_code
