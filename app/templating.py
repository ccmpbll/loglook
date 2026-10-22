import re
from pathlib import Path

import regex as regex_module
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.auth import current_user
from app.config import VERSION

templates_dir = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(templates_dir))
templates.env.globals["current_user"] = current_user
templates.env.globals["APP_VERSION"] = VERSION


def local_time(ts) -> Markup:
    """A UTC timestamp as a <time> tag that local-time.js turns into the viewer's own time."""
    if ts is None:
        return Markup("-")
    utc_text = ts.strftime("%Y-%m-%d %H:%M:%S")
    return Markup(f'<time class="local-time" datetime="{escape(ts.isoformat())}">{escape(utc_text)} UTC</time>')


def highlight(text: str, q: str = "", include: str = "") -> Markup:
    """Log text with the parts that matched the filter wrapped in <mark>. Everything else is escaped."""
    spans = []
    if q:
        spans += [m.span() for m in re.finditer(re.escape(q), text, re.IGNORECASE)]
    if include:
        try:
            spans += [m.span() for m in regex_module.finditer(include, text, timeout=0.25) if m.end() > m.start()]
        except (regex_module.error, TimeoutError):
            pass
    out, pos = [], 0
    for start, end in sorted(spans):
        if start < pos:
            start = pos  # overlapping matches are merged
        if end <= start:
            continue
        out.append(escape(text[pos:start]))
        out.append(Markup("<mark>") + escape(text[start:end]) + Markup("</mark>"))
        pos = end
    out.append(escape(text[pos:]))
    return Markup("").join(out)


templates.env.filters["local_time"] = local_time
templates.env.filters["highlight"] = highlight
