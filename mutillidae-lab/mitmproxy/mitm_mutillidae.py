# mitmproxy/scripts/mitm_mutillidae.py
from mitmproxy import http
import re

SQL_PATTERNS = [
    r"\bunion\b", r"\bdrop\b", r"--", r";--",
    r"benchmark\(", r"sleep\(", r"select.+from",
    r"information_schema"
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in SQL_PATTERNS]

def request(flow: http.HTTPFlow) -> None:
    # junta body, query params y form
    txt = flow.request.get_text() or ""
    txt += "".join(f"{k}={v}" for k,v in flow.request.query.items())
    for pat in COMPILED:
        if pat.search(txt.lower()):
            body = "Forbidden: posible inyección SQL detectada".encode("utf-8")
            flow.response = http.HTTPResponse.make(
                403,
                body,
                {"Content-Type": "text/plain; charset=utf-8"}
            )
            return
