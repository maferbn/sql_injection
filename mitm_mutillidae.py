# mitm_mutillidae.py

from mitmproxy import http, ctx
import re

# Patrones SQLi a bloquear
SQL_PATTERNS = [
    # Comandos básicos
    r"\bselect\b", r"\binsert\b", r"\bupdate\b", r"\bdelete\b",
    r"\bdrop\b", r"\balter\b", r"\bcreate\b", r"\btruncate\b",
    # Union select
    r"\bunion\s+select\b",
    # Comentarios y delimitadores
    r"--", r";--", r"/\*.*\*/",
    # Operadores lógicos
    r"\bor\b", r"\band\b",
    # Funciones peligrosas
    r"\bbenchmark\s*\(", r"\bsleep\s*\(", r"\bload_file\s*\(",
    r"\binformation_schema\b", r"\bchar\s*\(", r"\bconcat\s*\(",
    r"\bxp_cmdshell\b", r"\bexec(\s|\+)+(s|x)p\b"
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SQL_PATTERNS]

def request(flow: http.HTTPFlow) -> None:
    # Monta todo el payload en un string
    payload = flow.request.get_text() or ""
    if flow.request.query:
        payload += " ".join(f"{k}={v}" for k, v in flow.request.query.items())
    if flow.request.urlencoded_form:
        payload += " ".join(f"{k}={v}" for k, v in flow.request.urlencoded_form.items())
    try:
        j = flow.request.get_json(silent=True)
        if j:
            payload += str(j)
    except Exception:
        pass

    # Busca patrones
    for pat in COMPILED_PATTERNS:
        if pat.search(payload):
            ctx.log.info(f"[WAF] Bloqueando por patrón: {pat.pattern}")
            body = "Forbidden: posible inyección SQL detectada".encode("utf-8")
            flow.response = http.Response.make(
                403,
                body,
                {"Content-Type": "text/plain; charset=utf-8"}
            )
            return
