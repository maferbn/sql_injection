from flask import Flask, request, Response
import requests
import re
import os
import logging

app = Flask(__name__)
# Habilitar logging de nivel WARNING
app.logger.setLevel(logging.WARNING)

# URL del backend que atiende las peticiones válidas
MUT_URL = os.getenv("MUT_URL", "https://httpbin.org")

# Patrón SQL malicioso
PATTERN = re.compile(
    r"(union\s+select|drop\s+table|--|;--|benchmark\(|sleep\(|information_schema)",
    re.IGNORECASE
)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    """
    Recibe la petición, valida contra el patrón y la reenvía.
    """
    # Junta datos de URL, form y JSON
    data = " ".join(request.values.values())
    if request.is_json:
        data += request.get_data(as_text=True)
    data += " " + request.headers.get("Cookie", "")

    # Bloqueo si el patrón coincide
    if PATTERN.search(data):
        # Loguear cada bloqueo
        app.logger.warning(f"Blocked by WAF: {data}")
        # Respuesta al cliente
        return Response("Blocked by WAF", status=403)

    # Reenvío al servidor real
    resp = requests.request(
        method=request.method,
        url=f"{MUT_URL}/{path}",
        params=request.args,
        data=None if request.is_json else request.form,
        json=request.get_json(silent=True),
        headers={k: v for k, v in request.headers if k.lower() != "host"}
    )

    # Filtrar headers no válidos
    excluded = ['content-encoding', 'transfer-encoding', 'connection']
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded]

    return Response(resp.content, resp.status_code, headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
