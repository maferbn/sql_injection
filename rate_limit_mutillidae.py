# rate_limit_mutillidae.py

from flask import Flask, request, abort
import requests
import fakeredis as redis

app = Flask(__name__)

# Redis en memoria (fakeredis)
r = redis.FakeRedis()

def allowed(ip: str, path: str) -> bool:
    """
    Controla cuántas veces una IP accede a una ruta por minuto.
    Límite: 15 peticiones cada 60 segundos.
    """
    key = f"rl:{ip}:{path}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, 60)
    return count <= 15

@app.before_request
def limit():
    if not allowed(request.remote_addr, request.path):
        abort(429, "Too Many Requests")

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    """
    Reenvía las peticiones al backend (puede ser httpbin o test_server).
    """
    resp = requests.request(
        method=request.method,
        url=f"http://127.0.0.1:8000/{path}",
        params=request.args,
        data=request.form,
        json=request.get_json(silent=True),
        headers={k: v for k, v in request.headers if k.lower() != "host"}
    )

    excluded = ['content-encoding', 'transfer-encoding', 'connection']
    headers = [(k, v) for k, v in resp.raw.headers.items() if k.lower() not in excluded]

    return resp.content, resp.status_code, headers

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
