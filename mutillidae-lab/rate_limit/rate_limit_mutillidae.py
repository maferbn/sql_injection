import os
import redis
from flask import Flask, request, abort
import requests

app = Flask(__name__)
redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
r = redis.Redis.from_url(redis_url)

def allowed(ip, path):
    key = f"rate:{ip}:{path}"
    cnt = r.incr(key)
    if cnt == 1:
        r.expire(key, 60)
    return cnt <= 15

@app.before_request
def limit():
    if not allowed(request.remote_addr, request.path):
        abort(429, "Too many requests")

@app.route('/', defaults={'path': ''}, methods=['GET','POST'])
@app.route('/<path:path>', methods=['GET','POST'])
def proxy(path):
    resp = requests.request(
        request.method,
        f"http://mutillidae/{path}",
        params=request.args,
        data=request.form,
        json=request.get_json(silent=True),
        headers={k:v for k,v in request.headers if k.lower()!="host"}
    )
    excluded = ['content-encoding','transfer-encoding','connection']
    headers = [(k,v) for k,v in resp.raw.headers.items() if k.lower() not in excluded]
    return resp.content, resp.status_code, headers

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
