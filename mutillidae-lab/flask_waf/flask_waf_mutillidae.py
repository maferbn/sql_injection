from flask import Flask, request, Response
import requests, re

app = Flask(__name__)
MUT_URL = "http://mutillidae"
PATTERN = re.compile(
    r"(union\s+select|drop\s+table|--|;--|benchmark\(|sleep\(|information_schema)",
    re.IGNORECASE
)

@app.route('/', defaults={'path': ''}, methods=['GET','POST'])
@app.route('/<path:path>', methods=['GET','POST'])
def proxy(path):
    data = " ".join(request.values.values()) + " " + request.headers.get("Cookie","")
    if request.is_json:
        data += request.get_data(as_text=True)
    if PATTERN.search(data):
        return Response("Blocked by Flask WAF", status=403)
    resp = requests.request(
        request.method,
        f"{MUT_URL}/{path}",
        params=request.args,
        data=None if request.is_json else request.form,
        json=request.get_json(silent=True),
        headers={k:v for k,v in request.headers if k.lower()!="host"}
    )
    excluded = ['content-encoding','transfer-encoding','connection']
    headers = [(k,v) for k,v in resp.raw.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, headers)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
