# test_server.py

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def echo(path=''):
    """
    Devuelve en JSON todo lo que recibe:
    - query params en args
    - form-data en form
    - JSON en json
    """
    return jsonify({
        "path": path,
        "method": request.method,
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "json": request.get_json(silent=True)
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

