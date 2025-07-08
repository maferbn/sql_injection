from mitmproxy import http
from detector_sql_injection import SQLInjectionDetector
from mitigation import (
    bloquear_ip_logicamente,
    bloquear_ip_iptables,
    registrar_incidente
)
import json

# Instancia del detector
detector = SQLInjectionDetector()

def request(flow: http.HTTPFlow):
    # Obtener IP de origen
    ip = str(flow.client_conn.address[0])

    # Extraer datos de la solicitud
    method = flow.request.method
    url = flow.request.pretty_url
    headers = dict(flow.request.headers)
    body = flow.request.get_text()

    # Detección
    is_malicious, patterns = detector.analyze_request(method, url, headers, body)
    score = detector.get_risk_score(patterns)

    # Registrar actividad
    if is_malicious:
        print(f"\n🚨 SQLi detectado desde {ip}")
        print(f"🔗 URL: {url}")
        print(f"📊 Score: {score}")
        print(f"🧬 Patrones detectados: {patterns}\n")

        # Guardar alerta en JSON
        alerta = {
            "ip": ip,
            "url": url,
            "score": score,
            "patterns": patterns
        }
        with open("sqli_alerts.json", "a") as f:
            json.dump(alerta, f)
            f.write("\n")

        # Mitigación si el score es alto
        if score >= 30:
            registrar_incidente(ip, score, url)
            bloquear_ip_logicamente(flow, ip)
            # bloquear_ip_iptables(ip)  ← Descomenta si quieres defensa real a nivel de red
            return  # Cortar flujo tras mitigación