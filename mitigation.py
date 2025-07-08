# mitigation.py

import subprocess
import logging

# Lista de IPs ya bloqueadas en firewall para evitar duplicados
blocked_ips = set()

def bloquear_ip_logicamente(flow, ip):
    """
    Devuelve una respuesta HTTP 403 al atacante,
    sin necesidad de bloquear a nivel de red.
    """
    mensaje = "🟥 Acceso bloqueado por actividad maliciosa."
    flow.response = flow.response.make(
        403,
        mensaje,
        {"Content-Type": "text/plain"}
    )
    logging.warning(f"[MITIGACIÓN] Respuesta 403 enviada a {ip}")

def bloquear_ip_iptables(ip):
    """
    Ejecuta un bloqueo real en el firewall con iptables.
    Asegúrate de ejecutar mitmproxy con permisos adecuados.
    """
    if ip not in blocked_ips:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True)
            blocked_ips.add(ip)
            logging.warning(f"[MITIGACIÓN] IP bloqueada en iptables: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"[ERROR] Falló el bloqueo con iptables para {ip}: {e}")

def registrar_incidente(ip, score, url):
    """
    Guarda un registro de actividad maliciosa detectada
    con puntajes elevados.
    """
    mensaje = f"{ip} | SCORE: {score} | URL: {url}\n"
    try:
        with open("mitigation_log.txt", "a") as f:
            f.write(mensaje)
        logging.info(f"[MITIGACIÓN] Incidente registrado: {mensaje.strip()}")
    except Exception as e:
        logging.error(f"[ERROR] No se pudo registrar el incidente: {e}")