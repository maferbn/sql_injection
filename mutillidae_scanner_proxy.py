#!/usr/bin/env python3
# Mutillidae II General Scanner (modificado para usar proxy si se desea)

import requests
import re
import time
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import logging
from datetime import datetime

class MutillidaeScanner:
    def __init__(self, target_ip, port=80, proxy_ip=None):
        self.target_ip = target_ip
        self.port = port
        self.base_url = f"http://{target_ip}:{port}/mutillidae/"
        self.session = requests.Session()
        self.discovered_pages = []
        self.vulnerable_forms = []

        # Configurar headers comunes
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
            'Accept': 'text/html',
            'Connection': 'keep-alive'
        })

        # Configurar proxies si se ingresó proxy_ip
        if proxy_ip:
            self.proxies = {
                "http": f"http://{proxy_ip}:8080",
                "https": f"http://{proxy_ip}:8080"
            }
        else:
            self.proxies = None

        # Configurar logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

        # Páginas conocidas
        self.known_pages = [
            "index.php?page=user-info.php", "index.php?page=login.php",
            "index.php?page=register.php", "index.php?page=dns-lookup.php",
            "index.php?page=pen-test-tool-lookup.php", "index.php?page=add-to-your-blog.php"
            # Puedes completar el resto como antes
        ]

    def _get(self, url, **kwargs):
        return self.session.get(url, proxies=self.proxies, timeout=10, **kwargs)

    def check_target_availability(self):
        try:
            self.logger.info(f"🔍 Verificando {self.base_url}")
            response = self._get(self.base_url)
            if response.status_code == 200 and 'mutillidae' in response.text.lower():
                self.logger.info("✅ Mutillidae II detectado")
                return True
            else:
                self.logger.error("❌ Mutillidae II no encontrado")
                return False
        except Exception as e:
            self.logger.error(f"❌ Error conectando: {e}")
            return False

    def discover_pages(self):
        self.logger.info("🔍 Descubriendo páginas...")
        for page in self.known_pages:
            url = urljoin(self.base_url, page)
            try:
                response = self._get(url)
                if response.status_code == 200:
                    self.logger.info(f"✅ Página activa: {page}")
                    self.discovered_pages.append(page)
                time.sleep(0.2)
            except Exception as e:
                self.logger.debug(f"Error accediendo {page}: {e}")

    def run_discovery(self):
        print(f"\n📡 Analizando: {self.base_url}")
        if not self.check_target_availability():
            return False
        self.discover_pages()
        print(f"\n✅ Páginas encontradas: {len(self.discovered_pages)}")
        for page in self.discovered_pages:
            print(f"  • {page}")
        return True

def main():
    print("🔍 MUTILLIDAE II SCANNER")
    target_ip = input("🎯 IP objetivo (Metasploitable): ").strip()
    if not target_ip:
        print("❌ IP requerida")
        return

    proxy_ip = input("🛡️  IP del proxy (ENTER si no usas proxy): ").strip()
    port = input("🔌 Puerto (default 80): ").strip() or "80"
    try:
        port = int(port)
    except ValueError:
        print("❌ Puerto inválido")
        return

    scanner = MutillidaeScanner(target_ip, port, proxy_ip or None)
    scanner.run_discovery()

if __name__ == "__main__":
    main()