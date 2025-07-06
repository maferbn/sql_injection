#!/usr/bin/env python3
"""
Mutillidae II General Scanner
Escáner para descubrir páginas vulnerables y formularios en Mutillidae II
"""

import requests
import re
import time
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import logging
from datetime import datetime

class MutillidaeScanner:
    def __init__(self, target_ip, port=80):
        self.target_ip = target_ip
        self.port = port
        self.base_url = f"http://{target_ip}:{port}/mutillidae/"
        self.session = requests.Session()
        self.discovered_pages = []
        self.vulnerable_forms = []
        
        # Configurar headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Páginas conocidas de Mutillidae
        self.known_pages = [
            "index.php?page=user-info.php",
            "index.php?page=login.php",
            "index.php?page=register.php",
            "index.php?page=user-poll.php",
            "index.php?page=dns-lookup.php",
            "index.php?page=pen-test-tool-lookup.php",
            "index.php?page=view-someones-blog.php",
            "index.php?page=add-to-your-blog.php",
            "index.php?page=text-file-viewer.php",
            "index.php?page=source-viewer.php",
            "index.php?page=capture-data.php",
            "index.php?page=set-background-color.php",
            "index.php?page=html5-storage.php",
            "index.php?page=browser-info.php",
            "index.php?page=show-log.php",
            "index.php?page=password-generator.php",
            "index.php?page=arbitrary-file-inclusion.php",
            "index.php?page=secret-administrative-pages.php"
        ]

    def banner(self):
        """Mostrar banner del escáner"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                MUTILLIDAE II GENERAL SCANNER                 ║
║                    Discovery & Enumeration                   ║
╠══════════════════════════════════════════════════════════════╣
║ Target: {:<50} ║
║ Purpose: Discover vulnerable pages and forms                 ║
╚══════════════════════════════════════════════════════════════╝
        """.format(self.base_url))

    def check_target_availability(self):
        """Verificar que Mutillidae esté disponible"""
        try:
            self.logger.info(f"🔍 Verificando {self.base_url}")
            response = self.session.get(self.base_url, timeout=10)
            
            if response.status_code == 200 and 'mutillidae' in response.text.lower():
                self.logger.info("✅ Mutillidae II detectado")
                
                # Extraer información
                version_match = re.search(r'Version:\s*([\d.]+)', response.text)
                if version_match:
                    self.logger.info(f"📋 Versión: {version_match.group(1)}")
                
                security_match = re.search(r'Security Level:\s*(\d+)', response.text)
                if security_match:
                    level = security_match.group(1)
                    level_desc = {
                        '0': 'Hosed (Sin protección)',
                        '1': 'Arrogant (Protección mínima)',
                        '5': 'Secure (Máxima protección)'
                    }.get(level, f'Nivel {level}')
                    self.logger.info(f"🔒 Nivel de seguridad: {level} - {level_desc}")
                
                return True
            else:
                self.logger.error("❌ Mutillidae II no encontrado")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Error conectando: {e}")
            return False

    def discover_pages(self):
        """Descubrir páginas disponibles"""
        self.logger.info("🔍 Descubriendo páginas...")
        
        # Probar páginas conocidas
        for page in self.known_pages:
            url = urljoin(self.base_url, page)
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    page_info = {
                        'page': page,
                        'url': url,
                        'status': 'accessible',
                        'title': self.extract_title(response.text),
                        'forms_count': len(self.extract_forms(response.text)),
                        'has_inputs': self.has_input_fields(response.text),
                        'potential_vulns': self.identify_potential_vulnerabilities(response.text, page)
                    }
                    
                    self.discovered_pages.append(page_info)
                    
                    status = "✅" if page_info['has_inputs'] else "📄"
                    self.logger.info(f"  {status} {page} - {page_info['forms_count']} formularios")
                    
                    if page_info['potential_vulns']:
                        for vuln in page_info['potential_vulns']:
                            self.logger.info(f"    🎯 Posible {vuln}")
                
                time.sleep(0.2)  # Pausa entre requests
                
            except Exception as e:
                self.logger.debug(f"Error accediendo {page}: {e}")
        
        # Descubrir páginas adicionales desde enlaces
        self.discover_additional_pages()

    def discover_additional_pages(self):
        """Descubrir páginas adicionales desde enlaces"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar enlaces adicionales
            links = soup.find_all('a', href=True)
            additional_pages = []
            
            for link in links:
                href = link['href']
                if 'index.php?page=' in href and href not in self.known_pages:
                    additional_pages.append(href)
            
            if additional_pages:
                self.logger.info(f"🔍 Encontradas {len(additional_pages)} páginas adicionales")
                
                for page in additional_pages:
                    url = urljoin(self.base_url, page)
                    try:
                        response = self.session.get(url, timeout=10)
                        if response.status_code == 200:
                            page_info = {
                                'page': page,
                                'url': url,
                                'status': 'discovered',
                                'title': self.extract_title(response.text),
                                'forms_count': len(self.extract_forms(response.text)),
                                'has_inputs': self.has_input_fields(response.text),
                                'potential_vulns': self.identify_potential_vulnerabilities(response.text, page)
                            }
                            
                            self.discovered_pages.append(page_info)
                            self.logger.info(f"  📄 {page} (descubierta)")
                        
                        time.sleep(0.2)
                        
                    except Exception as e:
                        self.logger.debug(f"Error con página adicional {page}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error descubriendo páginas adicionales: {e}")

    def extract_title(self, html):
        """Extraer título de la página"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else "Sin título"
        except:
            return "Sin título"

    def extract_forms(self, html):
        """Extraer formularios de una página"""
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                # Extraer campos de entrada
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required')
                    }
                    if input_data['name']:
                        form_data['inputs'].append(input_data)
                
                if form_data['inputs']:
                    forms.append(form_data)
        
        except Exception as e:
            self.logger.debug(f"Error extrayendo formularios: {e}")
        
        return forms

    def has_input_fields(self, html):
        """Verificar si la página tiene campos de entrada"""
        input_patterns = [
            r'<input[^>]*name=["\'][^"\']*["\'][^>]*>',
            r'<textarea[^>]*name=["\'][^"\']*["\'][^>]*>',
            r'<select[^>]*name=["\'][^"\']*["\'][^>]*>'
        ]
        
        for pattern in input_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False

    def identify_potential_vulnerabilities(self, html, page):
        """Identificar posibles vulnerabilidades basadas en el contenido"""
        potential_vulns = []
        html_lower = html.lower()
        
        # SQL Injection indicators
        if any(keyword in html_lower for keyword in ['username', 'password', 'user info', 'login', 'search']):
            if any(keyword in page.lower() for keyword in ['user-info', 'login', 'register', 'poll']):
                potential_vulns.append('SQL Injection')
        
        # XSS indicators
        if any(keyword in html_lower for keyword in ['blog', 'comment', 'message', 'search', 'input']):
            potential_vulns.append('XSS')
        
        # Command Injection indicators
        if any(keyword in html_lower for keyword in ['dns', 'lookup', 'ping', 'tool']):
            potential_vulns.append('Command Injection')
        
        # File Inclusion indicators
        if any(keyword in html_lower for keyword in ['file', 'viewer', 'include', 'page']):
            potential_vulns.append('File Inclusion')
        
        # CSRF indicators
        if 'form' in html_lower and 'csrf' not in html_lower and 'token' not in html_lower:
            potential_vulns.append('CSRF')
        
        return potential_vulns

    def analyze_forms(self):
        """Analizar formularios encontrados"""
        self.logger.info("📋 Analizando formularios...")
        
        for page_info in self.discovered_pages:
            if page_info['forms_count'] > 0:
                try:
                    response = self.session.get(page_info['url'], timeout=10)
                    forms = self.extract_forms(response.text)
                    
                    for i, form in enumerate(forms):
                        form_analysis = {
                            'page': page_info['page'],
                            'url': page_info['url'],
                            'form_index': i,
                            'method': form['method'],
                            'action': form['action'],
                            'inputs': form['inputs'],
                            'vulnerability_types': [],
                            'risk_level': 'low'
                        }
                        
                        # Analizar tipos de vulnerabilidades posibles
                        input_names = [inp['name'].lower() for inp in form['inputs']]
                        
                        # SQL Injection
                        if any(name in input_names for name in ['username', 'user', 'login', 'search', 'id']):
                            form_analysis['vulnerability_types'].append('SQL Injection')
                            form_analysis['risk_level'] = 'high'
                        
                        # XSS
                        if any(name in input_names for name in ['comment', 'message', 'blog', 'search', 'name']):
                            form_analysis['vulnerability_types'].append('XSS')
                            if form_analysis['risk_level'] == 'low':
                                form_analysis['risk_level'] = 'medium'
                        
                        # Command Injection
                        if any(name in input_names for name in ['host', 'ip', 'domain', 'command', 'tool']):
                            form_analysis['vulnerability_types'].append('Command Injection')
                            form_analysis['risk_level'] = 'high'
                        
                        self.vulnerable_forms.append(form_analysis)
                        
                        risk_emoji = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}[form_analysis['risk_level']]
                        self.logger.info(f"  {risk_emoji} Formulario en {page_info['page']}")
                        self.logger.info(f"    Método: {form['method'].upper()}")
                        self.logger.info(f"    Campos: {len(form['inputs'])}")
                        self.logger.info(f"    Posibles vulnerabilidades: {', '.join(form_analysis['vulnerability_types'])}")
                
                except Exception as e:
                    self.logger.error(f"Error analizando formularios en {page_info['page']}: {e}")

    def generate_discovery_report(self):
        """Generar reporte de descubrimiento"""
        self.logger.info("📊 Generando reporte de descubrimiento...")
        
        # Estadísticas
        total_pages = len(self.discovered_pages)
        pages_with_forms = len([p for p in self.discovered_pages if p['forms_count'] > 0])
        total_forms = sum(p['forms_count'] for p in self.discovered_pages)
        high_risk_forms = len([f for f in self.vulnerable_forms if f['risk_level'] == 'high'])
        
        # Reporte en consola
        print("\n" + "="*80)
        print("🔍 REPORTE DE DESCUBRIMIENTO - MUTILLIDAE II")
        print("="*80)
        print(f"📄 Páginas descubiertas: {total_pages}")
        print(f"📋 Páginas con formularios: {pages_with_forms}")
        print(f"🎯 Total de formularios: {total_forms}")
        print(f"🔴 Formularios de alto riesgo: {high_risk_forms}")
        print("="*80)
        
        # Páginas por categoría de riesgo
        high_risk_pages = [p for p in self.discovered_pages if any('SQL Injection' in p['potential_vulns'] or 'Command Injection' in p['potential_vulns'])]
        medium_risk_pages = [p for p in self.discovered_pages if p['has_inputs'] and p not in high_risk_pages]
        
        if high_risk_pages:
            print("\n🔴 PÁGINAS DE ALTO RIESGO:")
            for page in high_risk_pages:
                print(f"  • {page['page']}")
                print(f"    Vulnerabilidades: {', '.join(page['potential_vulns'])}")
        
        if medium_risk_pages:
            print("\n🟡 PÁGINAS DE RIESGO MEDIO:")
            for page in medium_risk_pages:
                print(f"  • {page['page']} ({page['forms_count']} formularios)")
        
        # Guardar reporte JSON
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'statistics': {
                'total_pages': total_pages,
                'pages_with_forms': pages_with_forms,
                'total_forms': total_forms,
                'high_risk_forms': high_risk_forms
            },
            'discovered_pages': self.discovered_pages,
            'vulnerable_forms': self.vulnerable_forms
        }
        
        report_filename = f'mutillidae_discovery_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n💾 Reporte guardado en: {report_filename}")
        
        # Recomendaciones para el siguiente paso
        if high_risk_forms > 0:
            print(f"\n🎯 SIGUIENTE PASO:")
            print(f"Usar sql_injection_tool.py para explotar las {high_risk_forms} páginas de alto riesgo")
            print(f"Comando sugerido: python3 sql_injection_tool.py")

    def run_discovery(self):
        """Ejecutar descubrimiento completo"""
        self.banner()
        
        if not self.check_target_availability():
            return False
        
        self.discover_pages()
        self.analyze_forms()
        self.generate_discovery_report()
        
        return True

def main():
    """Función principal"""
    print("🔍 MUTILLIDAE II DISCOVERY SCANNER")
    
    target_ip = input("🎯 IP del objetivo (Metasploitable): ").strip()
    if not target_ip:
        print("❌ IP requerida")
        return
    
    port = input("🔌 Puerto (default 80): ").strip() or "80"
    
    try:
        port = int(port)
    except ValueError:
        print("❌ Puerto debe ser un número")
        return
    
    scanner = MutillidaeScanner(target_ip, port)
    scanner.run_discovery()

if __name__ == "__main__":
    main()
