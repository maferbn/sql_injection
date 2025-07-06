# nano reconocimiento.py
#!/usr/bin/env python3
import subprocess
import json
import re
import sys
import time

class NetworkReconnaissance:
    def __init__(self, network_range):
        self.network_range = network_range
        self.discovered_hosts = []
        
    def host_discovery(self):
        """Ejecuta nmap -sn para encontrar hosts activos"""
        print(f"[+] Escaneando red: {self.network_range}")
        
        try:
            cmd = ["nmap", "-sn", self.network_range]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Extraer IPs de hosts activos
            ip_pattern = r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)'
            matches = re.findall(ip_pattern, result.stdout)
            self.discovered_hosts = matches
            
            print(f"[+] Hosts encontrados: {len(self.discovered_hosts)}")
            for host in self.discovered_hosts:
                print(f"    - {host}")
                
            return self.discovered_hosts
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return []
    
    def detailed_scan(self, target_ip):
        """Ejecuta nmap -sV -sC -O en un host específico"""
        print(f"\n[+] Escaneando detalladamente: {target_ip}")
        print("[!] Este proceso puede tomar 3-5 minutos...")
        
        try:
            cmd = ["nmap", "-sV", "-sC", "-O", target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            print(f"[+] Escaneo completado para {target_ip}")
            return self.parse_nmap_output(result.stdout, target_ip)
            
        except Exception as e:
            print(f"[-] Error escaneando {target_ip}: {e}")
            return None
    
    def parse_nmap_output(self, nmap_output, target_ip):
        """Parsea la salida de nmap"""
        services = []
        os_info = "Desconocido"
        
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
                    
                    services.append({
                        'port': port,
                        'service': service,
                        'version': version
                    })
        
        for line in lines:
            if 'OS details:' in line:
                os_info = line.replace('OS details:', '').strip()
                break
        
        return {
            'ip': target_ip,
            'os': os_info,
            'services': services,
            'raw_output': nmap_output
        }

def main():
    print("=== RED TEAM RECONNAISSANCE TOOL ===")
    print("Proyecto: Análisis de Inyección SQL en Mutillidae")
    print("=" * 50)
    
    # Determinar rango de red automáticamente o solicitar al usuario
    if len(sys.argv) > 1:
        network_range = sys.argv[1]
    else:
        print("\nRangos comunes de VirtualBox:")
        print("- NAT Network: 10.0.2.0/24")
        print("- Host-Only: 192.168.56.0/24")
        print("- Bridged: Depende de tu red local")
        network_range = input("\nIngresa el rango de red: ")
    
    recon = NetworkReconnaissance(network_range)
    
    # Fase 1: Descubrimiento
    print("\n[FASE 1] Descubrimiento de hosts activos")
    hosts = recon.host_discovery()
    
    if not hosts:
        print("[-] No se encontraron hosts activos")
        print("[!] Verifica que las VMs estén en la misma red")
        return
    
    # Fase 2: Escaneo detallado
    print("\n[FASE 2] Escaneo detallado de servicios")
    target_results = []
    metasploitable_ip = None
    
    for host in hosts:
        result = recon.detailed_scan(host)
        if result:
            target_results.append(result)
            
            print(f"\n--- RESULTADOS PARA {host} ---")
            print(f"OS: {result['os']}")
            print("Servicios encontrados:")
            
            has_web = False
            has_mysql = False
            
            for service in result['services']:
                print(f"  Puerto {service['port']}: {service['service']} - {service['version']}")
                
                if service['port'] == '80':
                    has_web = True
                    print(f"  *** SERVIDOR WEB DETECTADO ***")
                if service['port'] == '3306':
                    has_mysql = True
                    print(f"  *** BASE DE DATOS MYSQL DETECTADA ***")
            
            # Identificar Metasploitable
            if has_web and has_mysql:
                metasploitable_ip = host
                print(f"\n  🎯 OBJETIVO IDENTIFICADO: {host} (Posible Metasploitable)")
    
    # Guardar resultados
    results_data = {
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'network_range': network_range,
        'metasploitable_ip': metasploitable_ip,
        'all_hosts': target_results
    }
    
    with open('reconnaissance_results.json', 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n[+] Resultados guardados en reconnaissance_results.json")
    
    if metasploitable_ip:
        print(f"\n🎯 PRÓXIMO PASO: Usar IP {metasploitable_ip} para el escaneo de Mutillidae")
    
    print("\n[+] Reconocimiento completado exitosamente!")

if __name__ == "__main__":
    main()

# Hacer ejecutable
# chmod +x reconnaissance.py

# Ejecutar (REQUIERE SUDO para algunos escaneos)
# sudo python3 reconnaissance.py

# O con rango específico
# sudo python3 reconnaissance.py 192.168.56.0/24
