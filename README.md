# sql_injection

Antes que nada, instalar el ambiente virtual y las dependencias, ejecutando (EN TODA TERMINAL QUE USEN):

1) Python -m venv venv (o puede ser también Python3 -m venv venv)

2) Activación: . venv/bin/activate (para Bash) o venv\Scripts\activate (para CMD)

3) Instalación de dependencias: pip install -r requirements.txt

Prueba mitm (mitim_multillidae.py):

1) En una terminal, iniciar el servidor de prueba: python test_server.py

2) En otra terminal, iniciar el mitm: mitmdump --mode reverse:http://127.0.0.1:8000 --listen-host 0.0.0.0 --listen-port 8080 -s sqli_injector.py -s mitm_mutillidae.py -vv

3) En una tercera terminal, ejecutar: curl -v "http://127.0.0.1:8080/" (debe arrojar error 200, OK)

4) En la misma terminal, ejecutar: curl -v "http://127.0.0.1:8080/?id=5%20OR%201=1--" (debe arrojar error 403, Forbidden, pues es una inyección)

Prueba Flask WAF (flask_waf_mutillidae.py):

1) En una terminal, iniciar el servidor de prueba: python test_server.py

2) En otra terminal, ejecutar: export MUT_URL=http://127.0.0.1:8000

3) En la misma terminal, ejecutar: python flask_waf_mutillidae.py

4) En una tercera terminal, ejecutar: curl -v "http://127.0.0.1:8081/" (debe arrojar error 200 OK)

5) En la misma terminal, ejecutar: curl -v "http://127.0.0.1:8081/?q=drop%20table%20users" (debe arrojar error 403 Forbidden, pues es una inyección)

Prueba limitación de IP (rate_limit_mutillidae.py):

1) En una terminal, iniciar el servidor de prueba: python test_server.py

2) En la misma terminal, ejecutar: python rate_limit_mutillidae.py

3) En una tercera terminal, ejecutar: 
for i in {1..16}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8082/
done

(Las primeras 15 veces se mostrará 200, señalando que todo esta OK, pero la última será 429, pues se excedieron el máximo de 15 solicitudes por minuto por cliente (IP))




