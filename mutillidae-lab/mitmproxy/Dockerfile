FROM mitmproxy/mitmproxy:latest

COPY mitm_mutillidae.py /scripts/mitm_mutillidae.py

# mitmdump es la interfaz sin consola que funciona en background
ENTRYPOINT ["mitmdump"]
CMD ["-s", "/scripts/mitm_mutillidae.py","--listen-host", "0.0.0.0","--listen-port", "8080"]
