FROM python:3.11-slim

WORKDIR /app

COPY flask_waf_mutillidae.py .

RUN pip install flask requests

CMD ["python", "flask_waf_mutillidae.py"]
