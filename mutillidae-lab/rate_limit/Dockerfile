FROM python:3.11-slim

WORKDIR /app

COPY rate_limit_mutillidae.py .

RUN pip install flask redis requests

CMD ["python", "rate_limit_mutillidae.py"]
