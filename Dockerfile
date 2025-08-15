FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y zabbix-sender openssl easy-rsa ipcalc && apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod -R 777 /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]