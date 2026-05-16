FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Default port for Prometheus metrics
EXPOSE 9100

ENTRYPOINT ["python", "main.py"]
