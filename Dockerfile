FROM python:3.12-slim

ARG VERSION=dev
ENV PYTHONUNBUFFERED=1 \
    LOGLOOK_VERSION=$VERSION \
    LOGLOOK_DATA_DIR=/data \
    LOGLOOK_LOG_DIR=/logs \
    LOGLOOK_CONFIG=/config/sources.yml

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data /config /logs
VOLUME ["/data", "/config"]

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
