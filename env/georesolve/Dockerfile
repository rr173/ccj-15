FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN groupadd -r georesolve && useradd -r -g georesolve georesolve \
    && mkdir -p /data && chown georesolve:georesolve /data
USER georesolve

ENV GEORESOLVE_DB_PATH=/data/georesolve.db
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2)"

CMD ["uvicorn", "--factory", "app.main:build_from_env", "--host", "0.0.0.0", "--port", "8080"]
