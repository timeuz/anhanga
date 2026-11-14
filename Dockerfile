FROM python:3.12-slim

# O motor usa o binário `openssl` (s_client, ocsp, crl) para cadeia, OCSP grampeado e revogação.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Estado (targets.yaml, anhanga.db) fica no volume /data; o processo roda sem privilégios.
RUN useradd --system --uid 10001 --home-dir /data anhanga && mkdir -p /data && chown anhanga /data
USER anhanga
WORKDIR /data
# targets.yaml é achado em /data (WORKDIR); ANHANGA_CONFIG explícito e inexistente é erro, então não o fixamos aqui.
ENV ANHANGA_DB_PATH=/data/anhanga.db \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 7890

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7890/healthz', timeout=4).status == 200 else 1)"

# Escuta fora do loopback: o servidor se recusa a iniciar sem ANHANGA_API_KEY (use `-e` ou `--env-file`).
CMD ["anhanga", "serve", "--host", "0.0.0.0", "--port", "7890"]
