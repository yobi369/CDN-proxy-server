FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROXY_HOST=0.0.0.0 \
    PROXY_CACHE_DIR=/app/cache \
    PROXY_ANALYTICS_DB=/data/analytics.db

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /app/cache /data \
    && chown -R appuser:appuser /app /data

COPY --chown=appuser:appuser cdn_proxy_server.py ./cdn_proxy_server.py
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()"
CMD ["python", "cdn_proxy_server.py"]
