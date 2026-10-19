FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY cdn_proxy_server.py .
RUN mkdir -p /app/cache /data && chown -R app:app /app /data
USER app:app

EXPOSE 8080
CMD ["python", "cdn_proxy_server.py"]
