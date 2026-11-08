FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    TEAM_AKI_DATA_DIR=/data

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm php-cli golang-go \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .
RUN chmod +x /app/docker-entrypoint.sh

USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/ping' % os.environ.get('PORT', '5000'), timeout=3)" || exit 1
ENTRYPOINT ["/app/docker-entrypoint.sh"]
