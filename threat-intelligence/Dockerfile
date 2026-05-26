FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Environment defaults
ENV TI_PORT=5004
ENV REDIS_URL=redis://redis:6379
ENV FEED_SYNC_INTERVAL_MINUTES=30

EXPOSE 5004

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5004/api/ti/health')" || exit 1

CMD ["python", "ti_service.py"]
