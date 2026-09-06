# Multi-stage lightweight Dockerfile for TraceMail AI Threat Intelligence Service
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY shared/requirements.txt /app/shared-reqs.txt
COPY threat-intelligence/requirements.txt /app/threat-reqs.txt

RUN pip install --no-cache-dir --user -r /app/shared-reqs.txt -r /app/threat-reqs.txt

# Final runtime stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Copy python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app

# Copy application source
COPY shared /app/shared
COPY threat-intelligence /app/threat_intelligence

# Non-root security user
RUN useradd -u 10001 tracemail && chown -R tracemail:tracemail /app
USER tracemail

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

CMD ["python", "-m", "uvicorn", "threat_intelligence.service:app", "--host", "0.0.0.0", "--port", "8001"]
