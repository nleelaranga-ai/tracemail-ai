# TraceMail AI — Backend API Gateway Dockerfile
# Multi-stage production build (Python 3.12-slim)

FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --user -r /app/requirements.txt

# Final runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Copy backend source and shared dependencies
COPY backend /app/backend
COPY shared /app/shared
COPY threat_intelligence /app/threat_intelligence

# Non-root security user
RUN useradd -u 10001 tracemail && chown -R tracemail:tracemail /app
USER tracemail

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
