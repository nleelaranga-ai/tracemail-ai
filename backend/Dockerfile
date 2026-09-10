# TraceMail AI — Backend API Gateway Dockerfile
# Production build (Python 3.12-slim)

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy backend source and shared dependencies
COPY backend /app/backend
COPY shared /app/shared
COPY threat_intelligence /app/threat_intelligence

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Non-root security user
RUN useradd -u 10001 tracemail && chown -R tracemail:tracemail /app
USER tracemail

EXPOSE 8000

CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
