FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install globally (NOT --user)
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

# Copy installed packages
COPY --from=builder /usr/local /usr/local

# Copy project folders
COPY backend /app/backend
COPY shared /app/shared
COPY threat_intelligence /app/threat_intelligence
COPY ai-engine /app/ai-engine
COPY maps_engine /app/maps_engine
COPY maps-engine /app/maps-engine

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Non-root user
RUN useradd -u 10001 tracemail && chown -R tracemail:tracemail /app

USER tracemail

EXPOSE 8000

CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
