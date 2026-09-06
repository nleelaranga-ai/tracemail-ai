# Dockerfile for TraceMail AI Phishing Classifier & Explainer (AI Engine Team)
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY shared /app/shared
COPY ai-engine /app/ai-engine

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8002

CMD ["python", "-m", "uvicorn", "ai-engine.main:app", "--host", "0.0.0.0", "--port", "8002"]
