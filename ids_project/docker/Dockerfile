# ============================================
# Multi-Stage Dockerfile for Network IDS
# ============================================

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="IDS Team"
LABEL description="Network Traffic Monitoring & Attack Detection System"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r ids_user && useradd -r -g ids_user -d /app -s /sbin/nologin ids_user

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs reports/generated && \
    chown -R ids_user:ids_user /app

USER ids_user

ENV FLASK_APP=run.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "run:app"]
