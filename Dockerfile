# Multi-stage Dockerfile for Kura Secure Learning Management System
# Pinned base image by SHA-256 digest for supply chain integrity

# Stage 1: Build dependencies and compile wheels
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS builder

# Prevent Python from writing .pyc files and buffer output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install compiler and headers needed for compiling packages (psycopg2, argon2)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies with SHA-256 hash verification (CFG-04)
COPY requirements.lock.txt /build/
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock.txt


# Stage 2: Final runtime container
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install only shared runtime libraries needed by psycopg2 and python-magic
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# Copy pre-compiled Python packages from the builder stage
COPY --from=builder /install /usr/local

# Create non-root user and group (kura) for least privilege
RUN groupadd -g 10001 kura && \
    useradd -u 10001 -g kura -s /bin/sh -d /app -m kura

WORKDIR /app

# Copy application source code with ownership set to non-root user
COPY --chown=kura:kura . /app

# Switch to unprivileged user
USER kura

# Document listening port
EXPOSE 8000

# Run production WSGI application with Gunicorn (loads mTLS settings from gunicorn.conf.py)
CMD ["gunicorn", "-c", "gunicorn.conf.py", "config.wsgi:application"]
