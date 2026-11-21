# Build Kura in stages with a SHA-256-pinned base image.

# Stage 1: Build dependencies and compile wheels
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS builder

# Prevent Python from writing .pyc files and buffer output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install compiler and headers needed for compiling packages (argon2)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies with SHA-256 hash verification (CFG-04)
COPY requirements.lock.txt /build/
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock.txt


# Stage 2: Collect static files (needs the full Django app + settings)
FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966 AS static

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /install /usr/local
COPY . /app

# Collect static files at build time. The key below is random, used only for this
# command and never stored: collectstatic only needs settings to load, and the real
# key arrives at run time from the Docker secret. DEBUG=False keeps the production
# guards (no django-insecure- key, SECRET_KEY must be 50+ characters).
RUN SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
    DEBUG=False VAULT_ENABLED=False \
    python manage.py collectstatic --noinput --clear \
        --ignore=admin --ignore=django_otp --ignore=otp_totp


# Stage 3: Final runtime container — distroless (strips apt, bash, util-linux,
# ncurses, perl-base, tar). Runs as nonroot:nonroot with no shell, no package
# manager, minimal attack surface.
FROM gcr.io/distroless/python3-debian13:latest AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy pre-compiled Python packages into distroless's /python prefix
COPY --from=builder /install /python

# Copy collected static files from the static stage
COPY --from=static /app/staticfiles /app/staticfiles

# Copy application source code needed at runtime (gunicorn imports config.wsgi)
COPY --from=static /app/kura /app/kura
COPY --from=static /app/config /app/config
COPY --from=static /app/manage.py /app/manage.py
COPY --from=static /app/gunicorn.conf.py /app/gunicorn.conf.py

WORKDIR /app

# Run as non-root user (distroless's built-in unprivileged user). No shell,
# no setpriv, no capability changes needed.
USER nonroot:nonroot

# Document listening port
EXPOSE 8000

# Run production WSGI application with Gunicorn (loads mTLS settings from gunicorn.conf.py)
CMD ["/python/bin/gunicorn", "-c", "gunicorn.conf.py", "config.wsgi:application"]

# Stage 4: nginx with the collected static files baked in (served read-only from /app/staticfiles).
FROM nginx:1.31.8-alpine@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606 AS nginx
RUN apk update && apk upgrade --no-cache
COPY --from=static /app/staticfiles /app/staticfiles
