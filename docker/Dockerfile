# AccessAudit Dockerfile
# Multi-stage build for minimal production image

# ============== Builder Stage ==============
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir .

# ============== Production Stage ==============
FROM python:3.12-slim as production

LABEL maintainer="AccessAudit Contributors"
LABEL description="IAM Access Review Automation Platform"
LABEL version="0.1.0"

# Create non-root user
RUN groupadd -r accessaudit && useradd -r -g accessaudit accessaudit

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application
COPY --from=builder /build/src ./src

# Set up volumes
VOLUME ["/app/config", "/app/reports"]

# Environment variables
ENV ACCESSAUDIT_REPORTING__OUTPUT_DIR=/app/reports
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER accessaudit

# Default command
ENTRYPOINT ["accessaudit"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD accessaudit --version || exit 1
