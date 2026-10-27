ARG PYTHON_VERSION=3.12-slim

# ─── Cosign binary (signature-verify gate for trusted-namespace image pulls)
# Pinned digest matches rhorizon's .woodpecker/*.yml — same trust anchor.
FROM gcr.io/projectsigstore/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00 AS cosign

# ─── Builder stage ──────────────────────────────────────────
# Installs Python deps into /install with their own prefix.
# Build tools (gcc, -dev headers) stay in this layer — never shipped.
FROM python:${PYTHON_VERSION} AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Hash-locked deps (SLSA): pin pip to the CVE-fixed release, then install only
# artifacts whose sha256 matches the lock — a tampered/substituted package on
# PyPI cannot be installed. Regenerate the lock from requirements.txt with:
#   pip-compile --generate-hashes --output-file=api/requirements.lock api/requirements.txt
COPY api/requirements.lock .
RUN pip install --no-cache-dir "pip==26.1.2" && \
    pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock


# ─── Runtime stage ──────────────────────────────────────────
# No build tools, no pip cache, no gcc — only what the app needs at runtime.
FROM python:${PYTHON_VERSION}

WORKDIR /app

# Runtime tools:
#   curl         — healthcheck (http://localhost:8000/api/v1/health)
#   iputils-ping — heartbeat ping (raw ICMP, needs NET_RAW cap)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl iputils-ping && \
    rm -rf /var/lib/apt/lists/* && \
    find /usr/local/lib/python3.12 -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Copy installed Python packages from builder (no pip/setuptools bloat rebuilt here)
COPY --from=builder /install /usr/local

# Cosign binary — used by the consumer gate in api/app/utils/image_verify.py
# to refuse pulling images from trusted namespaces (gitea.example.com/shdw/*)
# whose signature doesn't verify against trust/rhorizon-cosign.pub.
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

COPY api/app/ ./app/
COPY schema.sql ./migrations/schema.sql
COPY trust/ ./trust/

RUN useradd -r -u 1500 -s /usr/sbin/nologin cmdb && \
    mkdir -p /triggers && chown cmdb:cmdb /triggers && \
    chown root:root -R /app && \
    chmod 755 /app && \
    find /app -type f -exec chmod 644 {} + && \
    find /app -type d -exec chmod 755 {} +

USER cmdb

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS:-4}
