ARG PYTHON_VERSION=3.12-slim-bookworm
FROM python:${PYTHON_VERSION}

# Hash-locked deps (SLSA): pinned CVE-fixed pip + only sha256-verified artifacts.
# Regenerate: pip-compile --generate-hashes --output-file=tools/requirements.lock tools/requirements.in
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir "pip==26.1.2" && \
    pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock && \
    rm /tmp/requirements.lock

COPY sync_opencve.py sync_opencve_full.py sync_wazuh.py /app/
WORKDIR /app

# Same UID as api container — shared /triggers volume
RUN useradd -r -u 1500 -s /usr/sbin/nologin cmdb && \
    mkdir -p /triggers && chown cmdb:cmdb /triggers

# Entrypoint = run the specified sync in a loop
# Usage: command: ["python3", "/app/sync_opencve.py", "--hours", "2"]
# The loop interval is controlled by SYNC_INTERVAL_SECONDS env var
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER cmdb

ENTRYPOINT ["/app/entrypoint.sh"]
