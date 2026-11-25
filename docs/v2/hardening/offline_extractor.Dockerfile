# Unprivileged read-only offline QCOW2 artifact extractor container (OD-V2-04, OD-V2-16).
# Build: ./docs/v2/hardening/06_unprivileged_container_runner.sh --build
# Run strictly via: docs/v2/hardening/06_unprivileged_container_runner.sh <overlay.qcow2> <out_dir> <run_id> [base_cache.json.gz]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

# Pure-Python pip installation only (no FUSE, no libguestfs, no mount binaries installed)
WORKDIR /app
COPY docs/v2/hardening/requirements_extractor.txt /app/requirements_extractor.txt
RUN --mount=type=cache,target=/root/.cache/pip pip install --timeout=120 --retries=5 -r /app/requirements_extractor.txt

# Copy only read-only application extractor code (never malware samples or host secrets)
COPY src/__init__.py /app/src/__init__.py
COPY src/config.py /app/src/config.py
COPY src/utils/__init__.py /app/src/utils/__init__.py
COPY src/utils/repro.py /app/src/utils/repro.py
COPY src/data/__init__.py /app/src/data/__init__.py
COPY src/data/sanitize.py /app/src/data/sanitize.py
COPY src/data/features.py /app/src/data/features.py
COPY src/models/__init__.py /app/src/models/__init__.py
COPY src/models/preprocess.py /app/src/models/preprocess.py
COPY src/v2/__init__.py /app/src/v2/__init__.py
COPY src/v2/refgraph.py /app/src/v2/refgraph.py
COPY src/v2/offline_extractor.py /app/src/v2/offline_extractor.py

# Create non-privileged UID/GID 1000 user with /input, /cache, and /output mountpoints
RUN groupadd -g 1000 extractor \
    && useradd -u 1000 -g 1000 -M -d /tmp -s /usr/sbin/nologin extractor \
    && install -d -m 0555 -o 1000 -g 1000 /input \
    && install -d -m 0555 -o 1000 -g 1000 /cache \
    && install -d -m 0755 -o 1000 -g 1000 /output

USER 1000:1000
ENTRYPOINT ["python", "-m", "src.v2.offline_extractor"]
