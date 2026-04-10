# ==============================================================================
# Honeypot + Management API Container
# ==============================================================================
# Installs Python, nsjail, and runs the honeypot core.
# ==============================================================================

FROM python:3.11-slim-bookworm AS base

# Install system dependencies + nsjail
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    protobuf-compiler \
    libprotobuf-dev \
    pkg-config \
    flex \
    bison \
    libseccomp-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    && rm -rf /var/lib/apt/lists/*

# Build nsjail from source
RUN git clone -b 3.4 --depth 1 https://github.com/google/nsjail.git /opt/nsjail \
    && cd /opt/nsjail \
    && make -j$(nproc) \
    && cp /opt/nsjail/nsjail /usr/local/bin/nsjail \
    && rm -rf /opt/nsjail

# Create non-root user
RUN groupadd -g 1000 honeypot && \
    useradd -u 1000 -g honeypot -m -s /bin/bash honeypot

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY honeypot/ ./honeypot/
COPY analyzer/ ./analyzer/
COPY config.yaml .
COPY seccomp-profile.json .

# Create data directory
RUN mkdir -p /app/data && chown -R honeypot:honeypot /app/data

# Expose honeypot ports (sequential from 10001)
EXPOSE 10001 10002 10003 10004 10005

# Run as non-root user
# USER honeypot

# Entry point
CMD ["python", "-m", "honeypot", "--config", "/app/config.yaml"]
