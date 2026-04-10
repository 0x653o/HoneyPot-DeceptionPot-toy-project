FROM node:18-bookworm-slim

# Install system dependencies + nsjail
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    protobuf-compiler \
    libprotobuf-dev \
    pkg-config \
    flex \
    bison \
    libseccomp-dev \
    libnl-3-dev \
    libnl-route-3-dev \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Build nsjail from source
RUN git clone -b 3.4 --depth 1 https://github.com/google/nsjail.git /opt/nsjail \
    && cd /opt/nsjail \
    && make -j$(nproc) \
    && cp /opt/nsjail/nsjail /usr/local/bin/nsjail \
    && rm -rf /opt/nsjail

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

# We drop privileges to prevent Docker escape, but keep needed capabilities via docker-compose configuration
RUN mkdir -p /tmp/sandboxes && chown node:node /tmp/sandboxes

USER node

EXPOSE 8080
CMD ["npm", "start"]
