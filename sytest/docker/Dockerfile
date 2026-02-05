# Dockerfile for running Sytest against Persephone
# Based on the official sytest Docker image

FROM matrixdotorg/sytest:bookworm

# Install C++ build dependencies for Persephone
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    pkg-config \
    cmake \
    ninja-build \
    git \
    # Compiler toolchain
    clang-18 \
    lld-18 \
    # Persephone dependencies
    libpq-dev \
    libsodium-dev \
    libyaml-cpp-dev \
    libldns-dev \
    libjsoncpp-dev \
    nlohmann-json3-dev \
    uuid-dev \
    zlib1g-dev \
    libssl-dev \
    libevent-dev \
    libicu-dev \
    # PostgreSQL for tests
    postgresql \
    postgresql-contrib \
    && rm -rf /var/lib/apt/lists/*

# Fix jsoncpp include path (debian vs fedora difference)
RUN if [ -d /usr/include/jsoncpp/json ] && [ ! -d /usr/include/json ]; then \
        ln -s /usr/include/jsoncpp/json /usr/include/json; \
    fi

# Build and install drogon framework
RUN cd /tmp && \
    git clone --depth 1 https://github.com/drogonframework/drogon && \
    cd drogon && \
    git submodule update --init && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_POSTGRESQL=ON \
          -DBUILD_REDIS=OFF \
          -DBUILD_SQLITE=OFF \
          -DBUILD_MYSQL=OFF \
          -DBUILD_ORM=ON \
          -DBUILD_SHARED_LIBS=ON \
          .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    rm -rf /tmp/drogon

# Configure PostgreSQL for trust authentication on localhost
RUN find /etc/postgresql -name pg_hba.conf -exec sed -i 's/peer/trust/g' {} \; && \
    find /etc/postgresql -name pg_hba.conf -exec sed -i 's/scram-sha-256/trust/g' {} \; && \
    find /etc/postgresql -name pg_hba.conf -exec sed -i 's/md5/trust/g' {} \;

# Increase PostgreSQL max connections
RUN find /etc/postgresql -name postgresql.conf -exec sed -i 's/max_connections = 100/max_connections = 500/g' {} \;

# Create source mount point and build directory
RUN mkdir -p /src /build /logs /work

# Copy sytest plugin files
COPY sytest/lib/SyTest/Homeserver/Persephone.pm /sytest/lib/SyTest/Homeserver/
COPY sytest/lib/SyTest/HomeserverFactory/Persephone.pm /sytest/lib/SyTest/HomeserverFactory/
COPY sytest/scripts/persephone_sytest.sh /sytest/scripts/
COPY sytest/whitelist.txt /sytest/persephone_whitelist.txt
COPY sytest/blacklist.txt /sytest/persephone_blacklist.txt

# Make the runner script executable
RUN chmod +x /sytest/scripts/persephone_sytest.sh

# Set up environment
ENV SYTEST_PLUGINS=/sytest/lib
ENV PERSEPHONE_BINARY_DIR=/usr/local/bin

WORKDIR /sytest

ENTRYPOINT ["/bin/bash", "/sytest/scripts/persephone_sytest.sh"]
