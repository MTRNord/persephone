# Dockerfile for running Sytest against Persephone
# Based on the official sytest Docker image

FROM matrixdotorg/sytest:testing

# Install C++ build dependencies for Persephone
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    pkg-config \
    cmake \
    ninja-build \
    git \
    # Compiler toolchain (use versioned packages available in testing)
    clang \
    lld \
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
    # Additional perl deps for our plugin
    libdbi-perl \
    libdbd-pg-perl \
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
# Handle multiple possible postgres versions
RUN for conf in /etc/postgresql/*/main/pg_hba.conf; do \
        if [ -f "$conf" ]; then \
            sed -i 's/peer/trust/g' "$conf"; \
            sed -i 's/scram-sha-256/trust/g' "$conf"; \
            sed -i 's/md5/trust/g' "$conf"; \
        fi; \
    done; \
    for conf in /etc/postgresql/*/main/postgresql.conf; do \
        if [ -f "$conf" ]; then \
            sed -i 's/max_connections = 100/max_connections = 500/g' "$conf"; \
        fi; \
    done

# Create directories
RUN mkdir -p /src /build /persephone

# Copy Persephone source
COPY . /src

# Build Persephone
RUN cd /src && \
    CC=clang CXX=clang++ cmake -B /build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DDISABLE_TESTS=ON \
        -DCMAKE_INSTALL_PREFIX=/persephone \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DCMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" && \
    cmake --build /build -j$(nproc) && \
    cmake --install /build

# Copy our sytest plugin files to /persephone (not /sytest - that gets created by bootstrap.sh)
COPY sytest/lib /persephone/sytest-plugin/lib/
COPY sytest/scripts/persephone_sytest.sh /persephone/sytest-plugin/
COPY sytest/whitelist.txt /persephone/whitelist.txt
COPY sytest/blacklist.txt /persephone/blacklist.txt

RUN chmod +x /persephone/sytest-plugin/persephone_sytest.sh

# Set environment variables
ENV PERSEPHONE_BINDIR=/persephone/bin

# Create our own entrypoint wrapper
COPY sytest/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
